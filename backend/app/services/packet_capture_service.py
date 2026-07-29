import queue
import threading
import time
import random
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import logging

try:
    from scapy.all import sniff, get_if_list, conf
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger("app.packet_capture")

PROTOCOL_MAP = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF"
}

class PacketCaptureService:
    """
    Service responsible for physical packet capture or emulator fallback.
    Manages background thread lifecycle, pushes raw packets to a bounded queue,
    and exposes capture statistics.
    """
    def __init__(self):
        self.status = "STOPPED"  # STOPPED, STARTING, RUNNING, STOPPING, ERROR
        self.interface = None
        self.is_emulated = False
        self.error_message = None
        
        self.packet_queue = queue.Queue(maxsize=1000)
        self.thread = None
        self.is_running = False
        
        # Diagnostics
        self.packets_captured = 0
        self.dropped_packets = 0
        self.started_at = None

    def get_interfaces(self) -> List[str]:
        """
        Discover available network interfaces.
        """
        if not SCAPY_AVAILABLE:
            return ["Emulator-Interface"]
        try:
            # Get list of interfaces from scapy config or get_if_list
            ifaces = []
            for name in get_if_list():
                ifaces.append(name)
            if not ifaces:
                ifaces = [str(x) for x in conf.ifaces.keys()]
            return sorted(list(set(ifaces))) if ifaces else ["Emulator-Interface"]
        except Exception as e:
            logger.warning(f"Failed to retrieve interface list: {e}")
            return ["Emulator-Interface"]

    def start_capture(self, interface_name: Optional[str] = None):
        """
        Start the background packet capture thread.
        """
        if self.is_running or self.status in ["STARTING", "RUNNING"]:
            logger.info("Packet capture is already running or starting.")
            return

        self.status = "STARTING"
        self.interface = interface_name
        self.is_emulated = False
        self.error_message = None
        self.packets_captured = 0
        self.dropped_packets = 0
        self.started_at = datetime.now(timezone.utc)
        
        # Clear packet queue
        while not self.packet_queue.empty():
            try:
                self.packet_queue.get_nowait()
            except queue.Empty:
                break
                
        self.is_running = True
        self.thread = threading.Thread(target=self._run_capture, name="PacketCaptureThread", daemon=True)
        self.thread.start()

    def stop_capture(self):
        """
        Stop the background packet capture thread.
        """
        if not self.is_running:
            return

        self.status = "STOPPING"
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=3.0)
            self.thread = None
        self.status = "STOPPED"
        logger.info("Packet capture service stopped successfully.")

    def get_status(self) -> Dict[str, Any]:
        """
        Expose diagnostic details about the sniffer daemon.
        """
        return {
            "status": self.status,
            "interface": self.interface or ("Traffic-Emulator" if self.is_emulated else "Default"),
            "is_emulated": self.is_emulated,
            "error_message": self.error_message,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "packets_captured": self.packets_captured,
            "dropped_packets": self.dropped_packets,
            "queue_size": self.packet_queue.qsize(),
            "queue_capacity": 1000
        }

    def _run_capture(self):
        """
        Sniffing loop executed in the background thread.
        """
        logger.info(f"Starting capture loop. Selected Interface: {self.interface}")
        
        # If user explicitly requested Emulator or Scapy is unavailable, go straight to emulator
        if self.interface == "Emulator-Interface" or not SCAPY_AVAILABLE:
            self.is_emulated = True
            self.status = "RUNNING"
            self._run_emulator()
            return

        try:
            # Test if scapy can initialize raw sockets / driver is present
            # We run a dummy sniff for 0.1s to check for driver availability
            sniff(count=0, timeout=0.1, store=0)
            
            self.status = "RUNNING"
            logger.info("Scapy packet sniffer successfully initialized.")
            
            def prn_callback(packet):
                self._process_scapy_packet(packet)

            def stop_filter(packet):
                return not self.is_running

            # Run scapy sniffer in a loop with timeouts to check is_running flag regularly
            while self.is_running:
                iface_param = self.interface if self.interface else None
                sniff(
                    iface=iface_param,
                    filter="ip",
                    prn=prn_callback,
                    stop_filter=stop_filter,
                    store=0,
                    timeout=1.0
                )
                
        except Exception as e:
            err_str = str(e)
            logger.error(f"Failed to start raw packet capture: {err_str}. Falling back to Traffic Emulator.")
            self.is_emulated = True
            self.error_message = f"Capture driver issues or privilege error: {err_str}"
            self.status = "RUNNING"
            self._run_emulator()

    def _process_scapy_packet(self, packet):
        """
        Extract IP/TCP/UDP layers and push to bounded packet queue.
        """
        if not self.is_running:
            return
            
        if IP in packet:
            ip_layer = packet[IP]
            proto_num = ip_layer.proto
            protocol = PROTOCOL_MAP.get(proto_num, f"PROTO_{proto_num}")
            
            src_port = None
            dst_port = None
            tcp_flags = 0
            win_size = 0
            header_len = ip_layer.ihl * 4
            payload_len = len(ip_layer.payload)
            
            if TCP in packet:
                tcp_layer = packet[TCP]
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                # tcp_layer.flags is a flag field or string representation
                # Let's map flags to an integer
                flags_val = int(tcp_layer.flags) if not isinstance(tcp_layer.flags, str) else 0
                if isinstance(tcp_layer.flags, str):
                    # Scapy string flags: F, S, R, P, A, U, E, C
                    char_to_val = {'F': 0x01, 'S': 0x02, 'R': 0x04, 'P': 0x08, 'A': 0x10, 'U': 0x20, 'E': 0x40, 'C': 0x80}
                    for c, val in char_to_val.items():
                        if c in tcp_layer.flags:
                            flags_val |= val
                tcp_flags = flags_val
                win_size = int(tcp_layer.window)
                header_len += tcp_layer.dataofs * 4
                payload_len = len(tcp_layer.payload)
            elif UDP in packet:
                udp_layer = packet[UDP]
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                header_len += 8
                payload_len = len(udp_layer.payload)
            elif ICMP in packet:
                src_port = 0
                dst_port = 0
                header_len += 8
                payload_len = len(packet[ICMP].payload)

            packet_doc = {
                "src_ip": str(ip_layer.src),
                "dst_ip": str(ip_layer.dst),
                "source_port": src_port,
                "destination_port": dst_port,
                "protocol": protocol,
                "size": int(len(packet)),
                "payload_size": payload_len,
                "header_length": header_len,
                "tcp_flags": tcp_flags,
                "win_size": win_size,
                "timestamp": float(packet.time) if hasattr(packet, "time") else time.time()
            }
            
            self._enqueue_packet(packet_doc)

    def _enqueue_packet(self, packet_doc):
        """
        Thread-safe enqueue with bounded capacity logic.
        """
        self.packets_captured += 1
        try:
            # Put in queue. If full, raise queue.Full
            self.packet_queue.put_nowait(packet_doc)
        except queue.Full:
            self.dropped_packets += 1
            if self.dropped_packets % 100 == 1:
                logger.warning(f"Packet queue is full! Dropped {self.dropped_packets} packets so far.")

    def _run_emulator(self):
        """
        Generates realistic network packets to feed the flow aggregation.
        """
        logger.info("Traffic Emulator loop active.")
        
        ips = [
            "192.168.10.15", "192.168.10.22", "192.168.10.100",  # Internal LAN
            "10.0.0.4", "10.0.0.12",                             # Internal server
            "192.168.200.5", "10.0.0.10", "10.0.0.11",           # Specific IPs from test suite
            "8.8.8.8", "1.1.1.1",                                # DNS
            "142.250.190.46", "20.112.50.15"                     # Cloud Web servers
        ]
        
        protocols = ["TCP", "UDP", "TCP", "UDP", "ICMP", "TCP"]
        ports = [80, 443, 53, 22, 21, 8080, 5001, 1234]

        # Normal and attack patterns simulation
        # In emulator mode, we sleep and produce packets
        while self.is_running:
            src = random.choice(ips)
            dst = random.choice(ips)
            while dst == src:
                dst = random.choice(ips)
                
            proto = random.choice(protocols)
            sport = random.choice(ports) if proto != "ICMP" else 0
            dport = random.choice(ports) if proto != "ICMP" else 0
            
            size = random.randint(64, 1500)
            payload_len = max(0, size - 40)
            
            packet_doc = {
                "src_ip": src,
                "dst_ip": dst,
                "source_port": sport,
                "destination_port": dport,
                "protocol": proto,
                "size": size,
                "payload_size": payload_len,
                "header_length": 40,
                "tcp_flags": 0x02 if random.random() < 0.2 else 0x10, # SYN or ACK
                "win_size": 8192,
                "timestamp": time.time()
            }
            
            self._enqueue_packet(packet_doc)
            
            # Control emission rate: sleep between 5ms and 150ms
            time.sleep(random.uniform(0.005, 0.15))

# Global sniffer singleton instance
packet_capture_service = PacketCaptureService()

import time
import threading
import random
from datetime import datetime, timezone
from scapy.all import sniff
from scapy.layers.inet import IP

from app.db.mongodb import get_mongo_db

# Protocol number to name mapping
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

class PacketSniffer:
    """
    Background packet sniffer engine utilizing Scapy.
    Captures live packets, extracts metrics, and logs them to MongoDB.
    Includes a fallback emulator if packet capture drivers (Npcap/WinPcap) are missing.
    """
    def __init__(self):
        self.is_running = False
        self.is_emulated = False
        self.thread = None
        
        # Connect to MongoDB database
        self.mongo_db = get_mongo_db()
        self.collection = self.mongo_db["captured_packets"]

    def start(self):
        """
        Start the packet sniffer in a background thread.
        """
        if self.is_running:
            return
        
        self.is_running = True
        self.is_emulated = False
        self.thread = threading.Thread(target=self._run_sniffer, daemon=True)
        self.thread.start()

    def stop(self):
        """
        Stop the packet sniffer thread.
        """
        if not self.is_running:
            return
        
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=2.0)
            self.thread = None

    def _run_sniffer(self):
        """
        Internal sniffing loop executed in background thread.
        """
        print("Starting packet sniffing session...")
        try:
            # Attempt to sniff using Scapy
            def prn_callback(packet):
                self._process_scapy_packet(packet)

            def stop_filter(packet):
                return not self.is_running

            # Sniff only IP packets to reduce noise
            sniff(filter="ip", prn=prn_callback, stop_filter=stop_filter, store=0)
            
        except Exception as e:
            print(f"Scapy sniffing error: {e}. Falling back to Traffic Emulator...")
            self.is_emulated = True
            self._run_emulator()

    def _process_scapy_packet(self, packet):
        """
        Callback to extract key packet properties and write to MongoDB.
        """
        if IP in packet:
            ip_layer = packet[IP]
            proto_num = ip_layer.proto
            proto_name = PROTOCOL_MAP.get(proto_num, f"PROTO_{proto_num}")
            
            packet_doc = {
                "src_ip": str(ip_layer.src),
                "dst_ip": str(ip_layer.dst),
                "protocol": proto_name,
                "size": int(len(packet)),
                "timestamp": datetime.now(timezone.utc)
            }
            
            try:
                self.collection.insert_one(packet_doc)
            except Exception as mongo_err:
                print(f"Failed to write packet to MongoDB: {mongo_err}")

    def _run_emulator(self):
        """
        Emulator loop that generates realistic network packets if drivers are missing.
        """
        common_ips = [
            "192.168.1.1", "192.168.1.50", "192.168.1.100",  # LAN IPs
            "10.0.0.4", "10.0.0.12",
            "8.8.8.8", "8.8.4.4",  # Google DNS
            "1.1.1.1",             # Cloudflare
            "142.250.190.46",      # Google Web
            "20.112.50.15",        # Microsoft Azure
            "172.217.16.142"       # YouTube
        ]
        
        protocols = ["TCP", "UDP", "TCP", "UDP", "ICMP", "TCP"]  # TCP/UDP dominant
        
        while self.is_running:
            src = random.choice(common_ips)
            dst = random.choice(common_ips)
            while dst == src:
                dst = random.choice(common_ips)
                
            proto = random.choice(protocols)
            
            # Packets are typically 64 bytes (ping/ack) to 1500 bytes (ethernet MTU)
            size = random.randint(64, 1500)
            
            packet_doc = {
                "src_ip": src,
                "dst_ip": dst,
                "protocol": proto,
                "size": size,
                "timestamp": datetime.now(timezone.utc)
            }
            
            try:
                self.collection.insert_one(packet_doc)
            except Exception as mongo_err:
                print(f"Failed to write emulated packet to MongoDB: {mongo_err}")
                
            # Sleep between 100ms and 500ms to emulate real throughput
            time.sleep(random.uniform(0.1, 0.5))

# Global sniffer singleton instance
sniffer_instance = PacketSniffer()

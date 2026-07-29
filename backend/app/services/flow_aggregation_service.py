import queue
import threading
import time
import numpy as np
import logging
from typing import List, Dict, Any, Optional, Tuple
from app.services.packet_capture_service import packet_capture_service

logger = logging.getLogger("app.flow_aggregation")

class Flow:
    """
    Class representing an active network flow.
    Aggregates packets bidirectionally and extracts dataset-compatible features.
    """
    def __init__(self, first_packet: dict):
        self.src_ip = first_packet["src_ip"]
        self.dst_ip = first_packet["dst_ip"]
        self.source_port = first_packet["source_port"]
        self.destination_port = first_packet["destination_port"]
        self.protocol = first_packet["protocol"]
        
        self.flow_start = first_packet["timestamp"]
        self.flow_end = first_packet["timestamp"]
        self.last_active = first_packet["timestamp"]
        
        self.packets: List[dict] = []
        
        # Directions
        self.fwd_packets: List[dict] = []
        self.bwd_packets: List[dict] = []
        
        self.add_packet(first_packet)

    def add_packet(self, packet: dict):
        """Add packet to flow, sorting direction based on first packet."""
        packet_time = packet["timestamp"]
        self.flow_end = max(self.flow_end, packet_time)
        self.last_active = packet_time
        self.packets.append(packet)
        
        # Determine direction
        if packet["src_ip"] == self.src_ip and packet["source_port"] == self.source_port:
            packet["direction"] = "fwd"
            self.fwd_packets.append(packet)
        else:
            packet["direction"] = "bwd"
            self.bwd_packets.append(packet)

    def get_duration_ms(self) -> float:
        return max(0.0, (self.flow_end - self.flow_start) * 1000.0)

    def to_cicids2017_dict(self) -> Dict[str, Any]:
        """
        Extract the 77 numerical features required for the CICIDS2017 model profile.
        """
        duration_sec = max(1e-6, self.flow_end - self.flow_start)
        duration_us = duration_sec * 1000000.0
        
        fwd_lens = [p["size"] for p in self.fwd_packets]
        bwd_lens = [p["size"] for p in self.bwd_packets]
        all_lens = [p["size"] for p in self.packets]
        
        # Lengths
        tot_fwd_len = sum(fwd_lens)
        tot_bwd_len = sum(bwd_lens)
        
        fwd_len_max = max(fwd_lens) if fwd_lens else 0
        fwd_len_min = min(fwd_lens) if fwd_lens else 0
        fwd_len_mean = np.mean(fwd_lens) if fwd_lens else 0.0
        fwd_len_std = np.std(fwd_lens) if fwd_lens else 0.0
        
        bwd_len_max = max(bwd_lens) if bwd_lens else 0
        bwd_len_min = min(bwd_lens) if bwd_lens else 0
        bwd_len_mean = np.mean(bwd_lens) if bwd_lens else 0.0
        bwd_len_std = np.std(bwd_lens) if bwd_lens else 0.0
        
        # Flow rates
        flow_bytes_s = (tot_fwd_len + tot_bwd_len) / duration_sec
        flow_pkts_s = len(self.packets) / duration_sec
        
        # IATs
        all_times = sorted([p["timestamp"] for p in self.packets])
        flow_iats = np.diff(all_times) * 1000000.0 if len(all_times) > 1 else []
        flow_iat_mean = np.mean(flow_iats) if len(flow_iats) > 0 else 0.0
        flow_iat_std = np.std(flow_iats) if len(flow_iats) > 0 else 0.0
        flow_iat_max = max(flow_iats) if len(flow_iats) > 0 else 0.0
        flow_iat_min = min(flow_iats) if len(flow_iats) > 0 else 0.0
        
        fwd_times = sorted([p["timestamp"] for p in self.fwd_packets])
        fwd_iats = np.diff(fwd_times) * 1000000.0 if len(fwd_times) > 1 else []
        fwd_iat_total = sum(fwd_iats)
        fwd_iat_mean = np.mean(fwd_iats) if len(fwd_iats) > 0 else 0.0
        fwd_iat_std = np.std(fwd_iats) if len(fwd_iats) > 0 else 0.0
        fwd_iat_max = max(fwd_iats) if len(fwd_iats) > 0 else 0.0
        fwd_iat_min = min(fwd_iats) if len(fwd_iats) > 0 else 0.0
        
        bwd_times = sorted([p["timestamp"] for p in self.bwd_packets])
        bwd_iats = np.diff(bwd_times) * 1000000.0 if len(bwd_times) > 1 else []
        bwd_iat_total = sum(bwd_iats)
        bwd_iat_mean = np.mean(bwd_iats) if len(bwd_iats) > 0 else 0.0
        bwd_iat_std = np.std(bwd_iats) if len(bwd_iats) > 0 else 0.0
        bwd_iat_max = max(bwd_iats) if len(bwd_iats) > 0 else 0.0
        bwd_iat_min = min(bwd_iats) if len(bwd_iats) > 0 else 0.0
        
        # Header sizes
        fwd_header_len = sum([p["header_length"] for p in self.fwd_packets])
        bwd_header_len = sum([p["header_length"] for p in self.bwd_packets])
        
        # Flags
        fwd_psh = sum([1 for p in self.fwd_packets if (p["tcp_flags"] & 0x08)])
        bwd_psh = sum([1 for p in self.bwd_packets if (p["tcp_flags"] & 0x08)])
        fwd_urg = sum([1 for p in self.fwd_packets if (p["tcp_flags"] & 0x20)])
        bwd_urg = sum([1 for p in self.bwd_packets if (p["tcp_flags"] & 0x20)])
        
        fin_cnt = sum([1 for p in self.packets if (p["tcp_flags"] & 0x01)])
        syn_cnt = sum([1 for p in self.packets if (p["tcp_flags"] & 0x02)])
        rst_cnt = sum([1 for p in self.packets if (p["tcp_flags"] & 0x04)])
        psh_cnt = sum([1 for p in self.packets if (p["tcp_flags"] & 0x08)])
        ack_cnt = sum([1 for p in self.packets if (p["tcp_flags"] & 0x10)])
        urg_cnt = sum([1 for p in self.packets if (p["tcp_flags"] & 0x20)])
        ece_cnt = sum([1 for p in self.packets if (p["tcp_flags"] & 0x40)])
        cwr_cnt = sum([1 for p in self.packets if (p["tcp_flags"] & 0x80)]) # CWE Flag count
        
        # Packet sizes
        min_pkt_len = min(all_lens) if all_lens else 0
        max_pkt_len = max(all_lens) if all_lens else 0
        pkt_len_mean = np.mean(all_lens) if all_lens else 0.0
        pkt_len_std = np.std(all_lens) if all_lens else 0.0
        pkt_len_var = np.var(all_lens) if all_lens else 0.0
        
        down_up_ratio = len(self.bwd_packets) / max(1, len(self.fwd_packets))
        avg_pkt_size = tot_fwd_len + tot_bwd_len / max(1, len(self.packets))
        avg_fwd_seg = tot_fwd_len / max(1, len(self.fwd_packets))
        avg_bwd_seg = tot_bwd_len / max(1, len(self.bwd_packets))
        
        # TCP handshakes
        fwd_wins = [p["win_size"] for p in self.fwd_packets if p["win_size"] > 0]
        bwd_wins = [p["win_size"] for p in self.bwd_packets if p["win_size"] > 0]
        init_win_fwd = fwd_wins[0] if fwd_wins else 0
        init_win_bwd = bwd_wins[0] if bwd_wins else 0
        
        # Fwd active packets
        act_data_pkt_fwd = sum([1 for p in self.fwd_packets if p["payload_size"] > 0])
        
        # Min segment size forward (usually TCP option header size, approximate using header length of first fwd)
        min_seg_size_forward = self.fwd_packets[0]["header_length"] if self.fwd_packets else 20
        
        # Active/Idle logic (CICIDS2017 expects active/idle periods if flow is multi-burst)
        # For single short flows, active = duration, idle = 0
        active_val = duration_us
        idle_val = 0.0
        if len(flow_iats) > 0 and max(flow_iats) > 1000000.0:  # > 1s gap
            # Approximated: Active is the period without long gaps, Idle is the sum of gaps
            gaps = [g for g in flow_iats if g > 1000000.0]
            idle_val = sum(gaps)
            active_val = max(0.0, duration_us - idle_val)
            
        return {
            "Destination Port": self.destination_port or 0,
            "Flow Duration": duration_us,
            "Total Fwd Packets": len(self.fwd_packets),
            "Total Backward Packets": len(self.bwd_packets),
            "Total Length of Fwd Packets": float(tot_fwd_len),
            "Total Length of Bwd Packets": float(tot_bwd_len),
            "Fwd Packet Length Max": float(fwd_len_max),
            "Fwd Packet Length Min": float(fwd_len_min),
            "Fwd Packet Length Mean": float(fwd_len_mean),
            "Fwd Packet Length Std": float(fwd_len_std),
            "Bwd Packet Length Max": float(bwd_len_max),
            "Bwd Packet Length Min": float(bwd_len_min),
            "Bwd Packet Length Mean": float(bwd_len_mean),
            "Bwd Packet Length Std": float(bwd_len_std),
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_pkts_s,
            "Flow IAT Mean": float(flow_iat_mean),
            "Flow IAT Std": float(flow_iat_std),
            "Flow IAT Max": float(flow_iat_max),
            "Flow IAT Min": float(flow_iat_min),
            "Fwd IAT Total": float(fwd_iat_total),
            "Fwd IAT Mean": float(fwd_iat_mean),
            "Fwd IAT Std": float(fwd_iat_std),
            "Fwd IAT Max": float(fwd_iat_max),
            "Fwd IAT Min": float(fwd_iat_min),
            "Bwd IAT Total": float(bwd_iat_total),
            "Bwd IAT Mean": float(bwd_iat_mean),
            "Bwd IAT Std": float(bwd_iat_std),
            "Bwd IAT Max": float(bwd_iat_max),
            "Bwd IAT Min": float(bwd_iat_min),
            "Fwd PSH Flags": int(fwd_psh),
            "Bwd PSH Flags": int(bwd_psh),
            "Fwd URG Flags": int(fwd_urg),
            "Bwd URG Flags": int(bwd_urg),
            "Fwd Header Length": fwd_header_len,
            "Bwd Header Length": bwd_header_len,
            "Fwd Packets/s": len(self.fwd_packets) / duration_sec,
            "Bwd Packets/s": len(self.bwd_packets) / duration_sec,
            "Min Packet Length": float(min_pkt_len),
            "Max Packet Length": float(max_pkt_len),
            "Packet Length Mean": float(pkt_len_mean),
            "Packet Length Std": float(pkt_len_std),
            "Packet Length Variance": float(pkt_len_var),
            "FIN Flag Count": int(fin_cnt),
            "SYN Flag Count": int(syn_cnt),
            "RST Flag Count": int(rst_cnt),
            "PSH Flag Count": int(psh_cnt),
            "ACK Flag Count": int(ack_cnt),
            "URG Flag Count": int(urg_cnt),
            "CWE Flag Count": int(cwr_cnt),
            "ECE Flag Count": int(ece_cnt),
            "Down/Up Ratio": down_up_ratio,
            "Average Packet Size": avg_pkt_size,
            "Avg Fwd Segment Size": avg_fwd_seg,
            "Avg Bwd Segment Size": avg_bwd_seg,
            "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0,
            "Fwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0,
            "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0,
            "Subflow Fwd Packets": len(self.fwd_packets),
            "Subflow Fwd Bytes": float(tot_fwd_len),
            "Subflow Bwd Packets": len(self.bwd_packets),
            "Subflow Bwd Bytes": float(tot_bwd_len),
            "Init_Win_bytes_forward": int(init_win_fwd),
            "Init_Win_bytes_backward": int(init_win_bwd),
            "act_data_pkt_fwd": int(act_data_pkt_fwd),
            "min_seg_size_forward": int(min_seg_size_forward),
            "Active Mean": active_val,
            "Active Std": 0.0,
            "Active Max": active_val,
            "Active Min": active_val,
            "Idle Mean": float(idle_val),
            "Idle Std": 0.0,
            "Idle Max": float(idle_val),
            "Idle Min": float(idle_val)
        }

    def to_unsw_nb15_dict(self) -> Dict[str, Any]:
        """
        Extract the 40 numerical and 3 categorical features for the UNSW-NB15 model profile.
        """
        duration_sec = max(1e-6, self.flow_end - self.flow_start)
        
        fwd_lens = [p["size"] for p in self.fwd_packets]
        bwd_lens = [p["size"] for p in self.bwd_packets]
        
        tot_fwd_len = sum(fwd_lens)
        tot_bwd_len = sum(bwd_lens)
        
        smeansz = np.mean(fwd_lens) if fwd_lens else 0.0
        dmeansz = np.mean(bwd_lens) if bwd_lens else 0.0
        
        # Rates
        sload = (tot_fwd_len * 8) / duration_sec
        dload = (tot_bwd_len * 8) / duration_sec
        
        # IATs
        fwd_times = sorted([p["timestamp"] for p in self.fwd_packets])
        fwd_iats = np.diff(fwd_times) * 1000.0 if len(fwd_times) > 1 else []
        sintpkt = np.mean(fwd_iats) if len(fwd_iats) > 0 else 0.0
        
        bwd_times = sorted([p["timestamp"] for p in self.bwd_packets])
        bwd_iats = np.diff(bwd_times) * 1000.0 if len(bwd_times) > 1 else []
        dintpkt = np.mean(bwd_iats) if len(bwd_iats) > 0 else 0.0
        
        # Jitter
        sjit = np.std(fwd_iats) if len(fwd_iats) > 0 else 0.0
        djit = np.std(bwd_iats) if len(bwd_iats) > 0 else 0.0
        
        # TCP windows and SEQ numbers
        fwd_wins = [p["win_size"] for p in self.fwd_packets if p["win_size"] > 0]
        bwd_wins = [p["win_size"] for p in self.bwd_packets if p["win_size"] > 0]
        swin = fwd_wins[0] if fwd_wins else 0
        dwin = bwd_wins[0] if bwd_wins else 0
        
        # TTLs (standard defaults if packet field is unparsed, usually 64/128/255)
        sttl = 64.0
        dttl = 64.0
        
        # Round trip times
        tcprtt = 0.0
        synack = 0.0
        ackdat = 0.0
        
        # Connection tracking count placeholders (Approximated rolling cache defaults)
        ct_state_ttl = 0.0
        ct_srv_src = 1.0
        ct_srv_dst = 1.0
        ct_dst_ltm = 1.0
        ct_src_ltm = 1.0
        ct_src_dport_ltm = 1.0
        ct_dst_sport_ltm = 1.0
        ct_dst_src_ltm = 1.0
        
        is_sm = 1.0 if (self.src_ip == self.dst_ip and self.source_port == self.destination_port) else 0.0
        
        # Protocols & Categoricals mapping
        proto_clean = str(self.protocol).lower()
        state_clean = "CON"  # Default clean state
        service_clean = "-"
        
        # Assign typical ports to services
        if self.destination_port == 80 or self.source_port == 80:
            service_clean = "http"
        elif self.destination_port == 443 or self.source_port == 443:
            service_clean = "http"  # https maps to http service category
        elif self.destination_port == 53 or self.source_port == 53:
            service_clean = "dns"
        elif self.destination_port == 22 or self.source_port == 22:
            service_clean = "ssh"
        elif self.destination_port in [20, 21] or self.source_port in [20, 21]:
            service_clean = "ftp"
            
        return {
            "sport": float(self.source_port or 0),
            "dsport": float(self.destination_port or 0),
            "dur": duration_sec,
            "sbytes": float(tot_fwd_len),
            "dbytes": float(tot_bwd_len),
            "sttl": sttl,
            "dttl": dttl,
            "sloss": 0.0,
            "dloss": 0.0,
            "Sload": sload,
            "Dload": dload,
            "Spkts": float(len(self.fwd_packets)),
            "Dpkts": float(len(self.bwd_packets)),
            "swin": float(swin),
            "dwin": float(dwin),
            "stcpb": 0.0,
            "dtcpb": 0.0,
            "smeansz": smeansz,
            "dmeansz": dmeansz,
            "trans_depth": 0.0,
            "res_bdy_len": 0.0,
            "Sjit": sjit,
            "Djit": djit,
            "Sintpkt": sintpkt,
            "Dintpkt": dintpkt,
            "tcprtt": tcprtt,
            "synack": synack,
            "ackdat": ackdat,
            "is_sm_ips_ports": is_sm,
            "ct_state_ttl": ct_state_ttl,
            "ct_flw_http_mthd": 0.0,
            "is_ftp_login": 0.0,
            "ct_ftp_cmd": 0.0,
            "ct_srv_src": ct_srv_src,
            "ct_srv_dst": ct_srv_dst,
            "ct_dst_ltm": ct_dst_ltm,
            "ct_src_ltm": ct_src_ltm,
            "ct_src_dport_ltm": ct_src_dport_ltm,
            "ct_dst_sport_ltm": ct_dst_sport_ltm,
            "ct_dst_src_ltm": ct_dst_src_ltm,
            "proto": proto_clean,
            "state": state_clean,
            "service": service_clean
        }

class FlowAggregationService:
    """
    Background worker aggregating packet lists into bidirectional flows.
    Checks for idle timeouts and queues completed flows for ML inference.
    """
    def __init__(self):
        self.active_flows: Dict[Tuple, Flow] = {}
        self.completed_flow_queue = queue.Queue(maxsize=1000)
        self.flow_timeout_sec = 5.0
        
        self.thread = None
        self.is_running = False
        
        self.flows_processed = 0
        self.dropped_flows = 0

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        self.flows_processed = 0
        self.dropped_flows = 0
        self.active_flows.clear()
        
        # Clear completed queue
        while not self.completed_flow_queue.empty():
            try:
                self.completed_flow_queue.get_nowait()
            except queue.Empty:
                break
                
        self.thread = threading.Thread(target=self._run_aggregator, name="FlowAggregationThread", daemon=True)
        self.thread.start()

    def stop(self):
        if not self.is_running:
            return
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=3.0)
            self.thread = None
        logger.info("Flow aggregation service stopped.")

    def _make_flow_key(self, src_ip: str, sport: int, dst_ip: str, dport: int, protocol: str) -> Tuple:
        """Canonicalize source and destination to group bidirectionally."""
        src_pair = (src_ip, sport or 0)
        dst_pair = (dst_ip, dport or 0)
        if src_pair <= dst_pair:
            return (src_pair, dst_pair, protocol)
        else:
            return (dst_pair, src_pair, protocol)

    def _run_aggregator(self):
        logger.info("Flow aggregation worker active.")
        last_scan_time = time.time()
        
        while self.is_running:
            # 1. Process pending packets from capture queue
            packets_to_process = []
            # Drain up to 100 packets at a time to batch update
            for _ in range(100):
                try:
                    pkt = packet_capture_service.packet_queue.get_nowait()
                    packets_to_process.append(pkt)
                except queue.Empty:
                    break
                    
            for pkt in packets_to_process:
                key = self._make_flow_key(
                    pkt["src_ip"], pkt["source_port"], 
                    pkt["dst_ip"], pkt["destination_port"], 
                    pkt["protocol"]
                )
                
                if key in self.active_flows:
                    self.active_flows[key].add_packet(pkt)
                else:
                    self.active_flows[key] = Flow(pkt)

            # 2. Periodically scan for idle timeouts (every 1s)
            current_time = time.time()
            if current_time - last_scan_time >= 1.0:
                last_scan_time = current_time
                keys_to_remove = []
                for key, flow in self.active_flows.items():
                    if current_time - flow.last_active >= self.flow_timeout_sec:
                        keys_to_remove.append(key)
                        
                for key in keys_to_remove:
                    completed_flow = self.active_flows.pop(key)
                    self._enqueue_completed_flow(completed_flow)
            
            # Short sleep to prevent CPU spinning
            time.sleep(0.01)

    def _enqueue_completed_flow(self, flow: Flow):
        self.flows_processed += 1
        try:
            self.completed_flow_queue.put_nowait(flow)
        except queue.Full:
            self.dropped_flows += 1
            if self.dropped_flows % 50 == 1:
                logger.warning(f"Completed flow queue full! Dropped {self.dropped_flows} flows.")

# Global aggregation singleton instance
flow_aggregation_service = FlowAggregationService()

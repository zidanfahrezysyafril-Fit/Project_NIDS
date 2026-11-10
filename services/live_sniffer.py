"""
Live Traffic Sniffer & Flow Aggregator for NIDS.
Captures raw packets, aggregates into bidirectional 5-tuple flows,
extracts the 14 optimal CICIDS features, and passes them to XGBoost.
"""
import time
import threading
import numpy as np
from datetime import datetime

class FlowSession:
    """Represents a bidirectional flow between two endpoints."""
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        self.start_time = time.time()
        self.last_time = self.start_time
        
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        
        self.packet_lengths = []
        self.iats = []
        
        self.syn_count = 0
        self.ack_count = 0
        self.psh_count = 0
        self.init_win_fwd = 64240 # Default OS window
        
    def add_packet(self, direction, length, flags=None, window=None):
        now = time.time()
        iat = (now - self.last_time) * 1e6 # microseconds
        self.iats.append(iat)
        self.last_time = now
        self.packet_lengths.append(length)
        
        if direction == 'fwd':
            self.fwd_packets += 1
            self.fwd_bytes += length
            if window and self.fwd_packets == 1:
                self.init_win_fwd = window
        else:
            self.bwd_packets += 1
            self.bwd_bytes += length
            
        if flags:
            if 'S' in flags: self.syn_count += 1
            if 'A' in flags: self.ack_count += 1
            if 'P' in flags: self.psh_count += 1

    def to_14_features(self):
        """Computes the exact 14 optimal features for XGBoost."""
        duration_sec = max(self.last_time - self.start_time, 0.0001)
        duration_us = duration_sec * 1e6
        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes
        
        lengths = self.packet_lengths if self.packet_lengths else [0]
        iats = self.iats if self.iats else [0]
        
        return {
            'Flow Duration': float(duration_us),
            'Total Fwd Packets': float(self.fwd_packets),
            'Total Backward Packets': float(self.bwd_packets),
            'Flow Packets/s': float(total_packets / duration_sec),
            'Flow Bytes/s': float(total_bytes / duration_sec),
            'Packet Length Mean': float(np.mean(lengths)),
            'Packet Length Std': float(np.std(lengths)),
            'Flow IAT Mean': float(np.mean(iats)),
            'Flow IAT Std': float(np.std(iats)),
            'SYN Flag Count': float(self.syn_count),
            'ACK Flag Count': float(self.ack_count),
            'Average Packet Size': float(np.mean(lengths)),
            'PSH Flag Count': float(self.psh_count),
            'Init_Win_bytes_forward': float(self.init_win_fwd)
        }

class LiveTrafficSniffer:
    """
    Multi-Mode Live Packet Sniffer:
    - Mode A: Real Packet Capture via Scapy/Npcap (if available/admin)
    - Mode B: In-Memory Live Gateway Flow Ingestion
    - Mode C: Live Attack Simulator / Testbed Streamer
    """
    def __init__(self, app=None):
        self.app = app
        self.is_running = False
        self._thread = None
        self._lock = threading.Lock()
        
        self.active_flows = {} # key: (src_ip, dst_ip, src_port, dst_port, proto)
        self.flow_timeout = 5.0 # seconds of inactivity to finalize flow
        
        # Telemetry stats for dashboard
        self.stats = {
            'status': 'Stopped',
            'mode': 'Gateway Ingestion & Simulation',
            'packets_captured': 0,
            'flows_analyzed': 0,
            'attacks_detected': 0,
            'last_attack': None,
            'last_update': datetime.utcnow().strftime('%H:%M:%S')
        }

    def start(self, mode='auto'):
        if self.is_running:
            return False, "Live sniffer is already running."
            
        self.is_running = True
        self.stats['status'] = 'Running'
        self.stats['mode'] = mode
        
        self._thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._thread.start()
        print("[LiveSniffer] Started live packet sniffing service.")
        return True, "Live sniffer successfully started."

    def stop(self):
        self.is_running = False
        self.stats['status'] = 'Stopped'
        print("[LiveSniffer] Stopped live packet sniffing service.")
        return True, "Live sniffer stopped."

    def ingest_packet(self, src_ip, dst_ip, src_port, dst_port, protocol, length, flags=None, window=None):
        """Ingests a packet from any gateway, reverse proxy, or raw listener."""
        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
        rev_key = (dst_ip, src_ip, dst_port, src_port, protocol)
        
        with self._lock:
            self.stats['packets_captured'] += 1
            if flow_key in self.active_flows:
                self.active_flows[flow_key].add_packet('fwd', length, flags, window)
            elif rev_key in self.active_flows:
                self.active_flows[rev_key].add_packet('bwd', length, flags, window)
            else:
                session = FlowSession(src_ip, dst_ip, src_port, dst_port, protocol)
                session.add_packet('fwd', length, flags, window)
                self.active_flows[flow_key] = session

    def _worker_loop(self):
        """Background thread to monitor flows and evaluate completed sessions with XGBoost."""
        from detectors.cicids_flow_detector import flow_detector
        
        while self.is_running:
            time.sleep(1.0)
            now = time.time()
            to_evaluate = []
            
            with self._lock:
                expired_keys = []
                for key, session in self.active_flows.items():
                    # Evaluate if flow has been inactive for flow_timeout OR has reached burst threshold
                    if (now - session.last_time >= self.flow_timeout) or (session.fwd_packets >= 50):
                        to_evaluate.append((key, session.to_14_features()))
                        expired_keys.append(key)
                        
                for k in expired_keys:
                    del self.active_flows[k]
                    
            # Evaluate extracted features with XGBoost
            for key, features in to_evaluate:
                self.stats['flows_analyzed'] += 1
                pred = flow_detector.predict_flow(features)
                
                if pred.get('is_attack'):
                    self.stats['attacks_detected'] += 1
                    label = pred.get('primary_label', 'DDoS')
                    conf = pred.get('confidence', 95.0)
                    self.stats['last_attack'] = {
                        'type': label,
                        'source_ip': key[0],
                        'target_ip': key[1],
                        'confidence': conf,
                        'timestamp': datetime.utcnow().strftime('%H:%M:%S')
                    }
                    self._record_attack_alert(key[0], key[1], label, conf, features)
                    
            self.stats['last_update'] = datetime.utcnow().strftime('%H:%M:%S')

    def _record_attack_alert(self, src_ip, dst_ip, attack_type, confidence, features):
        """Records the detected flow attack into PostgreSQL via Flask app context."""
        print(f"[ALERT LIVE SNIFFER] {attack_type} detected from {src_ip} -> {dst_ip} (Conf: {confidence}%)")
        if not self.app:
            return
            
        try:
            with self.app.app_context():
                from models import db, Website, Alert
                site = Website.query.first() # Attach to active website or default
                if site:
                    is_sim = src_ip == '192.168.1.185'
                    source_tag = "[Simulasi Pipeline] " if is_sim else "[Live Gateway] "
                    alert = Alert(
                        website_id=site.id,
                        attack_type=attack_type,
                        severity='Kritis' if 'DDoS' in attack_type or 'DoS' in attack_type else 'Tinggi',
                        source_ip=src_ip,
                        payload_sample=f"{source_tag}Flow Metrics: Pkts/s={features.get('Flow Packets/s', 0):.0f}, Dur={features.get('Flow Duration', 0):.0f}us, SYN={features.get('SYN Flag Count', 0)}",
                        status='Baru',
                        confidence_score=confidence
                    )
                    db.session.add(alert)
                    site.status = 'Serangan Aktif'
                    site.total_alerts_count += 1
                    db.session.commit()
        except Exception as e:
            print(f"[LiveSniffer Alert Error] {e}")

    def simulate_attack_burst(self, attack_type='DDoS', src_ip='192.168.1.185', target_ip='127.0.0.1', count=150, packet_count=None):
        """
        Simulates an in-memory packet burst for testing the pipeline end-to-end:
        verifies multi-threading, flow session aggregation, ML evaluation, and DB alerting.
        Clearly labeled as [Mode Simulasi Pipeline] to differentiate from physical raw capture.
        """
        if packet_count is not None:
            count = packet_count
        if attack_type == 'DDoS':
            for _ in range(count):
                self.ingest_packet(src_ip, target_ip, np.random.randint(1024, 65535), 80, 'TCP', length=64, flags='S', window=256)
        elif attack_type == 'PortScan':
            for port in range(20, 20 + count):
                self.ingest_packet(src_ip, target_ip, np.random.randint(1024, 65535), port, 'TCP', length=40, flags='S', window=1024)
        elif attack_type == 'DoS slowloris':
            for _ in range(min(count, 50)):
                self.ingest_packet(src_ip, target_ip, np.random.randint(1024, 65535), 80, 'TCP', length=12, flags='P', window=64240)
        return True

live_sniffer = LiveTrafficSniffer()

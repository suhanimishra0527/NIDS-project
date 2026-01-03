from src.detectors.base_detector import BaseDetector
from scapy.all import IP, TCP
import time
from collections import defaultdict, deque

class BruteForceDetector(BaseDetector):
    def __init__(self, config):
        super().__init__(config)
        self.enabled = config.get('brute_force', {}).get('enabled', False)
        self.interval = config.get('brute_force', {}).get('interval', 60)
        self.threshold = config.get('brute_force', {}).get('threshold', 20)
        
        # Optimization: Use deque for O(1) pop operations on sliding window
        # Structure: { (src_ip, dst_port): deque([timestamp1, timestamp2, ...]) }
        self.attempts = defaultdict(deque)
        self.last_alert = {}
        
        # False Positive Reduction: Whitelist known friendly IPs
        self.whitelist = set(config.get('whitelist_ips', []))

    def process_packet(self, packet):
        alerts = []
        if not self.enabled:
            return alerts

        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            
            if src_ip in self.whitelist:
                return alerts
            
            # False Positive Reduction: Only valid for services prone to brute-force
            # Ignoring random high ports or ephemeral ports
            if dst_port not in [21, 22, 23, 80, 443, 3306, 3389]:
                return alerts

            # Logic: Track connection initiation packets (SYN)
            # This counts attempts, not successful connections
            if packet[TCP].flags & 0x02: # 0x02 is SYN flag
                current_time = time.time()
                key = (src_ip, dst_port)
                
                window = self.attempts[key]
                window.append(current_time)
                
                # Cleanup: Remove old attempts that fell out of the sliding window
                while window and (current_time - window[0] > self.interval):
                    window.popleft()
                
                # Detection
                if len(window) > self.threshold:
                    # Rate Limit
                    last = self.last_alert.get(key, 0)
                    if current_time - last > self.interval:
                        alerts.append({
                            'message': f"Brute Force detected: {src_ip} -> Port {dst_port} ({len(window)} attempts/min)",
                            'source_ip': src_ip,
                            'severity': 'HIGH',
                            'type': 'brute_force'
                        })
                        self.last_alert[key] = current_time

        return alerts

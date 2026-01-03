from src.detectors.base_detector import BaseDetector
from scapy.all import IP, TCP, Raw

class SignatureDetector(BaseDetector):
    def __init__(self, config):
        super().__init__(config)
        self.signatures = config.get('signatures', [])
        # Optimization: Store whitelists as a set for O(1) lookup
        self.whitelist = set(config.get('whitelist_ips', []))

    def process_packet(self, packet):
        alerts = []
        if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # False Positive Reduction: Ignore whitelisted flows
            if src_ip in self.whitelist:
                return alerts

            try:
                # Performance: Decode payload once
                # Errors='ignore' prevents crashing on binary data
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # Logic: Scan for known malicious strings
                for signature in self.signatures:
                    if signature in payload:
                        alerts.append({
                            'message': f"Signature detected: '{signature}' to {dst_ip}",
                            'source_ip': src_ip,
                            'severity': 'HIGH',
                            'type': 'signature'
                        })
                        # Performance: Break after first match to avoid duplicate alerts per packet
                        break
            except Exception:
                pass
        return alerts

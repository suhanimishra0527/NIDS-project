from src.detectors.base_detector import BaseDetector
from scapy.all import IP, TCP
import time
from collections import defaultdict

class PortScanDetector(BaseDetector):
    def __init__(self, config):
        super().__init__(config)
        self.enabled = config.get('port_scan', {}).get('enabled', False)
        self.interval = config.get('port_scan', {}).get('interval', 60)
        self.threshold = config.get('port_scan', {}).get('threshold', 10)
        
        # Optimization: Use separate structure for tracking just the minimal info needed.
        # Structure: {src_ip: {port: last_seen_timestamp}}
        self.scan_history = defaultdict(dict)
        self.last_alert = {}
        
        # False Positive Reduction: Whitelisted IPs (e.g., Gateway, DNS server)
        self.whitlist = set(config.get('whitelist_ips', []))

    def process_packet(self, packet):
        alerts = []
        if not self.enabled:
            return alerts

        # Only analyze TCP packets (SYN/Connect scans)
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            
            # False Positive Reduction: Ignore whitelisted IPs
            if src_ip in self.whitlist:
                return alerts

            current_time = time.time()

            # Logic: Track 'distinct' ports accessed within the time interval
            # We lazy-clean (clean only on activity) for performance
            self.cleanup(src_ip, current_time)

            # Record port access
            self.scan_history[src_ip][dst_port] = current_time

            # Detection: Count distinct ports currently active in the window
            unique_ports_count = len(self.scan_history[src_ip])
            
            if unique_ports_count > self.threshold:
                # Rate Limiting: Alert only once per interval to reduce log noise
                last = self.last_alert.get(src_ip, 0)
                if current_time - last > self.interval:
                    alerts.append({
                        'message': f"Port Scan: {src_ip} scanned {unique_ports_count} distinct ports (Threshold: {self.threshold})",
                        'source_ip': src_ip,
                        'severity': 'MEDIUM',
                        'type': 'port_scan'
                    })
                    self.last_alert[src_ip] = current_time

        return alerts

    def cleanup(self, src_ip, current_time):
        """
        Removes ports that haven't been accessed within the rolling window.
        """
        if src_ip in self.scan_history:
            # Create a list of ports to remove to avoid 'dictionary changed size during iteration'
            ports_to_remove = [
                port for port, ts in self.scan_history[src_ip].items() 
                if current_time - ts > self.interval
            ]
            for port in ports_to_remove:
                del self.scan_history[src_ip][port]
            
            # Memory Optimization: If IP has no active ports, remove IP entry
            if not self.scan_history[src_ip]:
                del self.scan_history[src_ip]

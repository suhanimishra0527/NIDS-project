from src.detectors.base_detector import BaseDetector
import time

class AnomalyDetector(BaseDetector):
    def __init__(self, config):
        super().__init__(config)
        self.enabled = config.get('anomaly', {}).get('enabled', False)
        self.threshold = config.get('anomaly', {}).get('packet_rate_threshold', 100)
        
        # Optimization: Use variables for lightweight state
        self.start_time = time.time()
        self.packet_count = 0
        self.window_size = 1.0 # Check every second
        self.last_check = time.time()
        
        # Smoothing: Use simple Moving Average if needed, 
        # but for simple rate limiting, direct count is usually fine.
        # False Positive Reduction: A burst of 101 packets shouldn't trigger if average is 50.
        # But for DDoS, we care about 'current' intensity. 
        # We will keep it simple but add a 'persistence' check could be a future enhancement.

    def process_packet(self, packet):
        alerts = []
        if not self.enabled:
            return alerts

        current_time = time.time()
        self.packet_count += 1

        if current_time - self.last_check >= self.window_size:
            # Calculate rate accurately
            elapsed = current_time - self.last_check
            rate = self.packet_count / elapsed
            
            if rate > self.threshold:
                alerts.append({
                    'message': f"Anomaly: High packet rate detected ({int(rate)} pkt/s)",
                    'source_ip': "Network",
                    'severity': 'MEDIUM',
                    'type': 'anomaly'
                })
            
            # Reset
            self.packet_count = 0
            self.last_check = current_time

        return alerts

class BaseDetector:
    def __init__(self, config):
        self.config = config

    def process_packet(self, packet):
        """
        Process a packet and return a list of alerts.
        Each alert should be a dict: {
            'message': str,
            'source_ip': str,
            'severity': str, # 'LOW', 'MEDIUM', 'HIGH'
            'type': str # 'signature', 'port_scan', 'brute_force', 'anomaly'
        }
        """
        raise NotImplementedError("Subclasses must implement process_packet")

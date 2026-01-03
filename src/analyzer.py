from scapy.all import IP, TCP, Raw
from src.utils import load_config
from src.alerts import setup_logger, log_to_json
from src.scoring import ThreatScoringEngine
from src.detectors.signature_detector import SignatureDetector
from src.detectors.port_scan_detector import PortScanDetector
from src.detectors.brute_force_detector import BruteForceDetector
from src.detectors.anomaly_detector import AnomalyDetector
import os

class PacketAnalyzer:
    def __init__(self):
        self.config = load_config()
        self.scoring_engine = ThreatScoringEngine(self.config)
        
        # Initialize Detectors
        self.detectors = [
            SignatureDetector(self.config),
            PortScanDetector(self.config),
            BruteForceDetector(self.config),
            AnomalyDetector(self.config)
        ]

    def process_packet(self, packet):
        """
        Runs packet through all detectors.
        """
        for detector in self.detectors:
            alerts = detector.process_packet(packet)
            for alert in alerts:
                self.handle_alert(alert)

    def handle_alert(self, alert):
        severity = alert['severity']
        message = alert['message']
        source_ip = alert['source_ip']
        alert_type = alert['type']

        # Calculate Risk and Score
        base_score = self.scoring_engine.get_score(severity)
        # We could accumulate scores here if we tracked session state, 
        # but for now we essentially log each alert with its risk.
        risk_level = self.scoring_engine.calculate_risk(base_score)
        
        # Print to Console
        print(f"[{risk_level}] {message}")

        # Log to File (Legacy)
        # We need to ensure the logger is setup. Ideally run.py sets it up, 
        # but we can call it here or rely on the global logging config.
        # Assuming run.py sets up basic logging.
        import logging
        logging.info(f"[{risk_level}] {message}")

        # Log to JSON
        log_to_json(risk_level, message, source_ip, alert_type)

import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Add src to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detectors.signature_detector import SignatureDetector

class TestSignatureDetector(unittest.TestCase):

    def setUp(self):
        # Mock Config
        self.config = {
            "signatures": ["TEST_SIG", "BAD_STUFF"],
            "logging": {"log_dir": "test_logs", "filename": "test_alerts.txt"}
        }
        self.detector = SignatureDetector(self.config)

    def test_signature_detected(self):
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"
        payload = "This packet contains BAD_STUFF inside it."
        
        # Mock Scapy Packet
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = True
        mock_packet.__getitem__.return_value.src = src_ip
        mock_packet.__getitem__.return_value.dst = dst_ip
        mock_packet.__getitem__.return_value.load.decode.return_value = payload
        
        alerts = self.detector.process_packet(mock_packet)
        
        self.assertTrue(len(alerts) > 0)
        self.assertIn("BAD_STUFF", alerts[0]['message'])
        self.assertEqual(alerts[0]['severity'], 'HIGH')

    def test_clean_packet(self):
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"
        payload = "Just some innocent data."
        
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = True
        mock_packet.__getitem__.return_value.src = src_ip
        mock_packet.__getitem__.return_value.dst = dst_ip
        mock_packet.__getitem__.return_value.load.decode.return_value = payload
        
        alerts = self.detector.process_packet(mock_packet)
        
        self.assertEqual(len(alerts), 0)

    def test_custom_signatures(self):
        self.assertIn("TEST_SIG", self.detector.signatures)

if __name__ == '__main__':
    unittest.main()

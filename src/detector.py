import os
import datetime
import yaml

class ThreatDetector:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.config_path = os.path.join(self.base_dir, "configs", "config.yaml")
        
        self.config = self.load_config()
        
        # Load settings from config or ignore if missing (defaults)
        log_config = self.config.get("logging", {})
        self.log_dir = os.path.join(self.base_dir, log_config.get("log_dir", "logs"))
        self.log_file = os.path.join(self.log_dir, log_config.get("filename", "alerts.txt"))
        
        # Ensure log directory exists
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

        self.signatures = self.config.get("signatures", [])
        if not self.signatures:
            # Fallback default signatures
            self.signatures = ["UNION SELECT", "DROP TABLE"]

    def load_config(self):
        if os.path.exists(self.config_path):
            with open(self.config_path, "r") as f:
                try:
                    return yaml.safe_load(f) or {}
                except yaml.YAMLError as e:
                    print(f"[!] Error loading config: {e}")
        return {}

    def check_threat(self, src_ip, dst_ip, payload):
        for signature in self.signatures:
            if signature in payload:
                alert_msg = f"[ALERT] Signature detected: '{signature}' from {src_ip} -> {dst_ip}"
                print(alert_msg)
                self.log_alert(alert_msg)

    def log_alert(self, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, "a") as f:
            f.write(f"[{timestamp}] {message}\n")

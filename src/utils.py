import yaml
import os

def load_config(config_path="configs/config.yaml"):
    """
    Loads configuration from a YAML file.
    """
    if not os.path.exists(config_path):
        print(f"[!] Config file not found: {config_path}")
        return None

    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            return config
    except Exception as e:
        print(f"[!] Error loading config: {e}")
        return None

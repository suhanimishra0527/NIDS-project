import os
import logging
import sqlite3
import datetime

import json

JSON_LOG_PATH = "logs/alerts.json"

def log_to_json(severity, message, source_ip, alert_type):
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = {
            "timestamp": timestamp,
            "severity": severity,
            "message": message,
            "source_ip": source_ip,
            "type": alert_type
        }
        with open(JSON_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[!] JSON Log Error: {e}")

def setup_logger(log_file_path):
    """
    Sets up a simple logger to append to a file.
    """
    # Create directory if it doesn't exist
    log_dir = os.path.dirname(log_file_path)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)

    logging.basicConfig(
        filename=log_file_path,
        level=logging.INFO,
        format='[%(asctime)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    


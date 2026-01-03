# NIDS Project (Advanced)

A modular, production-ready Network Intrusion Detection System built using Python, Scapy, and Flask.

## 🚀 Features

### Core Capabilities
- **Real-time Packet Capture**: Monitors network traffic live.
- **PCAP Replay**: Analyze offline `.pcap` files for forensic analysis.
- **Threat Scoring Engine**: auto-calculates risk (LOW, MEDIUM, HIGH) based on severity.
- **Web Dashboard**: Visualizes threats in real-time.

### Advanced Detection Modules
1.  **Signature Detection**: SQL Injection, XSS, etc.
2.  **Port Scan Detection**: Identifies rapid access to multiple distinct ports (`threshold=10`).
3.  **Brute Force Detection**: Flags high-frequency connection attempts to sensitive ports (SSH, FTP, HTTP).
4.  **Anomaly Detection**: Monitors packet rate for DDoS-like behavior.

## 📂 Project Structure
- `src/`
  - `detectors/`: Modular detection logic (`port_scan`, `brute_force`, `anomaly`, `signature`).
  - `analyzer.py`: Orchestrates the detection pipeline.
  - `scoring.py`: Risk calculation logic.
  - `alerts.py`: Dual logging (Text + SQLite).
- `dashboard/`: Flask web application.
- `configs/`: YAML configuration.

## 🛠 Installation
```bash
pip install -r requirement.txt
```

## ⚡ Usage

### 1. Live Detection
Start the NIDS in live mode:
```bash
python run.py --live
```

### 2. Dashboard
Start the Web UI (Open `http://localhost:5000`):
```bash
python run.py --dashboard
```

### 3. PCAP Analysis
Replay a capture file:
```bash
python run.py --pcap traffic.pcap
```

## 🧪 Testing & Simulation
To verify the system, run the simulation script which mimics **SQLi, XSS, Port Scans, and Brute Force attacks**:
```bash
python attack_simulation.py
```

Run unit tests:
```bash
python -m unittest discover tests
```

## ⚙️ Configuration
All thresholds and toggles are in `configs/config.yaml`.

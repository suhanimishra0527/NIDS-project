# Network Intrusion Detection System (NIDS)

## Overview
This project is a Network Intrusion Detection System (NIDS) developed to monitor
network traffic and detect malicious or suspicious activities within a network.
It is designed as an academic and learning-oriented implementation inspired by
industry-standard tools such as Snort and Suricata.

The system analyzes network behavior to identify potential security threats and
presents the detected events through a SOC-style dashboard for monitoring and analysis.


## Objectives
- To understand the working principles of network intrusion detection systems
- To implement multiple detection techniques in a single framework
- To visualize security alerts in a structured and meaningful way
- To simulate and analyze real-world network attacks in a controlled environment


## Key Features
- Port scan detection based on connection patterns
- Signature-based detection for common web attacks such as SQL Injection and XSS
- Anomaly-based detection using traffic rate analysis
- Real-time alert generation
- Persistent alert logging for historical analysis
- SOC-style dashboard with graphs and alert history
- Timestamped alerts using system date and time


## Detection Techniques Used

### 1. Port Scan Detection
Detects rapid or sequential connection attempts to multiple ports from a single source,
indicating reconnaissance activity.

### 2. Signature-Based Detection
Matches network payloads against predefined patterns to identify known attacks such as:
- SQL Injection
- Cross-Site Scripting (XSS)

### 3. Anomaly-Based Detection
Monitors traffic behavior and detects deviations from normal patterns, such as unusually
high packet or request rates.


## Project Architecture
The project follows a modular architecture with a clear separation between detection
and visualization components.

- **Detection Engine**: Runs locally and monitors network traffic
- **Alert Logger**: Stores detected alerts persistently in log files
- **Dashboard**: Reads alert logs and presents them visually


## Project Structure
NIDS/
├── run.py
├── dashboard/
│ ├── templates/
│ │ └── index.html
│ └── static/
│ ├── css/
│ ├── js/
│ └── assets/
├── logs/
│ └── alerts.json
├── requirements.txt
└── README.md

yaml

## Running the Project Locally (Step-by-Step)

### Prerequisites
- Python 3.9 or higher
- Git
- Administrator / Root privileges (required for packet capture)
- Npcap (Windows only)  
  Download: https://nmap.org/npcap/  
  Enable **WinPcap compatibility mode** during installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/suhanimishra0527/NIDS-project.git
cd NIDS-project
Step 2: (Optional) Create a Virtual Environment
bash

python -m venv venv
Activate it:

Windows

bash

venv\Scripts\activate
Linux / macOS

bash

source venv/bin/activate
Step 3: Install Dependencies
bash

pip install -r requirements.txt
Install Scapy for local detection:

bash

pip install scapy
Step 4: Run the Dashboard (Visualization Mode)
This mode is cloud-safe and does not require administrator privileges.

bash

python run.py --dashboard
Open in browser:

arduino

http://localhost:5000
Step 5: Run Live Intrusion Detection (Local Mode)
 Run the terminal as Administrator / Root

bash

python run.py --live
This enables:

Live packet capture

Attack detection

Alert generation

Attack Simulation (Optional Testing)
Port Scan (Windows PowerShell)
powershell

1..50 | ForEach-Object { Test-NetConnection localhost -Port $_ -WarningAction SilentlyContinue }
Traffic Spike / Anomaly
bash

ping localhost -t
SQL Injection / XSS Simulation
bash
Copy code
curl "http://localhost:5000/test?input=' OR 1=1--"
curl "http://localhost:5000/test?input=<script>alert(1)</script>"
Detected attacks will appear in:

Live detection terminal

Dashboard interface

Alert log files

Cloud vs Local Execution
Mode	Environment	Functionality
Local	Personal system	Full packet capture and detection
Cloud	Render	Dashboard and visualization only

Cloud platforms restrict raw socket access; therefore, live packet capture runs locally.

Deployment Note
Due to security restrictions imposed by cloud platforms, live packet capture and
network sniffing cannot be performed in deployed environments.

The deployed version provides a read-only SOC-style dashboard for visualization,
while full detection is demonstrated locally.

Technologies Used
Python

Flask

Scapy (local detection)

PowerShell (attack simulation)

JSON-based persistent logging

HTML, CSS, and JavaScript for dashboard visualization

Limitations
Designed for educational and small-scale environments

Intrusion Detection System only (IDS), not an Intrusion Prevention System (IPS)

Cloud deployment limited to visualization

Academic Purpose
This project is developed as an academic cybersecurity project to demonstrate
core concepts of network intrusion detection, traffic analysis, and security monitoring.
It is not intended for direct production use without further hardening and optimization.

yaml

##  FINAL STEP 

After pasting and saving:

```bash
git add README.md
git commit -m "Update README with local usage and cloning steps"
git push

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

- Detection Engine: Runs locally and monitors network traffic
- Alert Logger: Stores detected alerts persistently in a log file
- Dashboard: Reads alert logs and presents them visually


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


## How to Run the Project Locally

### Step 1: Start the Detection Engine
Run the following command to start live intrusion detection:
```bash
python run.py --live
Step 2: Start the Dashboard
In a separate terminal, start the dashboard:

bash
Copy code
python run.py --dashboard
Open the dashboard in a browser:

arduino
Copy code
http://localhost:5000
Attack Simulation
Attacks can be simulated manually using PowerShell or command-line tools to generate:

Port scans

Injection payloads

High-volume traffic for anomaly detection

These simulations help validate the effectiveness of each detection module.

Deployment Note
Due to security restrictions imposed by cloud platforms, live packet capture and
network sniffing cannot be performed in deployed environments.

Therefore:

Live intrusion detection is demonstrated locally

The deployed version provides a read-only dashboard for visualization

Alert history is loaded from persistent logs

This approach aligns with how real-world NIDS solutions are demonstrated and evaluated.

Technologies Used
Python

Flask

PowerShell (for attack simulation)

JSON-based persistent logging

HTML, CSS, and JavaScript for dashboard visualization

Limitations
The system is designed for educational purposes and small-scale environments

It does not block traffic (IDS, not IPS)

Cloud deployment is limited to visualization only

Academic Purpose
This project is developed as an academic cybersecurity project to demonstrate
core concepts of network intrusion detection, traffic analysis, and security monitoring.

It is not intended for direct use in production environments without further hardening
and optimization.

yaml

### What to do next
1. Paste this into `README.md`
2. Save the file
3. Run:
```bash
git add README.md
git commit -m "Update detailed project README"
git push

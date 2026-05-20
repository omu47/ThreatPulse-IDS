# ThreatPulse IDS
### AI Powered Intrusion Detection & Network Monitoring System

ThreatPulse IDS is an advanced real-time network packet monitoring and intrusion detection system developed using Python, Flask, Scapy, SQLite, and Machine Learning.

The system captures live network traffic, analyzes packets, detects suspicious activities, generates security alerts, and visualizes traffic statistics through a modern SOC-style dashboard.

---
https://x.com/Umashankar098/status/2057103803770679344



# Key Features

## Real-Time Packet Sniffing
- Live network packet capture using Scapy
- TCP / UDP / ICMP traffic monitoring
- Source and destination IP tracking
- Port inspection and protocol analysis

## Threat Detection Engine
- DDoS attack detection
- Port scan detection
- Suspicious IP activity analysis
- Blacklisted IP identification
- Real-time security alert generation

## AI / Machine Learning Detection
- Isolation Forest anomaly detection
- Unusual packet size identification
- Intelligent traffic anomaly analysis

## SOC Dashboard
- Flask-based monitoring dashboard
- Live packet monitoring table
- Attack alert visualization
- Protocol statistics charts
- Real-time traffic insights

## Database Integration
- SQLite-based packet storage
- Security alert database
- Persistent traffic logging
- Fast query-based monitoring

## Reporting System
- Automated PDF security reports
- Threat summary generation
- Protocol statistics reports
- Alert severity breakdown

---

# Technologies Used

## Backend
- Python
- Flask
- Flask-SocketIO

## Networking & Security
- Scapy
- Socket Programming

## Machine Learning
- Scikit-learn
- Isolation Forest
- NumPy

## Database
- SQLite

## Frontend
- HTML5
- Bootstrap 5
- Chart.js

## Reporting
- ReportLab PDF Engine

---

# System Architecture

```text
ThreatPulse-IDS/
│
├── app/
│   ├── dashboard/
│   │   └── routes.py
│   │
│   ├── database/
│   │   └── db.py
│   │
│   ├── detection/
│   │   ├── threat_detector.py
│   │   └── threat_intelligence.py
│   │
│   ├── ml/
│   │   └── anomaly_detector.py
│   │
│   ├── sniffer/
│   │   └── packet_sniffer.py
│   │
│   └── utils/
│       ├── logger.py
│       ├── alert_logger.py
│       └── report_generator.py
│
├── templates/
│   └── dashboard.html
│
├── reports/
├── logs/
├── threatpulse.db
├── run.py
├── config.py
└── requirements.txt

Core Concepts Implemented
Network Packet Analysis

The system captures raw packets from the network interface and analyzes:

protocols
IP addresses
ports
traffic direction
packet sizes
Intrusion Detection System (IDS)

ThreatPulse IDS acts as a lightweight IDS by monitoring network behavior and identifying:

suspicious traffic
DDoS attacks
scanning behavior
abnormal traffic patterns
Threat Intelligence

The system checks incoming IP addresses against a simulated blacklist database to identify:

malicious hosts
TOR exit nodes
suspicious scanners
Anomaly Detection

Machine learning is used to identify abnormal packet sizes using:

Isolation Forest algorithm
statistical anomaly analysis
Real-Time Monitoring

Flask-SocketIO enables live packet and alert streaming directly to the dashboard.

Security Reporting

The application generates downloadable PDF reports containing:

traffic statistics
protocol distribution
top source IPs
threat summaries
alert severity analysis
Implemented Security Features
Feature	Status
TCP Monitoring	Completed
UDP Monitoring	Completed
ICMP Monitoring	Completed
Packet Logging	Completed
DDoS Detection	Completed
Port Scan Detection	Completed
Threat Intelligence	Completed
Blacklisted IP Detection	Completed
AI Anomaly Detection	Completed
SQLite Database	Completed
Real-Time Dashboard	Completed
PDF Reports	Completed
Chart Visualization	Completed
Future Enhancements
GeoIP attacker tracking
CVE intelligence integration
REST API support
User authentication
Elasticsearch logging
Docker deployment
SIEM integration
Threat heatmap visualization
Installation
Clone Repository
git clone https://github.com/YOUR_USERNAME/ThreatPulse-IDS.git
cd ThreatPulse-IDS
Install Dependencies
pip install -r requirements.txt
Install Npcap (Windows)

Download:
https://npcap.com/

Install with:

WinPcap Compatibility Mode enabled
Run Application
python run.py

Open browser:

http://127.0.0.1:5000


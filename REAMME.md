# ThreatPulse IDS

Advanced Network Intrusion Detection & Monitoring System built with Python, Flask, Scapy, SQLite, and Machine Learning.

---

## Features

### Network Monitoring
- Real-time packet sniffing
- TCP / UDP / ICMP inspection
- Source & destination tracking
- Live traffic monitoring

### Threat Detection
- DDoS attack detection
- Port scan detection
- Blacklisted IP detection
- Suspicious traffic analysis

### AI / ML Features
- Isolation Forest anomaly detection
- Unusual packet size detection
- Intelligent threat alerts

### Dashboard
- Flask web dashboard
- Live packet monitoring
- Threat alert panel
- Protocol statistics charts
- Downloadable PDF security reports

### Database
- SQLite-based storage
- Packet logging
- Alert management

---

## Tech Stack

### Backend
- Python
- Flask
- Flask-SocketIO

### Networking & Security
- Scapy
- Socket Programming

### AI/ML
- Scikit-learn
- Isolation Forest

### Database
- SQLite

### Frontend
- HTML
- Bootstrap 5
- Chart.js

---

## Project Structure

```bash
ThreatPulse-IDS/
│
├── app/
│   ├── dashboard/
│   ├── database/
│   ├── detection/
│   ├── ml/
│   ├── sniffer/
│   └── utils/
│
├── logs/
├── reports/
├── static/
├── templates/
│
├── threatpulse.db
├── run.py
├── config.py
└── requirements.txt
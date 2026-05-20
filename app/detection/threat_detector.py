from collections import defaultdict, deque
from datetime import datetime
import time

from config import Config
from app.utils.alert_logger import save_alert

packet_times = defaultdict(deque)
port_access = defaultdict(deque)
last_alert_time = defaultdict(float)


def _build_alert(alert_type, severity, source_ip, message):
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": alert_type,
        "severity": severity,
        "source_ip": source_ip,
        "message": message,
    }


def detect_ddos(src_ip):
    now = time.time()
    window = Config.THREAT_WINDOW_SECONDS

    times = packet_times[src_ip]
    times.append(now)

    while times and times[0] < now - window:
        times.popleft()

    if len(times) >= Config.DDOS_THRESHOLD and now - last_alert_time[src_ip] >= window:
        last_alert_time[src_ip] = now
        return _build_alert(
            "DDoS Attack",
            "HIGH",
            src_ip,
            f"High packet rate detected from {src_ip}",
        )

    return None


def detect_port_scan(src_ip, dst_port):
    now = time.time()
    window = Config.THREAT_WINDOW_SECONDS

    accesses = port_access[src_ip]
    accesses.append((now, dst_port))

    while accesses and accesses[0][0] < now - window:
        accesses.popleft()

    unique_ports = {port for _, port in accesses}

    if len(unique_ports) >= Config.PORT_SCAN_THRESHOLD:
        return _build_alert(
            "Port Scan",
            "MEDIUM",
            src_ip,
            f"Multiple ports accessed from {src_ip} within {window}s",
        )

    return None


def generate_alert(alert_data):
    normalized = {
        "timestamp": alert_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "type": alert_data.get("type") or alert_data.get("alert_type", "Unknown"),
        "severity": alert_data.get("severity", "LOW"),
        "source_ip": alert_data.get("source_ip", "N/A"),
        "message": alert_data.get("message", ""),
    }

    print("\n" + "=" * 60)
    print(f"[ALERT] {normalized['timestamp']}")
    print(f"TYPE: {normalized['type']}")
    print(f"SEVERITY: {normalized['severity']}")
    print(f"SOURCE IP: {normalized['source_ip']}")
    print(f"MESSAGE: {normalized['message']}")
    print("=" * 60 + "\n")

    save_alert(normalized)
    return normalized
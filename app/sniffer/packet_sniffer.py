from collections import Counter
from datetime import datetime
import socket

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP

from config import Config
from app.detection.threat_intelligence import check_blacklist
from app.utils.logger import log_packet
from app.ml.anomaly_detector import detect_anomaly
from app.detection.threat_detector import (
    detect_ddos,
    detect_port_scan,
    generate_alert,
)

protocol_stats = Counter()


def get_local_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]


LOCAL_IP = get_local_ip()


def emit_alert(socketio, alert):
    normalized = generate_alert(alert)
    if socketio:
        socketio.emit("new_alert", normalized)


def emit_packet(socketio, packet_data):
    if socketio:
        socketio.emit("new_packet", packet_data)


def process_packet(pkt, socketio):
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if pkt.haslayer(TCP):
            ip_layer = IP if pkt.haslayer(IP) else IPv6

            src_ip = pkt[ip_layer].src
            dst_ip = pkt[ip_layer].dst
            direction = "INCOMING" if dst_ip == LOCAL_IP else "OUTGOING"

            protocol_stats["TCP"] += 1

            print(f"[TCP-{direction}] {src_ip}:{pkt.sport} -> {dst_ip}:{pkt.dport}")

            log_packet(
                protocol="TCP",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=pkt.sport,
                dst_port=pkt.dport,
                packet_size=len(pkt),
                direction=direction,
            )

            emit_packet(socketio, {
                "timestamp": timestamp,
                "protocol": "TCP",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": pkt.sport,
                "destination_port": pkt.dport,
                "packet_size": len(pkt),
                "direction": direction,
            })

            ddos_alert = detect_ddos(src_ip)
            if ddos_alert:
                emit_alert(socketio, ddos_alert)

            portscan_alert = detect_port_scan(src_ip, pkt.dport)
            if portscan_alert:
                emit_alert(socketio, portscan_alert)

            blacklist_result = check_blacklist(src_ip)
            if blacklist_result["blacklisted"]:
                emit_alert(socketio, {
                    "type": "Blacklisted IP Detected",
                    "severity": "CRITICAL",
                    "source_ip": src_ip,
                    "message": f"{src_ip} flagged as {blacklist_result['reason']}",
                    "timestamp": timestamp,
                })

            anomaly_result = detect_anomaly(len(pkt))
            if anomaly_result["anomaly"]:
                emit_alert(socketio, {
                    "type": "AI Traffic Anomaly",
                    "severity": "HIGH",
                    "source_ip": src_ip,
                    "message": anomaly_result["message"],
                    "timestamp": timestamp,
                })

        elif pkt.haslayer(UDP) and pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            direction = "INCOMING" if dst_ip == LOCAL_IP else "OUTGOING"

            protocol_stats["UDP"] += 1

            print(f"[UDP-{direction}] {src_ip}:{pkt.sport} -> {dst_ip}:{pkt.dport}")

            log_packet(
                protocol="UDP",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=pkt.sport,
                dst_port=pkt.dport,
                packet_size=len(pkt),
                direction=direction,
            )

            emit_packet(socketio, {
                "timestamp": timestamp,
                "protocol": "UDP",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": pkt.sport,
                "destination_port": pkt.dport,
                "packet_size": len(pkt),
                "direction": direction,
            })

        elif pkt.haslayer(ICMP) and pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            direction = "INCOMING" if dst_ip == LOCAL_IP else "OUTGOING"

            protocol_stats["ICMP"] += 1

            print(f"[ICMP-{direction}] {src_ip} -> {dst_ip}")

            log_packet(
                protocol="ICMP",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port="N/A",
                dst_port="N/A",
                packet_size=len(pkt),
                direction=direction,
            )

            emit_packet(socketio, {
                "timestamp": timestamp,
                "protocol": "ICMP",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": "N/A",
                "destination_port": "N/A",
                "packet_size": len(pkt),
                "direction": direction,
            })

    except Exception as e:
        print(f"[ERROR] {e}")


def start_sniffer(socketio):
    print(f"[INFO] Packet Sniffer Started on {LOCAL_IP}")

    try:
        sniff(
            prn=lambda pkt: process_packet(pkt, socketio),
            store=False,
        )
    except RuntimeError as e:
        print(f"[ERROR] Sniffer failed: {e}")
        print("Make sure Npcap is installed on Windows.")
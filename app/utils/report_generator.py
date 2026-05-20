from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet

from datetime import datetime
import os

from app.database.db import (
    get_recent_packets,
    get_recent_alerts,
    get_protocol_stats
)


def generate_security_report():

    os.makedirs("reports", exist_ok=True)

    filename = (
        f"reports/security_report_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    )

    document = SimpleDocTemplate(filename)

    styles = getSampleStyleSheet()

    elements = []

    # ---------------- TITLE ---------------- #

    elements.append(
        Paragraph(
            "ThreatPulse IDS Security Report",
            styles["Title"]
        )
    )

    elements.append(Spacer(1, 20))

    # ---------------- PACKET STATS ---------------- #

    stats = get_protocol_stats()

    tcp_count = stats["TCP"]
    udp_count = stats["UDP"]
    icmp_count = stats["ICMP"]

    total_packets = (
        tcp_count +
        udp_count +
        icmp_count
    )

    elements.append(
        Paragraph(
            f"Total Packets Captured: {total_packets}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"TCP Traffic: {tcp_count}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"UDP Traffic: {udp_count}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"ICMP Traffic: {icmp_count}",
            styles["BodyText"]
        )
    )

    # ---------------- TOP SOURCE IPS ---------------- #

    packets = get_recent_packets(200)

    ip_counter = {}

    for packet in packets:

        ip = packet["source_ip"]

        if ip not in ip_counter:

            ip_counter[ip] = 0

        ip_counter[ip] += 1

    top_ips = sorted(
        ip_counter.items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]

    elements.append(Spacer(1, 15))

    elements.append(
        Paragraph(
            "Top Source IP Addresses",
            styles["Heading2"]
        )
    )

    for ip, count in top_ips:

        elements.append(
            Paragraph(
                f"{ip} - {count} packets",
                styles["BodyText"]
            )
        )

    # ---------------- ALERT STATS ---------------- #

    alerts = get_recent_alerts(100)

    total_alerts = len(alerts)

    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            f"Total Threat Alerts: {total_alerts}",
            styles["BodyText"]
        )
    )

    severity_counts = {}

    for alert in alerts:

        severity = alert["severity"]

        if severity not in severity_counts:

            severity_counts[severity] = 0

        severity_counts[severity] += 1

    elements.append(Spacer(1, 15))

    elements.append(
        Paragraph(
            "Alert Severity Breakdown",
            styles["Heading2"]
        )
    )

    for severity, count in severity_counts.items():

        elements.append(
            Paragraph(
                f"{severity}: {count}",
                styles["BodyText"]
            )
        )

    # ---------------- RECENT ALERTS ---------------- #

    elements.append(Spacer(1, 15))

    elements.append(
        Paragraph(
            "Recent Security Alerts",
            styles["Heading2"]
        )
    )

    for alert in alerts[:5]:

        alert_text = (
            f"{alert['timestamp']} | "
            f"{alert['alert_type']} | "
            f"{alert['severity']} | "
            f"{alert['source_ip']}"
        )

        elements.append(
            Paragraph(
                alert_text,
                styles["BodyText"]
            )
        )

    # ---------------- EMPTY STATE ---------------- #

    if total_packets == 0 and total_alerts == 0:

        elements.append(
            Paragraph(
                "No traffic or alert data available yet.",
                styles["BodyText"]
            )
        )

    document.build(elements)

    return filename
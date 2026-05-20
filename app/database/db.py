import sqlite3
from datetime import datetime

DATABASE_NAME = "threatpulse.db"


def get_connection():

    conn = sqlite3.connect(
        DATABASE_NAME,
        check_same_thread=False
    )

    conn.row_factory = sqlite3.Row

    return conn


def initialize_database():

    conn = get_connection()

    cursor = conn.cursor()

    # Packet logs table

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS packet_logs (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        timestamp TEXT,

        protocol TEXT,

        source_ip TEXT,

        destination_ip TEXT,

        source_port TEXT,

        destination_port TEXT,

        packet_size INTEGER,

        direction TEXT
    )
    """)

    # Alerts table

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        timestamp TEXT,

        alert_type TEXT,

        severity TEXT,

        source_ip TEXT,

        message TEXT
    )
    """)

    conn.commit()

    conn.close()


# ---------------- PACKETS ---------------- #

def insert_packet(
    protocol,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    packet_size,
    direction
):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO packet_logs (

        timestamp,
        protocol,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        packet_size,
        direction

    )

    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (

        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        packet_size,
        direction
    ))

    conn.commit()

    conn.close()


def get_recent_packets(limit=20):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(f"""
    SELECT * FROM packet_logs
    ORDER BY id DESC
    LIMIT {limit}
    """)

    rows = cursor.fetchall()

    conn.close()

    return [dict(row) for row in rows]


def get_protocol_stats():

    conn = get_connection()

    cursor = conn.cursor()

    protocols = ["TCP", "UDP", "ICMP"]

    stats = {}

    for protocol in protocols:

        cursor.execute("""
        SELECT COUNT(*) FROM packet_logs
        WHERE protocol=?
        """, (protocol,))

        stats[protocol] = cursor.fetchone()[0]

    conn.close()

    return stats


# ---------------- ALERTS ---------------- #

def insert_alert(
    alert_type,
    severity,
    source_ip,
    message
):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO alerts (

        timestamp,
        alert_type,
        severity,
        source_ip,
        message

    )

    VALUES (?, ?, ?, ?, ?)
    """, (

        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        alert_type,
        severity,
        source_ip,
        message
    ))

    conn.commit()

    conn.close()


def get_recent_alerts(limit=10):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(f"""
    SELECT * FROM alerts
    ORDER BY id DESC
    LIMIT {limit}
    """)

    rows = cursor.fetchall()

    conn.close()

    return [dict(row) for row in rows]
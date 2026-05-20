from app.database.db import insert_packet


def log_packet(
    protocol,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    packet_size,
    direction
):

    insert_packet(
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        packet_size,
        direction
    )
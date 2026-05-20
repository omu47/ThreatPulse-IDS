from app.database.db import insert_alert


def save_alert(alert_data):

    insert_alert(
        alert_data["type"],
        alert_data["severity"],
        alert_data["source_ip"],
        alert_data["message"]
    )
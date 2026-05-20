import os


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "threatpulse-secret-key")

    DDOS_THRESHOLD = int(os.getenv("DDOS_THRESHOLD", "100"))
    PORT_SCAN_THRESHOLD = int(os.getenv("PORT_SCAN_THRESHOLD", "20"))
    THREAT_WINDOW_SECONDS = int(os.getenv("THREAT_WINDOW_SECONDS", "10"))

    MAX_LOG_ROWS = int(os.getenv("MAX_LOG_ROWS", "20"))
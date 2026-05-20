BLACKLISTED_IPS = {
    "185.220.101.1": "TOR Exit Node",
    "45.95.147.100": "Known Malware Host",
    "103.21.244.0": "Suspicious Scanner",
    "192.168.1.250": "Internal Threat Simulation",
}


def check_blacklist(ip_address):
    reason = BLACKLISTED_IPS.get(ip_address)

    if reason:
        return {
            "blacklisted": True,
            "reason": reason,
            "risk_score": 95,
        }

    return {
        "blacklisted": False,
        "reason": None,
        "risk_score": 0,
    }
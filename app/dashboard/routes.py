from flask import (
    Blueprint,
    render_template,
    send_file
)

from app.database.db import (
    get_recent_packets,
    get_recent_alerts,
    get_protocol_stats
)

from app.utils.report_generator import (
    generate_security_report
)

dashboard = Blueprint(
    "dashboard",
    __name__
)


@dashboard.route("/")
def home():

    packets = get_recent_packets()

    alerts = get_recent_alerts()

    stats = get_protocol_stats()

    return render_template(

        "dashboard.html",

        packets=packets,

        alerts=alerts,

        stats=stats
    )


@dashboard.route("/download-report")
def download_report():

    report_path = generate_security_report()

    return send_file(
        report_path,
        as_attachment=True
    )
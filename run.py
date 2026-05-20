from flask import Flask
from flask_socketio import SocketIO

from app.sniffer.packet_sniffer import start_sniffer
from app.dashboard.routes import dashboard

from app.database.db import initialize_database

from config import Config

app = Flask(__name__)

app.config.from_object(Config)

socketio = SocketIO(

    app,

    async_mode="threading",

    cors_allowed_origins="*"
)

# Register Blueprint

app.register_blueprint(dashboard)


if __name__ == "__main__":

    # Initialize SQLite Database

    initialize_database()

    print("[INFO] SQLite Database Initialized")

    # Start Packet Sniffer

    socketio.start_background_task(
        start_sniffer,
        socketio
    )

    print("[INFO] ThreatPulse IDS Started")

    # Run Flask App

    socketio.run(

        app,

        debug=True,

        use_reloader=False,

        allow_unsafe_werkzeug=True
    )
import socket
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "siem.db"
HOST_ID = socket.gethostname()
DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 8082
PORT_SCAN_THRESHOLD = 5
PORT_SCAN_WINDOW_SECONDS = 30
SSH_FAILURE_THRESHOLD = 5
SSH_FAILURE_WINDOW_SECONDS = 120

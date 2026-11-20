import argparse
import socket
import sys
import threading
from pathlib import Path

import uvicorn

from app import app, engine, set_collectors
from collectors import SysmonCollector, NetworkCollector, SSHCollector
from config import DASHBOARD_HOST, DASHBOARD_PORT, HOST_ID


def find_available_port(host, preferred):
    for port in range(preferred, preferred + 20):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind((host, port))
            return port
        except OSError:
            continue
        finally:
            probe.close()
    raise RuntimeError("No available dashboard port found")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-id", default=socket.gethostname() or HOST_ID)
    parser.add_argument("--host", default=DASHBOARD_HOST)
    parser.add_argument("--port", type=int, default=DASHBOARD_PORT)
    parser.add_argument("--no-network", action="store_true")
    parser.add_argument("--no-sysmon", action="store_true")
    parser.add_argument("--no-ssh", action="store_true")
    args = parser.parse_args()
    try:
        args.port = find_available_port(args.host, args.port)
    except RuntimeError as exc:
        parser.error(str(exc))

    root = Path(__file__).resolve().parent
    sysmon = None
    network = None
    ssh = None

    if not args.no_sysmon:
        sysmon = SysmonCollector(args.host_id, engine, root)
        sysmon.start()
    if not args.no_network:
        network = NetworkCollector(args.host_id, engine)
        network.start()
    if not args.no_ssh:
        ssh = SSHCollector(args.host_id, engine)
        ssh.start()

    set_collectors(network=network, ssh=ssh, sysmon=sysmon)
    print(f"[SIEM-l] dashboard: http://{args.host}:{args.port}")
    print(f"[SIEM-l] host: {args.host_id}")
    print("[SIEM-l] press Ctrl+C to stop")
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()

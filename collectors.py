import os
import re
import socket
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from scapy.all import sniff, TCP, IP


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def base_event(host_id, collector, category, action):
    return {
        "@timestamp": utc_now(),
        "event": {
            "id": str(uuid.uuid4()),
            "category": category,
            "action": action,
            "kind": "event",
        },
        "host": {
            "id": host_id,
            "os": "windows",
            "hostname": socket.gethostname(),
        },
        "collector": collector,
    }


class SysmonCollector:
    def __init__(self, host_id, engine, root):
        self.host_id = host_id
        self.engine = engine
        self.running = False
        self.error = None
        self.bookmark = root / ".runtime" / "sysmon-record.txt"
        self.bookmark.parent.mkdir(parents=True, exist_ok=True)

    def start(self):
        thread = threading.Thread(target=self.run, daemon=True)
        thread.start()
        return thread

    def run(self):
        channel = "Microsoft-Windows-Sysmon/Operational"
        query = "*[System[(EventID=1 or EventID=3 or EventID=5 or EventID=10 or EventID=11 or EventID=13)]]"
        last = 0
        try:
            last = int(self.bookmark.read_text(encoding="ascii").strip())
        except (FileNotFoundError, ValueError):
            pass
        self.running = True
        while self.running:
            result = subprocess.run(
                ["wevtutil", "qe", channel, f"/q:{query}", "/c:64", "/rd:true", "/f:xml"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                self.error = result.stderr.strip() or "unable to read Sysmon"
                time.sleep(2)
                continue
            self.error = None
            try:
                xml_events = re.sub(r"<\?xml[^>]*\?>", "", result.stdout)
                root = ET.fromstring(f"<Events>{xml_events}</Events>")
                for event_xml in reversed(list(root)):
                    record = event_xml.find("./{*}System/{*}EventRecordID")
                    record_id = int(record.text) if record is not None and record.text else None
                    if record_id is not None and record_id <= last:
                        continue
                    fields = {
                        data.attrib.get("Name"): data.text or ""
                        for data in event_xml.findall("./{*}EventData/{*}Data")
                    }
                    event_id = event_xml.find("./{*}System/{*}EventID")
                    if event_id is not None:
                        fields["EventID"] = event_id.text or ""
                    event = self.map_event(fields)
                    if event:
                        self.engine.process(event)
                        self.engine.store.heartbeat(self.host_id, "sysmon")
                    if record_id is not None:
                        last = record_id
                        self.bookmark.write_text(str(last), encoding="ascii")
            except ET.ParseError as exc:
                self.error = str(exc)
            time.sleep(1)

    def map_event(self, fields):
        try:
            sysmon_id = int(fields.get("EventID", "0"))
        except ValueError:
            return None
        if sysmon_id not in {1, 3, 5, 10, 11, 13}:
            return None
        category = {1: "process", 3: "network", 5: "process", 10: "process_access",
                    11: "file", 13: "registry"}[sysmon_id]
        action = {1: "process_created", 3: "network_connection", 5: "process_terminated",
                  10: "process_access", 11: "file_created", 13: "registry_value_set"}[sysmon_id]
        event = base_event(self.host_id, "sysmon", category, action)
        utc = fields.get("UtcTime")
        if utc:
            try:
                event["@timestamp"] = datetime.fromisoformat(
                    utc.replace("Z", "+00:00").replace(" ", "T")
                ).astimezone(timezone.utc).isoformat()
            except ValueError:
                pass
        guid = fields.get("ProcessGuid", "")
        process_id = int(fields.get("ProcessId", "0") or 0)
        image = fields.get("Image", "")
        parent_guid = fields.get("ParentProcessGuid", "")
        parent_id = int(fields.get("ParentProcessId", "0") or 0)

        if sysmon_id in {1, 5}:
            process = {
                "pid": process_id,
                "guid": guid,
                "ppid": parent_id,
                "name": os.path.basename(image),
                "executable": image,
                "command_line": fields.get("CommandLine", image),
                "parent": {
                    "pid": parent_id,
                    "guid": parent_guid,
                    "name": os.path.basename(fields.get("ParentImage", "")),
                    "command_line": fields.get("ParentCommandLine", ""),
                },
            }
            if sysmon_id == 5:
                process["end_time"] = event["@timestamp"]
            else:
                process["start_time"] = event["@timestamp"]
            event["process"] = process
            event["user"] = {"name": fields.get("User", "")}
        elif sysmon_id == 3:
            event["source"] = {"ip": fields.get("SourceIp", "")}
            event["destination"] = {
                "ip": fields.get("DestinationIp", ""),
                "port": int(fields.get("DestinationPort", "0") or 0),
            }
            event["network"] = {
                "protocol": (fields.get("Protocol", "tcp") or "tcp").lower(),
                "direction": "outbound",
            }
            event["process"] = {"pid": process_id, "guid": guid, "name": os.path.basename(image)}
        elif sysmon_id == 10:
            event["source"] = {
                "process": {
                    "pid": process_id,
                    "guid": guid,
                    "name": os.path.basename(image),
                }
            }
            event["target"] = {
                "process": {
                    "pid": int(fields.get("TargetProcessId", "0") or 0),
                    "guid": fields.get("TargetProcessGuid", ""),
                    "name": os.path.basename(fields.get("TargetImage", "")),
                }
            }
        elif sysmon_id == 11:
            event["file"] = {"path": fields.get("TargetFilename", "")}
            event["process"] = {"pid": process_id, "guid": guid, "name": os.path.basename(image)}
        elif sysmon_id == 13:
            event["registry"] = {
                "target_object": fields.get("TargetObject", ""),
                "details": fields.get("Details", ""),
            }
            event["process"] = {"pid": process_id, "guid": guid, "name": os.path.basename(image)}
        return event


class NetworkCollector:
    def __init__(self, host_id, engine):
        self.host_id = host_id
        self.engine = engine
        self.running = False
        self.error = None

    def start(self):
        thread = threading.Thread(target=self.run, daemon=True)
        thread.start()
        return thread

    def run(self):
        self.running = True
        try:
            local_ips = {"127.0.0.1"}
            local_ips.update(get_local_ips())

            def callback(packet):
                if not packet.haslayer(TCP) or not packet.haslayer(IP):
                    return
                tcp = packet[TCP]
                ip = packet[IP]
                if tcp.flags != "S" or ip.dst not in local_ips:
                    return
                event = base_event(self.host_id, "scapy", "network", "tcp_syn")
                event["source"] = {"ip": ip.src}
                event["destination"] = {"ip": ip.dst, "port": int(tcp.dport)}
                event["network"] = {"protocol": "tcp", "direction": "inbound"}
                self.engine.process(event)
                self.engine.store.heartbeat(self.host_id, "network")

            sniff(
                iface="Software Loopback Interface 1",
                filter="tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0",
                prn=callback,
                store=False,
            )
        except Exception as exc:
            self.error = str(exc)
            self.running = False


def get_local_ips():
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except socket.gaierror:
        pass
    ips.add("127.0.0.1")
    return ips


class SSHCollector:
    def __init__(self, host_id, engine):
        self.host_id = host_id
        self.engine = engine
        self.running = False
        self.error = None

    def start(self):
        thread = threading.Thread(target=self.run, daemon=True)
        thread.start()
        return thread

    def run(self):
        self.running = True
        channels = [
            ("Security", "*[System[(EventID=4625)]]"),
            ("OpenSSH/Operational", "*[System[(EventID=4625)]]"),
            ("OpenSSH/Operational", "*"),
        ]
        seen = set()
        while self.running:
            found = False
            for channel, query in channels:
                result = subprocess.run(
                    ["wevtutil", "qe", channel, f"/q:{query}", "/c:100", "/rd:true", "/f:xml"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode != 0:
                    continue
                found = True
                try:
                    xml_events = re.sub(r"<\?xml[^>]*\?>", "", result.stdout)
                    root = ET.fromstring(f"<Events>{xml_events}</Events>")
                    for event_xml in reversed(list(root)):
                        record = event_xml.find("./{*}System/{*}EventRecordID")
                        record_id = record.text if record is not None else None
                        if not record_id or record_id in seen:
                            continue
                        seen.add(record_id)
                        fields = {
                            data.attrib.get("Name"): data.text or ""
                            for data in event_xml.findall("./{*}EventData/{*}Data")
                        }
                        text = " ".join(fields.values()).lower()
                        if "failed password" not in text and "authentication failure" not in text:
                            continue
                        source_ip = fields.get("IpAddress") or fields.get("SourceAddress")
                        account = fields.get("TargetUserName") or fields.get("AccountName")
                        event = base_event(self.host_id, "openssh", "authentication", "ssh_password_failed")
                        event["source"] = {"ip": source_ip or "unknown"}
                        event["account"] = account or "unknown"
                        self.engine.process(event)
                        self.engine.store.heartbeat(self.host_id, "openssh")
                except ET.ParseError:
                    pass
            if not found:
                self.error = "OpenSSH Operational log unavailable"
            else:
                self.error = None
            if len(seen) > 500:
                seen = set(list(seen)[-250:])
            time.sleep(2)

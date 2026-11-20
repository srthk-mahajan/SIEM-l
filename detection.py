import threading
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from config import (
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_WINDOW_SECONDS,
    SSH_FAILURE_THRESHOLD,
    SSH_FAILURE_WINDOW_SECONDS,
)
from store import utc_now


def parse_timestamp(value):
    if not value:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class DetectionEngine:
    def __init__(self, store, alerts_callback=None):
        self.store = store
        self.alerts_callback = alerts_callback
        self.lock = threading.Lock()
        self.port_probes = defaultdict(deque)
        self.ssh_failures = defaultdict(deque)
        self.alert_fingerprints = {}

    def process(self, event):
        event_id = self.store.add_event(event)
        timestamp = parse_timestamp(event.get("@timestamp"))
        category = event.get("event", {}).get("category")
        action = event.get("event", {}).get("action")
        source_ip = event.get("source", {}).get("ip")

        with self.lock:
            if category == "network" and action in {"tcp_syn", "network_connection"}:
                self._detect_port_scan(event, source_ip, timestamp)
            if category == "authentication" and action in {"logon_failed", "ssh_password_failed"}:
                self._detect_ssh_brute_force(event, source_ip, timestamp)
            if category == "process":
                self._detect_office_shell(event)
            if category == "registry":
                self._detect_registry_persistence(event)
            if category == "process_access":
                self._detect_lsass_access(event)

        return event_id

    def _emit(self, rule_id, rule_name, severity, mitre, host_id, description, source_event_ids,
              source_ip=None, account=None):
        fingerprint = (rule_id, host_id, source_ip, account)
        now = datetime.now(timezone.utc)
        previous = self.alert_fingerprints.get(fingerprint)
        if previous and now - previous["time"] < timedelta(seconds=60):
            previous["count"] += 1
            previous["source_event_ids"] = list(dict.fromkeys(
                previous["source_event_ids"] + source_event_ids
            ))
            if self.alerts_callback:
                self.alerts_callback(previous)
            return previous

        alert = {
            "id": str(uuid.uuid4()),
            "timestamp": utc_now(),
            "rule_id": rule_id,
            "rule_name": rule_name,
            "severity": severity,
            "mitre": mitre,
            "host_id": host_id,
            "source_ip": source_ip,
            "account": account,
            "description": description,
            "source_event_ids": list(dict.fromkeys(source_event_ids)),
            "count": 1,
        }
        self.store.add_alert(alert)
        self.alert_fingerprints[fingerprint] = {"time": now, "count": 1, "source_event_ids": source_event_ids}
        if self.alerts_callback:
            self.alerts_callback(alert)
        return alert

    def _detect_port_scan(self, event, source_ip, timestamp):
        if not source_ip:
            return
        port = event.get("destination", {}).get("port")
        if not isinstance(port, int):
            return
        probes = self.port_probes[source_ip]
        probes.append((timestamp, port))
        cutoff = timestamp - timedelta(seconds=PORT_SCAN_WINDOW_SECONDS)
        while probes and probes[0][0] < cutoff:
            probes.popleft()
        ports = {item[1] for item in probes}
        if len(ports) >= PORT_SCAN_THRESHOLD:
            event_id = event["event"]["id"]
            self._emit(
                "WIN-NET-001",
                "Inbound or Local Port Scan",
                "high",
                "T1046",
                event["host"]["id"],
                f"{len(ports)} distinct destination ports observed within {PORT_SCAN_WINDOW_SECONDS} seconds.",
                [event_id],
                source_ip=source_ip,
            )
            probes.clear()

    def _detect_ssh_brute_force(self, event, source_ip, timestamp):
        source_ip = source_ip or event.get("source", {}).get("ip") or "unknown"
        account = event.get("account")
        failures = self.ssh_failures[(source_ip, account)]
        failures.append(timestamp)
        cutoff = timestamp - timedelta(seconds=SSH_FAILURE_WINDOW_SECONDS)
        while failures and failures[0] < cutoff:
            failures.popleft()
        if len(failures) >= SSH_FAILURE_THRESHOLD:
            event_id = event["event"]["id"]
            self._emit(
                "WIN-AUTH-001",
                "SSH Brute Force",
                "critical",
                "T1110",
                event["host"]["id"],
                f"{len(failures)} failed SSH authentications from {source_ip} for account {account or 'unknown'}.",
                [event_id],
                source_ip=source_ip,
                account=account,
            )
            failures.clear()

    def _detect_office_shell(self, event):
        process = event.get("process", {})
        name = (process.get("name") or "").lower()
        parent = process.get("parent", {}).get("name", "").lower()
        if parent in {"winword.exe", "excel.exe", "powerpnt.exe"} and name in {"cmd.exe", "powershell.exe", "pwsh.exe"}:
            self._emit(
                "WIN-PROC-001",
                "Office Application Spawned Shell",
                "high",
                "T1204.002",
                event["host"]["id"],
                f"{process.get('parent', {}).get('name')} spawned {process.get('name')}.",
                [event["event"]["id"]],
                account=event.get("user", {}).get("name"),
            )

    def _detect_registry_persistence(self, event):
        target = event.get("registry", {}).get("target_object", "")
        if "CurrentVersion\\Run" in target or "CurrentVersion\\RunOnce" in target:
            self._emit(
                "WIN-PERS-001",
                "Registry Run Key Persistence",
                "high",
                "T1547.001",
                event["host"]["id"],
                f"Registry persistence value set at {target}.",
                [event["event"]["id"]],
            )

    def _detect_lsass_access(self, event):
        source = event.get("source", {}).get("process", {}).get("name", "").lower()
        target = event.get("target", {}).get("process", {}).get("name", "").lower()
        if "lsass" in target and source not in {"", "svchost.exe", "services.exe", "lsass.exe"}:
            self._emit(
                "WIN-CRED-001",
                "Process Accessed LSASS",
                "critical",
                "T1003.001",
                event["host"]["id"],
                f"{source or 'Unknown process'} accessed {target}.",
                [event["event"]["id"]],
            )

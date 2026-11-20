from config import PORT_SCAN_THRESHOLD
from detection import DetectionEngine
from store import Store


class TemporaryStore(Store):
    def __init__(self, path):
        super().__init__(path)


def event(category, action, source_ip=None, destination_port=None, account=None):
    result = {
        "@timestamp": "2026-11-21T02:30:00Z",
        "event": {"id": "11111111-1111-4111-8111-111111111111", "category": category, "action": action},
        "host": {"id": "localhost"},
        "collector": "test",
    }
    if source_ip:
        result["source"] = {"ip": source_ip}
    if destination_port:
        result["destination"] = {"ip": "127.0.0.1", "port": destination_port}
    if account:
        result["account"] = account
    return result


def test_port_scan_threshold(tmp_path):
    engine = DetectionEngine(TemporaryStore(tmp_path / "test.db"))
    for port in range(PORT_SCAN_THRESHOLD):
        engine.process(event("network", "tcp_syn", "192.168.1.20", 1000 + port))
    alerts = engine.store.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "Inbound or Local Port Scan"


def test_ssh_brute_force_threshold(tmp_path):
    engine = DetectionEngine(TemporaryStore(tmp_path / "test.db"))
    for _ in range(5):
        engine.process(event("authentication", "ssh_password_failed", "192.168.1.21", account="invalid"))
    alerts = engine.store.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "SSH Brute Force"


def test_office_shell_rule(tmp_path):
    engine = DetectionEngine(TemporaryStore(tmp_path / "test.db"))
    sample = event("process", "process_created")
    sample["process"] = {
        "pid": 123,
        "name": "powershell.exe",
        "parent": {"pid": 100, "name": "WINWORD.EXE"},
    }
    sample["user"] = {"name": "LAB\\Analyst"}
    engine.process(sample)
    alerts = engine.store.get_alerts()
    assert len(alerts) == 1
    assert alerts[0]["mitre"] == "T1204.002"

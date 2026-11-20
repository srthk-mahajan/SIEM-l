import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from config import DB_PATH, HOST_ID
from store import Store
from detection import DetectionEngine
from threat_intel import refresh_abuseipdb

ROOT = Path(__file__).resolve().parent
store = Store(DB_PATH)
engine = DetectionEngine(store)
app = FastAPI(title="SIEM-l", version="1.0")
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")

collectors = {}


def set_collectors(network=None, ssh=None, sysmon=None):
    collectors.update({"network": network, "ssh": ssh, "sysmon": sysmon})


@app.get("/")
def index():
    return FileResponse(str(ROOT / "static" / "index.html"))


@app.get("/api/status")
def status():
    host = store.get_host_status(HOST_ID)
    alerts = store.get_alerts(500)
    collector_status = {}
    for name, collector in collectors.items():
        if collector is None:
            collector_status[name] = {"status": "not_started", "error": None}
        else:
            collector_status[name] = {
                "status": "running" if collector.running else "stopped",
                "error": collector.error,
            }
    return {
        "server_time": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "collectors": collector_status,
        "alerts": len(alerts),
        "database": str(DB_PATH),
    }


@app.get("/api/alerts")
def alerts(limit: int = 100):
    limit = max(1, min(limit, 500))
    result = []
    for alert in store.get_alerts(limit):
        alert["source_event_ids"] = json.loads(alert["source_event_ids"])
        result.append(alert)
    return result


@app.get("/api/events")
def events(limit: int = 100):
    return store.get_events(max(1, min(limit, 500)))


@app.post("/api/threat-intel/refresh")
def refresh_threat_intel():
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    try:
        refresh_abuseipdb(DB_PATH, api_key)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "refreshed"}


@app.get("/api/graph/{alert_id}")
def alert_graph(alert_id: str):
    alert = store.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="alert not found")
    source_ids = json.loads(alert["source_event_ids"])
    source_events = store.get_source_events(source_ids)
    nodes = []
    edges = []
    node_ids = set()

    def add_node(node_id, label, kind, details, alert_node=False):
        if node_id not in node_ids:
            node_ids.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "kind": kind,
                "details": details,
                "alert": alert_node,
            })

    host_id = alert["host_id"]
    add_node(f"host:{host_id}", host_id, "host", {"host_id": host_id})
    add_node(f"alert:{alert_id}", alert["rule_name"], "alert", {
        "severity": alert["severity"],
        "mitre": alert["mitre"],
        "description": alert["description"],
        "source_event_ids": source_ids,
    }, True)
    edges.append({"from": f"alert:{alert_id}", "to": f"host:{host_id}", "label": "detected on"})

    if alert.get("source_ip"):
        ip_id = f"ip:{alert['source_ip']}"
        add_node(ip_id, alert["source_ip"], "ip", {"ip": alert["source_ip"]})
        edges.append({"from": ip_id, "to": f"host:{host_id}", "label": "contacted"})

    if alert.get("account"):
        account_id = f"account:{alert['account']}"
        add_node(account_id, alert["account"], "account", {"account": alert["account"]})
        edges.append({"from": account_id, "to": f"host:{host_id}", "label": "authentication attempted"})

    for event in source_events:
        event_id = event["event"]["id"]
        category = event["event"]["category"]
        action = event["event"]["action"]
        event_node_id = f"event:{event_id}"
        add_node(event_node_id, action, "event", {
            "event_id": event_id,
            "timestamp": event["@timestamp"],
            "category": category,
            "action": action,
        })
        edges.append({"from": f"alert:{alert_id}", "to": event_node_id, "label": "source evidence"})

        source_ip = event.get("source", {}).get("ip")
        if source_ip:
            ip_id = f"ip:{source_ip}"
            add_node(ip_id, source_ip, "ip", {"ip": source_ip})
            edges.append({"from": ip_id, "to": event_node_id, "label": "source"})

        destination = event.get("destination", {})
        if destination:
            destination_id = f"endpoint:{destination.get('ip')}:{destination.get('port')}"
            add_node(destination_id, f"{destination.get('ip')}:{destination.get('port')}", "endpoint", destination)
            edges.append({"from": event_node_id, "to": destination_id, "label": "connected to"})

        process = event.get("process", {})
        if process:
            process_id = process.get("guid") or f"pid:{process.get('pid')}:{event['@timestamp']}"
            process_node_id = f"process:{process_id}"
            add_node(process_node_id, process.get("name") or "process", "process", {
                "pid": process.get("pid"),
                "guid": process.get("guid"),
                "name": process.get("name"),
                "executable": process.get("executable"),
                "command_line": process.get("command_line"),
                "start_time": process.get("start_time"),
            })
            edges.append({"from": process_node_id, "to": event_node_id, "label": "observed in"})

            parent = process.get("parent", {})
            if parent and parent.get("name"):
                parent_node_id = f"process:{parent.get('guid') or 'parent:' + str(parent.get('pid'))}"
                add_node(parent_node_id, parent["name"], "process", parent)
                edges.append({"from": parent_node_id, "to": process_node_id, "label": "spawned"})

        account = event.get("account")
        if account:
            account_id = f"account:{account}"
            add_node(account_id, account, "account", {"account": account})
            edges.append({"from": account_id, "to": event_node_id, "label": "user activity"})

        registry = event.get("registry")
        if registry:
            target = registry.get("target_object") or "registry"
            registry_id = f"registry:{target}"
            add_node(registry_id, target, "registry", registry)
            edges.append({"from": event_node_id, "to": registry_id, "label": "modified"})

        file_data = event.get("file")
        if file_data:
            path = file_data.get("path") or "file"
            file_id = f"file:{path}"
            add_node(file_id, path, "file", file_data)
            edges.append({"from": event_node_id, "to": file_id, "label": "created"})

    return {"nodes": nodes, "edges": edges}


class CreateCaseRequest(BaseModel):
    title: str
    severity: str = "medium"
    host_id: str = HOST_ID
    alert_ids: list[str] = Field(default_factory=list)


class AddNoteRequest(BaseModel):
    author: str
    content: str


@app.post("/api/cases")
def create_case(request: CreateCaseRequest):
    return store.create_case(request.title, request.severity, request.host_id, request.alert_ids)


@app.get("/api/cases/{case_id}")
def get_case(case_id: str):
    case = store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case not found")
    return case


@app.post("/api/cases/{case_id}/notes")
def add_note(case_id: str, request: AddNoteRequest):
    if not store.get_case(case_id):
        raise HTTPException(status_code=404, detail="case not found")
    return store.add_case_note(case_id, request.author, request.content)


@app.post("/api/cases/{case_id}/report")
def report(case_id: str):
    case = store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case not found")
    alerts = []
    evidence = []
    for alert_id in case["alert_ids"]:
        alert = store.get_alert(alert_id)
        if not alert:
            continue
        alerts.append(alert)
        evidence.extend(store.get_source_events(json.loads(alert["source_event_ids"])))
    report_dir = ROOT / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"{case_id}.md"
    lines = [
        f"# Incident Report: {case['title']}",
        "",
        f"- **Case ID:** {case['id']}",
        f"- **Status:** {case['status']}",
        f"- **Severity:** {case['severity']}",
        f"- **Host:** {case['host_id']}",
        f"- **Created:** {case['created_at']}",
        "",
        "## Alerts",
        "",
    ]
    for alert in alerts:
        lines.extend([
            f"### {alert['rule_name']} ({alert['severity']})",
            f"- MITRE: {alert['mitre']}",
            f"- Description: {alert['description']}",
            f"- Source IP: {alert.get('source_ip') or 'none'}",
            f"- Event IDs: {', '.join(json.loads(alert['source_event_ids']))}",
            "",
        ])
    lines.extend(["## Evidence", ""])
    for event in evidence:
        lines.extend(["```json", json.dumps(event, indent=2, ensure_ascii=False), "```", ""])
    lines.extend(["## Analyst Notes", ""])
    for note in case["notes"]:
        lines.append(f"- **{note['author']}** ({note['created_at']}): {note['content']}")
    lines.extend([
        "",
        "## Remediation",
        "",
        "Contain the affected host, preserve evidence, rotate exposed credentials, "
        "remove persistence, and monitor for recurrence.",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")
    return {"path": str(path)}

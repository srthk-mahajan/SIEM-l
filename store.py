import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: Path):
        self.path = str(path)
        self.lock = threading.Lock()
        self.init_db()

    def connect(self):
        connection = sqlite3.connect(self.path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def init_db(self):
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    collector TEXT NOT NULL,
                    category TEXT NOT NULL,
                    action TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    process_guid TEXT,
                    pid INTEGER,
                    process_name TEXT,
                    parent_guid TEXT,
                    parent_pid INTEGER,
                    user_name TEXT,
                    account TEXT,
                    data TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    mitre TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    source_ip TEXT,
                    account TEXT,
                    description TEXT NOT NULL,
                    source_event_ids TEXT NOT NULL,
                    count INTEGER NOT NULL,
                    case_id TEXT
                );
                CREATE TABLE IF NOT EXISTS heartbeat (
                    host_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    collector TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    host_id TEXT,
                    alert_ids TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS case_notes (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    author TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ioc_cache (
                    ip TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    confidence INTEGER NOT NULL,
                    refreshed_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
                CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
                """
            )

    def heartbeat(self, host_id, collector):
        timestamp = utc_now()
        with self.lock, self.connect() as db:
            db.execute(
                "INSERT INTO heartbeat(host_id,timestamp,collector) VALUES(?,?,?) "
                "ON CONFLICT(host_id) DO UPDATE SET timestamp=excluded.timestamp,collector=excluded.collector",
                (host_id, timestamp, collector),
            )
        return timestamp

    def add_event(self, event):
        event_id = event.get("event", {}).get("id") or str(uuid.uuid4())
        event.setdefault("event", {})["id"] = event_id
        event.setdefault("@timestamp", utc_now())
        process = event.get("process", {})
        parent = process.get("parent", {})
        source_ip = event.get("source", {}).get("ip")
        destination = event.get("destination", {})
        row = (
            event_id,
            event["@timestamp"],
            event.get("host", {}).get("id", "localhost"),
            event.get("collector", "unknown"),
            event.get("event", {}).get("category", "unknown"),
            event.get("event", {}).get("action", "unknown"),
            source_ip,
            destination.get("ip"),
            destination.get("port"),
            process.get("guid"),
            process.get("pid"),
            process.get("name"),
            parent.get("guid"),
            parent.get("pid"),
            event.get("user", {}).get("name"),
            event.get("account"),
            json.dumps(event, ensure_ascii=False),
        )
        with self.lock, self.connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO events("
                "id,timestamp,host_id,collector,category,action,source_ip,destination_ip,"
                "destination_port,process_guid,pid,process_name,parent_guid,parent_pid,"
                "user_name,account,data) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                row,
            )
        return event_id

    def add_alert(self, alert):
        alert_id = alert["id"]
        with self.lock, self.connect() as db:
            db.execute(
                "INSERT INTO alerts(id,timestamp,rule_id,rule_name,severity,mitre,host_id,"
                "source_ip,account,description,source_event_ids,count) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    alert_id,
                    alert["timestamp"],
                    alert["rule_id"],
                    alert["rule_name"],
                    alert["severity"],
                    alert["mitre"],
                    alert["host_id"],
                    alert.get("source_ip"),
                    alert.get("account"),
                    alert["description"],
                    json.dumps(alert["source_event_ids"]),
                    alert["count"],
                ),
            )
        return alert_id

    def get_alerts(self, limit=100):
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def get_events(self, limit=500):
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        alerts = []
        for row in rows:
            item = dict(row)
            item["data"] = json.loads(item["data"])
            alerts.append(item)
        return alerts

    def get_host_status(self, host_id):
        with self.connect() as db:
            row = db.execute(
                "SELECT timestamp,collector FROM heartbeat WHERE host_id=?", (host_id,)
            ).fetchone()
            if not row:
                row = db.execute(
                    "SELECT host_id,timestamp,collector FROM heartbeat "
                    "ORDER BY timestamp DESC LIMIT 1"
                ).fetchone()
                if row:
                    host_id = row["host_id"]
        if not row:
            return {"host_id": host_id, "status": "unknown", "last_seen": None, "collector": None}
        now = datetime.now(timezone.utc)
        last = parse_store_timestamp(row["timestamp"])
        status = "online" if now - last <= timedelta(minutes=5) else "offline"
        return {
            "host_id": host_id,
            "status": status,
            "last_seen": row["timestamp"],
            "collector": row["collector"],
        }

    def create_case(self, title, severity, host_id, alert_ids):
        now = utc_now()
        case_id = str(uuid.uuid4())
        with self.lock, self.connect() as db:
            db.execute(
                "INSERT INTO cases(id,title,status,severity,host_id,alert_ids,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (case_id, title, "new", severity, host_id, json.dumps(alert_ids), now, now),
            )
            for alert_id in alert_ids:
                db.execute("UPDATE alerts SET case_id=? WHERE id=?", (case_id, alert_id))
        return self.get_case(case_id)

    def get_case(self, case_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if not row:
                return None
            notes = db.execute(
                "SELECT * FROM case_notes WHERE case_id=? ORDER BY created_at",
                (case_id,),
            ).fetchall()
        result = dict(row)
        result["alert_ids"] = json.loads(result["alert_ids"])
        result["notes"] = [dict(note) for note in notes]
        return result

    def add_case_note(self, case_id, author, content):
        note_id = str(uuid.uuid4())
        now = utc_now()
        with self.lock, self.connect() as db:
            db.execute(
                "INSERT INTO case_notes(id,case_id,author,content,created_at) VALUES(?,?,?,?,?)",
                (note_id, case_id, author, content, now),
            )
            db.execute("UPDATE cases SET updated_at=? WHERE id=?", (now, case_id))
        return {"id": note_id, "case_id": case_id, "author": author, "content": content, "created_at": now}

    def get_alert(self, alert_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return dict(row) if row else None

    def get_source_events(self, event_ids):
        if not event_ids:
            return []
        placeholders = ",".join("?" for _ in event_ids)
        with self.connect() as db:
            rows = db.execute(
                f"SELECT * FROM events WHERE id IN ({placeholders})",
                event_ids,
            ).fetchall()
        return [json.loads(row["data"]) for row in rows]


def parse_store_timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed

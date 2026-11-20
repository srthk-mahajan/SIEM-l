import sqlite3
from datetime import datetime, timezone

import json
import urllib.parse
import urllib.request


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def lookup_ip(db_path, ip):
    with sqlite3.connect(db_path) as db:
        row = db.execute(
            "SELECT source,confidence,refreshed_at FROM ioc_cache WHERE ip=?",
            (ip,),
        ).fetchone()
    if not row:
        return None
    return {"source": row[0], "confidence": row[1], "refreshed_at": row[2]}


def refresh_abuseipdb(db_path, api_key):
    if not api_key:
        raise RuntimeError("ABUSEIPDB_API_KEY is required")
    params = urllib.parse.urlencode({"confidenceMinimum": 90, "limit": 10000})
    request = urllib.request.Request(
        "https://api.abuseipdb.com/api/v2/blacklist?" + params,
        headers={"Key": api_key, "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    now = utc_now()
    with sqlite3.connect(db_path) as db:
        for item in payload.get("data", []):
            ip = item.get("ipAddress")
            if ip:
                db.execute(
                    "INSERT INTO ioc_cache(ip,source,confidence,refreshed_at) VALUES(?,?,?,?) "
                    "ON CONFLICT(ip) DO UPDATE SET source=excluded.source,"
                    "confidence=excluded.confidence,refreshed_at=excluded.refreshed_at",
                    (ip, "abuseipdb", int(item.get("abuseConfidenceScore", 0)), now),
                )

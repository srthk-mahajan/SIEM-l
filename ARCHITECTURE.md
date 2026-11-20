# Fresh SIEM-l architecture

## Runtime

```text
main.py
  ├── SQLite event and alert storage
  ├── In-memory detection engine
  ├── Sysmon Event Log collector
  ├── Scapy loopback/network collector
  ├── OpenSSH/Security log collector
  ├── Threat-intelligence SQLite cache
  ├── FastAPI dashboard
  └── Local SVG incident graph
```

There is intentionally no Redis or Elasticsearch in the fresh implementation.

## Startup

Run as Administrator:

```powershell
python main.py
```

Open:

```text
http://127.0.0.1:8082
```

Non-privileged collectors are reported as unavailable; the dashboard never
creates fake host or alert state.

## Detection

The in-memory engine currently detects:

- Port scanning.
- SSH brute force.
- Office application spawning a shell.
- Registry Run-key persistence.
- LSASS process access.

MITRE technique IDs are attached directly to the alert.

## Demo scripts

Real loopback port scan:

```powershell
powershell -ExecutionPolicy Bypass -File .\attacks\port_scan.ps1
```

Real SSH failures:

```powershell
powershell -ExecutionPolicy Bypass -File .\attacks\ssh_failures.ps1
```

Safe Office/shell relationship demo:

```powershell
powershell -ExecutionPolicy Bypass -File .\attacks\office_shell.ps1
```

The Office demo does not embed or execute a macro.

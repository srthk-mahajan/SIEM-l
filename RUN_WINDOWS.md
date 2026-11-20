# Run SIEM-l on Windows

This runbook is for the fresh project only:

```text
C:\Users\saart\Desktop\SIEM-l
```

The old implementation is preserved outside the active project at:

```text
C:\Users\saart\Desktop\bygones\soc-siem
```

Do not run or copy the old `soc-siem` files as part of normal startup.

## Files used at runtime

| File | Purpose |
|---|---|
| `main.py` | Single application entry point; starts the dashboard and collectors |
| `app.py` | FastAPI dashboard and REST API |
| `store.py` | SQLite event, alert, heartbeat, and case storage |
| `detection.py` | Port scan, SSH, Office/shell, registry, and LSASS detections |
| `collectors.py` | Sysmon, Scapy, OpenSSH, and Security log collectors |
| `threat_intel.py` | Optional local SQLite AbuseIPDB refresh |
| `static/index.html` | Dashboard HTML |
| `static/app.js` | Live alert, event, status, and SVG graph UI |
| `static/style.css` | Dashboard styling |
| `attacks/port_scan.ps1` | Real localhost TCP scan demo |
| `attacks/ssh_failures.ps1` | Real SSH failure demo |
| `attacks/office_shell.ps1` | Safe visible Office/shell relationship demo |

There is no Redis, Elasticsearch, Docker, or `.env` requirement for the fresh
MVP.

## Terminal choice

Use PowerShell for the normal setup and run commands. PowerShell is strongly
recommended because the application and demo scripts use PowerShell and
Windows paths.

The project can also be run from Command Prompt, but activation and scripts
must use CMD syntax. If a terminal is not an elevated PowerShell terminal,
some collectors and demo scripts may report permissions or unavailable logs.

## 1. Open PowerShell

Open a normal PowerShell in the project:

```powershell
Set-Location C:\Users\saart\Desktop\SIEM-l
```

## 2. Create or reuse a virtual environment

The project does not need a separate virtual environment if the existing
environment already has FastAPI, Scapy, pywin32, and pytest.

Option A - reuse the existing project environment:

```powershell
C:\Users\saart\Desktop\soc-siem\.venv\Scripts\python.exe -m pip install -r .\requirements.txt
```

Option B - create a dedicated environment:

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
& .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Do not recreate `.venv` while SIEM-l or another Python worker is running.

## 3. Start the complete project

Open PowerShell as Administrator:

```powershell
Set-Location C:\Users\saart\Desktop\SIEM-l
& C:\Users\saart\Desktop\soc-siem\.venv\Scripts\python.exe .\main.py --host-id $env:COMPUTERNAME
```

If you created `SIEM-l\.venv`, use:

```powershell
Set-Location C:\Users\saart\Desktop\SIEM-l
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
& .\.venv\Scripts\Activate.ps1
python .\main.py --host-id $env:COMPUTERNAME
```

Default URL:

```text
http://127.0.0.1:8082
```

If port `8082` is already occupied, `main.py` searches the next 19 ports and
prints the actual URL. The terminal print is authoritative.

Do not stop an elevated dashboard by process name. Find the port owner:

```powershell
Get-NetTCPConnection -LocalPort 8082 -State Listen |
  Select-Object LocalPort,OwningProcess
```

Stop it only by exact PID:

```powershell
Stop-Process -Id <PID> -Force
```

Keep this terminal running.

The startup reports:

- Dashboard URL.
- Sysmon collector state.
- Scapy/network collector state.
- OpenSSH/Security collector state.
- SQLite database location.

## 4. Start without privileged collectors

Normal PowerShell can start the dashboard and report unavailable collectors:

```powershell
Set-Location C:\Users\saart\Desktop\SIEM-l
C:\Users\saart\Desktop\soc-siem\.venv\Scripts\python.exe .\main.py `
  --no-sysmon `
  --no-network `
  --no-ssh `
  --host-id $env:COMPUTERNAME
```

Do not use this mode for real detection. It is useful for UI/API development.

## 5. Run the real port-scan demo

In a normal or elevated PowerShell:

```powershell
Set-Location C:\Users\saart\Desktop\SIEM-l
powershell -NoProfile -ExecutionPolicy Bypass -File .\attacks\port_scan.ps1
```

It generates real loopback connections across several ports.

Wait 5-10 seconds, then open:

```text
http://127.0.0.1:8082
```

The alert should show:

- Rule: `Inbound or Local Port Scan`
- Severity: `high`
- Source: `127.0.0.1`
- MITRE: `T1046`

## 6. Run the SSH failure demo

Requires an SSH client and a real SSH service. Open PowerShell:

```powershell
Get-Command ssh.exe
```

Run:

```powershell
Set-Location C:\Users\saart\Desktop\SIEM-l
powershell -NoProfile -ExecutionPolicy Bypass -File `
  .\attacks\ssh_failures.ps1 `
  -Target 127.0.0.1 `
  -Account siem_demo_invalid `
  -Attempts 6
```

The detection activates after the configured failure threshold.

## 7. Run the Office/shell demo

Requires Microsoft Office/Word and Sysmon:

```powershell
Set-Location C:\Users\saart\Desktop\SIEM-l
powershell -NoProfile -ExecutionPolicy Bypass -File .\attacks\office_shell.ps1
```

This demo is not a macro. It opens Word and launches a visible `cmd.exe`
command in a way that gives Word the real parent-process relationship.
The generated relationship is rule-driven from real Sysmon events.

## 8. Use the dashboard

Open:

```text
http://127.0.0.1:8082
```

Tabs:

- **Overview**: host, collector health, and recent alerts.
- **Alerts**: live alerts from SQLite.
- **Timeline**: real events, newest first.
- **Investigation**: click an alert to render the bounded SVG evidence graph.

Click a graph node to inspect:

- Event ID.
- Timestamp.
- PID/ProcessGuid.
- Command line.
- IP.
- Endpoint.
- Registry target.
- File path.

No host or alert is synthesized at startup.

## 9. Create a case

In PowerShell:

```powershell
$alert = Invoke-RestMethod "http://127.0.0.1:8082/api/alerts?limit=1"

$body = @{
  title = "Live scan investigation"
  severity = "high"
  host_id = $alert[0].host_id
  alert_ids = @($alert[0].id)
} | ConvertTo-Json -Compress

Invoke-RestMethod `
  "http://127.0.0.1:8082/api/cases" `
  -Method Post `
  -ContentType "application/json" `
  -Body $body
```

## 10. Add a note

Replace `<CASE_ID>`:

```powershell
$body = @{
  author = "Analyst"
  content = "Live source event reviewed."
} | ConvertTo-Json -Compress

Invoke-RestMethod `
  "http://127.0.0.1:8082/api/cases/<CASE_ID>/notes" `
  -Method Post `
  -ContentType "application/json" `
  -Body $body
```

## 11. Generate a Markdown report

```powershell
Invoke-RestMethod `
  "http://127.0.0.1:8082/api/cases/<CASE_ID>/report" `
  -Method Post
```

Reports are written under:

```text
C:\Users\saart\Desktop\SIEM-l\reports\
```

## 12. Optional threat-intelligence refresh

Set a temporary AbuseIPDB key for the current PowerShell process:

```powershell
$env:ABUSEIPDB_API_KEY = "replace-with-key"
```

Restart `main.py` after setting the environment variable.

Use the dashboard `Refresh local IP cache` button or call:

```powershell
Invoke-RestMethod `
  "http://127.0.0.1:8082/api/threat-intel/refresh" `
  -Method Post
```

The application makes no threat-intelligence API call during normal event
ingestion. It only reads the local SQLite cache.

## 13. Run automated tests

PowerShell:

```powershell
Set-Location C:\Users\saart\Desktop\SIEM-l
C:\Users\saart\Desktop\soc-siem\.venv\Scripts\python.exe -m pytest -q
```

Dedicated environment:

```powershell
python -m pytest -q
```

## 14. Stop the project

Press `Ctrl+C` in the elevated terminal running `main.py`.

Stop an elevated process by exact PID only:

```powershell
Stop-Process -Id <PID> -Force
```

Do not use Docker for the fresh project.

## 15. CMD alternatives

CMD can start the project, but PowerShell is preferred for setup and demos.

Start with the existing environment:

```cmd
cd /d C:\Users\saart\Desktop\SIEM-l
C:\Users\saart\Desktop\soc-siem\.venv\Scripts\python.exe main.py
```

Run tests:

```cmd
cd /d C:\Users\saart\Desktop\SIEM-l
C:\Users\saart\Desktop\soc-siem\.venv\Scripts\python.exe -m pytest -q
```

Run a demo from CMD:

```cmd
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\saart\Desktop\SIEM-l\attacks\port_scan.ps1
```

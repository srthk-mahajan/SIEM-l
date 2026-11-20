# SIEM-l

A fresh, Windows-localhost SOC lab with direct local collectors and SQLite
persistence. It does not use Redis or Elasticsearch.

Start from an Administrator PowerShell:

```powershell
python main.py
```

Open `http://127.0.0.1:8082`.

The dashboard does not invent hosts or alerts. It stays empty until real
Sysmon, network, or SSH events arrive.

See `ARCHITECTURE.md` for the runtime design and `GRAPH_COMPARISON.md` for
the graph implementation and alternatives.

Run tests:

```powershell
python -m pytest -q
```

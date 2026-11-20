# Graph implementation comparison

## GroupNumber_6 implementation

The referenced project uses:

- NetworkX for the directed graph.
- Deterministic resource nodes and edges.
- Plotly for interactive browser rendering.
- Streamlit for the host dashboard.

Its graph is appropriate for cloud configuration findings because it builds
known relationship types such as:

```text
internet -> public EC2
security group -> EC2
instance role -> S3/RDS
```

It also calculates attack paths with NetworkX shortest/simple paths and marks
chained findings.

## Current SIEM-l implementation

SIEM-l uses:

- A server-side evidence graph contract.
- SQLite source-event lookup.
- Plain JavaScript plus local SVG for rendering.
- No CDN graph library.
- No browser download or package CDN dependency.
- No full 24-hour process graph.

The backend adds nodes only for evidence observed in the selected alert:

- Host
- Alert
- IP
- Account
- Event
- Endpoint
- Process
- Registry object
- File

Every edge is labeled with its evidence relationship. Clicking a node returns
the underlying event or process fields.

## Alternatives considered

| Option | Benefits | Why selected or not |
|---|---|---|
| Local SVG | Offline, no CDN, small, direct node detail | Selected |
| NetworkX server graph | Mature graph algorithms and directed edges | Available conceptually; not needed for a 20-node incident graph |
| Plotly | Polished hover and layout | Rejected for FastAPI MVP because it adds a heavyweight package/UI dependency |
| Vis-network | Interactive nodes and edges | Rejected as initial choice due previous CDN and noise issues |
| Cytoscape.js | Excellent graph interactions and layouts | Good future upgrade if the graph grows beyond 100 nodes |
| Sigma.js | High-performance graph rendering | Too heavy for a one-host incident graph |
| D3.js | Flexible custom visualization | Useful later, but higher code and layout maintenance |
| React Flow | Strong node editors and node details | Overbuilt for FastAPI and incident read-only UI |

## Incident layout rule

The graph must remain alert-centric. It is not a 24-hour process inventory.

The first implementation supports up to 20 nodes per alert. Future growth should
be implemented with a node limit and explicit expansion, not an automatic host
history dump.

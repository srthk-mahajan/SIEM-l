const state = { alertId: null, graph: null };

function esc(value) {
  const span = document.createElement("span");
  span.textContent = value == null ? "" : String(value);
  return span.innerHTML;
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

function activateView(name) {
  document.querySelectorAll(".view").forEach(v => v.classList.remove("view-active"));
  document.querySelectorAll("nav button").forEach(b => b.classList.remove("nav-active"));
  document.getElementById(name).classList.add("view-active");
  document.querySelector(`[data-view="${name}"]`).classList.add("nav-active");
  if (name === "investigation") {
    if (state.alertId) {
      loadGraph(state.alertId);
    } else {
      api("/api/alerts?limit=1").then(alerts => {
        if (alerts.length) {
          state.alertId = alerts[0].id;
          loadGraph(state.alertId);
        }
      }).catch(console.error);
    }
  }
}

async function refreshStatus() {
  const status = await api("/api/status");
  const hostStatus = document.getElementById("host-status");
  hostStatus.textContent = status.host.status === "online"
    ? `Host online · ${status.host.host_id}`
    : `${status.host.status} · ${status.host.host_id}`;
  hostStatus.className = `status-chip ${status.host.status === "online" ? "online" : ""}`;
  document.getElementById("host-name").textContent = status.host.host_id;
  document.getElementById("last-event").textContent =
    status.host.last_seen ? formatTime(status.host.last_seen) : "No real telemetry";
  document.getElementById("alert-count").textContent = status.alerts;
  const running = Object.values(status.collectors).filter(c => c.status === "running").length;
  document.getElementById("collector-count").textContent = `${running} running`;
  document.getElementById("collector-status").innerHTML = Object.entries(status.collectors).map(([name, c]) =>
    `<div><strong>${esc(name)}</strong> · ${esc(c.status)}${c.error ? ` · ${esc(c.error)}` : ""}</div>`
  ).join("") || "<div class=\"muted\">No collectors started</div>";
}

function formatTime(value) {
  if (!value) return "Unknown";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

async function refreshAlerts() {
  const alerts = await api("/api/alerts?limit=100");
  if (!state.alertId && alerts.length) {
    state.alertId = alerts[0].id;
  }
  document.getElementById("overview-alerts").innerHTML = alerts.length
    ? alerts.slice(0, 8).map(renderAlertRow).join("")
    : `<p class="muted">No real alerts. Run a real scan or authentication attempt.</p>`;
  document.getElementById("alert-table").innerHTML = alerts.length
    ? alerts.map(renderAlertRow).join("")
    : `<p class="muted">Waiting for detection evidence.</p>`;
  bindAlertRows();
}

function renderAlertRow(alert) {
  const severity = String(alert.severity).toLowerCase();
  return `<button class="alert-row" data-alert-id="${esc(alert.id)}">
    <span class="severity severity-${severity}">${esc(alert.severity)}</span>
    · <strong>${esc(alert.rule_name)}</strong>
    · ${esc(alert.source_ip || alert.account || "host")}
    · MITRE ${esc(alert.mitre)}
    · ${formatTime(alert.timestamp)}
  </button>`;
}

function bindAlertRows() {
  document.querySelectorAll("[data-alert-id]").forEach(row => {
    row.onclick = () => {
      state.alertId = row.dataset.alertId;
      activateView("investigation");
    };
  });
}

async function refreshEvents() {
  const events = await api("/api/events?limit=150");
  document.getElementById("timeline-list").innerHTML = events.length
    ? events.map(event => `<div class="timeline-row">
        <strong>${esc(event.category)} / ${esc(event.action)}</strong>
        · ${esc(event.source_ip || event.process_name || event.user_name || event.host_id)}
        · ${formatTime(event.timestamp)}
      </div>`).join("")
    : `<p class="muted">No real events received yet.</p>`;
}

function svgElement(name, attributes = {}) {
  const element = document.createElementNS("http://www.w3.org/2000/svg", name);
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
  return element;
}

async function loadGraph(alertId) {
  state.graph = await api(`/api/graph/${encodeURIComponent(alertId)}`);
  const svg = document.getElementById("graph");
  svg.replaceChildren();
  document.getElementById("investigation-empty").textContent =
    `${state.graph.nodes.length} evidence nodes · ${state.graph.edges.length} evidence relationships`;

  const defs = svgElement("defs");
  defs.innerHTML = `<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b"></path></marker>`;
  svg.appendChild(defs);

  const positions = new Map();
  const columns = Math.max(1, Math.ceil(Math.sqrt(state.graph.nodes.length)));
  const rows = Math.max(1, Math.ceil(state.graph.nodes.length / columns));
  state.graph.nodes.forEach((node, index) => {
    const column = index % columns;
    const row = Math.floor(index / columns);
    positions.set(node.id, {
      x: 90 + column * (720 / Math.max(columns - 1, 1)),
      y: 70 + row * (380 / Math.max(rows - 1, 1)),
    });
  });

  state.graph.edges.forEach(edge => {
    const source = positions.get(edge.from);
    const target = positions.get(edge.to);
    if (!source || !target) return;
    const line = svgElement("line", {
      x1: source.x, y1: source.y, x2: target.x, y2: target.y,
      stroke: "#64748b", "stroke-width": 2, "marker-end": "url(#arrow)",
    });
    const title = svgElement("title");
    title.textContent = edge.label;
    line.appendChild(title);
    svg.appendChild(line);
  });

  const colors = {
    host: "#2563eb",
    alert: "#ef4444",
    ip: "#f59e0b",
    account: "#a855f7",
    process: "#14b8a6",
    event: "#64748b",
    endpoint: "#38bdf8",
    registry: "#e11d48",
    file: "#84cc16",
  };
  state.graph.nodes.forEach(node => {
    const point = positions.get(node.id);
    const group = svgElement("g", { transform: `translate(${point.x} ${point.y})`, tabindex: "0" });
    const circle = svgElement("circle", { r: 20, fill: colors[node.kind] || "#64748b" });
    const title = svgElement("title");
    title.textContent = `${node.kind}: ${node.label}`;
    circle.appendChild(title);
    group.appendChild(circle);
    const label = svgElement("text", {
      "text-anchor": "middle", y: 38, fill: "#e5edf7", "font-size": "11",
    });
    label.textContent = node.label.length > 28 ? `${node.label.slice(0, 28)}…` : node.label;
    group.appendChild(label);
    group.onclick = () => showNode(node);
    svg.appendChild(group);
  });
}

function showNode(node) {
  document.getElementById("node-detail").innerHTML =
    `<h2>${esc(node.label)}</h2><p class="muted">${esc(node.kind)}</p><pre>${esc(JSON.stringify(node.details, null, 2))}</pre>`;
}

async function refresh() {
  try {
    await Promise.all([refreshStatus(), refreshAlerts(), refreshEvents()]);
  } catch (error) {
    console.error(error);
  }

  document.getElementById("refresh-intel").onclick = async () => {
    const status = document.getElementById("intel-status");
    status.textContent = "Refreshing...";
    try {
      await api("/api/threat-intel/refresh", { method: "POST" });
      status.textContent = "Threat-intelligence cache refreshed.";
    } catch (error) {
      status.textContent = "Refresh unavailable: API key or network feed not configured.";
    }
  };
}

document.querySelectorAll("nav button").forEach(button => {
  button.onclick = () => activateView(button.dataset.view);
});
refresh();
setInterval(refresh, 3000);

"""
INT Telemetry Dashboard
=======================
Run alongside the collector:

    # Terminal 1 (in Mininet collector host):
    python3 controller/int_controller.py &
    python3 controller/dashboard.py

Then open http://<collector-ip>:8080 in your browser.

The dashboard polls /api/state every second for live data.
"""

import json
import time
import threading
import sys
import os

# Allow running from project root or controller/ directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

# ---------------------------------------------------------------------------
# Shared state (populated by the INT collector running in the same process)
# ---------------------------------------------------------------------------
from int_controller import (
    IntController, FlowTracker, IntCollector,
    COLLECTOR_HOST, COLLECTOR_PORT, COLLECTOR_IFACE
)

# Global controller instance shared between the web server and the collection loop
_controller: IntController = None
_burst_requested = threading.Event()
_history: list = []          # last 60 per-second latency snapshots
_history_lock = threading.Lock()
_session_max_us: float = 0.0


def _sample_loop():
    """Background thread: samples tracker state every second for the history graph."""
    global _session_max_us
    while True:
        time.sleep(1)
        if _controller is None:
            continue
        stats = _controller.tracker.all_flow_stats()
        if not stats:
            continue
        # Use the first active flow as the primary
        s = stats[0]
        avg_us = s.get("avg_latency_us", 0)
        if avg_us > _session_max_us:
            _session_max_us = avg_us
        with _history_lock:
            _history.append(round(avg_us, 1))
            if len(_history) > 60:
                _history.pop(0)


# ---------------------------------------------------------------------------
# API state builder
# ---------------------------------------------------------------------------

def _build_state() -> dict:
    global _session_max_us
    if _controller is None:
        return {"ready": False}

    stats = _controller.tracker.all_flow_stats()
    col   = _controller.collector.stats

    # ---- aggregate across all flows ----
    all_avg = [s["avg_latency_us"] for s in stats if s["avg_latency_us"] > 0]
    all_max = [s["max_latency_us"] for s in stats]
    global_avg = round(sum(all_avg) / len(all_avg), 1) if all_avg else 0
    global_max = round(max(all_max), 1) if all_max else 0
    rps = col["decoded"]   # crude; frontend can diff successive values

    flows_out = []
    for s in stats:
        # rebuild per-hop info from the most recent report in the tracker
        key_str = s["flow"]
        rec = _controller.tracker.flows.get(key_str)
        hops_data = []
        if rec and rec["reports"]:
            last = rec["reports"][-1]
            for h in last.hops:
                hops_data.append({
                    "switch_id":    h.switch_id,
                    "ingress_port": h.ingress_port,
                    "egress_port":  h.egress_port,
                    "latency_us":   round(h.hop_latency_ns / 1000, 2),
                    "queue_pct":    round((h.queue_occupancy / 1024) * 100, 1),
                })
        path_label = "→".join(f"S{h['switch_id']}" for h in hops_data) if hops_data else s.get("current_path", "?")
        flows_out.append({
            "flow":        key_str,
            "path":        path_label,
            "avg_lat_us":  round(s["avg_latency_us"], 1),
            "max_lat_us":  round(s["max_latency_us"], 1),
            "min_lat_us":  round(s["min_latency_us"], 1),
            "hop_count":   s["hop_count"],
            "samples":     s["sample_count"],
            "hops":        hops_data,
            "status":      "Critical" if s["avg_latency_us"] > 500
                           else "Warn" if s["avg_latency_us"] > 100
                           else "Normal",
        })

    with _history_lock:
        hist = list(_history)

    # anomaly detection
    anomalies = []
    for s in stats:
        if s["avg_latency_us"] > 500:
            anomalies.append(f"Critical latency on {s['flow']}: {s['avg_latency_us']:.1f}µs")
        for h in (flows_out[0]["hops"] if flows_out else []):
            if h["queue_pct"] > 80:
                anomalies.append(f"Queue congestion at S{h['switch_id']}: {h['queue_pct']}%")

    return {
        "ready":         True,
        "timestamp":     datetime.now().strftime("%H:%M:%S"),
        "global_avg_us": global_avg,
        "global_max_us": global_max,
        "session_max_us": round(_session_max_us, 1),
        "reports_total": col["decoded"],
        "errors":        col["errors"],
        "active_flows":  len(stats),
        "flows":         flows_out,
        "history":       hist,
        "anomalies":     anomalies if anomalies else ["None detected"],
    }


# ---------------------------------------------------------------------------
# Inline HTML (no external files needed)
# ---------------------------------------------------------------------------

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>INT Telemetry Dashboard</title>
<style>
  :root {
    --bg:      #0d1117;
    --surface: #161b22;
    --border:  #30363d;
    --text:    #e6edf3;
    --muted:   #8b949e;
    --green:   #3fb950;
    --yellow:  #d29922;
    --red:     #f85149;
    --blue:    #58a6ff;
    --accent:  #1f6feb;
    --font:    'JetBrains Mono', 'Fira Mono', 'Courier New', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font);
         font-size: 13px; line-height: 1.5; }

  /* ── Header ── */
  header { background: var(--surface); border-bottom: 1px solid var(--border);
            padding: 12px 20px; display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
  header h1 { font-size: 16px; font-weight: 700; letter-spacing: .03em; }
  header p  { color: var(--muted); font-size: 11px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green);
         box-shadow: 0 0 6px var(--green); animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
  .badge { padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 600;
           background: #21262d; border: 1px solid var(--border); cursor: pointer;
           color: var(--text); transition: background .15s; }
  .badge:hover { background: var(--accent); border-color: var(--blue); }
  .badge.active { background: var(--accent); border-color: var(--blue); }
  .status-collecting { color: var(--green); font-size: 11px; font-weight: 700; }

  /* ── Layout ── */
  main { padding: 16px 20px; display: grid; gap: 14px;
         grid-template-columns: repeat(4, 1fr); }
  .card { background: var(--surface); border: 1px solid var(--border);
          border-radius: 8px; padding: 14px 16px; }
  .card-title { font-size: 10px; font-weight: 700; letter-spacing: .12em;
                color: var(--muted); text-transform: uppercase; margin-bottom: 8px; }

  /* ── KPI cards ── */
  .kpi { }
  .kpi .val { font-size: 28px; font-weight: 700; line-height: 1.1; }
  .kpi .sub { font-size: 10px; color: var(--muted); margin-top: 4px; }
  .kpi .badge-status { font-size: 10px; margin-top: 6px; display: inline-block;
                        padding: 2px 8px; border-radius: 3px; font-weight: 600; }
  .normal  { color: var(--green); }
  .warn    { color: var(--yellow); }
  .critical{ color: var(--red); }
  .badge-normal   { background: #1a3a20; color: var(--green); }
  .badge-warn     { background: #3a2e0a; color: var(--yellow); }
  .badge-critical { background: #3a1010; color: var(--red); }

  /* ── Topology + chart row ── */
  .wide2 { grid-column: span 2; }

  /* Topology */
  #topology-svg { width: 100%; height: 160px; }
  .topo-node { font-size: 10px; font-weight: 700; text-anchor: middle; }
  .topo-label { font-size: 9px; text-anchor: middle; fill: var(--muted); }
  .topo-link  { stroke: var(--border); stroke-width: 1.5; }
  .topo-link.active { stroke: var(--blue); stroke-width: 2;
                       animation: dash 1s linear infinite; stroke-dasharray: 6 4; }
  @keyframes dash { to { stroke-dashoffset: -10; } }

  /* Bar chart */
  #chart-wrap { display: flex; align-items: flex-end; gap: 2px; height: 80px;
                margin-top: 8px; }
  .bar { flex: 1; border-radius: 2px 2px 0 0; background: var(--accent);
         transition: height .3s, background .3s; min-width: 3px; }
  .chart-labels { display: flex; justify-content: space-between;
                  font-size: 9px; color: var(--muted); margin-top: 4px; }
  .anomaly-list { margin-top: 10px; }
  .anomaly-item { font-size: 11px; color: var(--muted); padding: 2px 0; }
  .anomaly-item.bad { color: var(--red); }

  /* ── Flow table ── */
  .flow-table-wrap { grid-column: span 4; }
  table { width: 100%; border-collapse: collapse; }
  th { font-size: 10px; font-weight: 700; color: var(--muted); text-transform: uppercase;
       letter-spacing: .08em; padding: 6px 8px; text-align: left;
       border-bottom: 1px solid var(--border); }
  td { padding: 8px 8px; border-bottom: 1px solid #1c2128; font-size: 12px; }
  tr:last-child td { border-bottom: none; }
  .queue-bar-wrap { display: flex; gap: 3px; align-items: center; }
  .queue-seg { width: 18px; height: 12px; border-radius: 2px; background: var(--blue); }
  .queue-pct { font-size: 10px; color: var(--muted); margin-left: 4px; }

  /* ── Bottom row ── */
  .bottom-row { grid-column: span 4; display: grid;
                grid-template-columns: 1fr 1fr; gap: 14px; }

  /* Instruction bitmap */
  .bit-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin-top: 8px; }
  .bit-cell { background: #1f6feb33; border: 1px solid var(--accent); border-radius: 4px;
              padding: 6px 4px; text-align: center; }
  .bit-cell .bc-name { font-size: 10px; font-weight: 700; color: var(--blue); }
  .bit-cell .bc-size { font-size: 9px; color: var(--muted); margin-top: 2px; }
  .bit-meta { margin-top: 10px; font-size: 10px; color: var(--muted); }

  /* Telemetry log */
  #log { height: 140px; overflow-y: auto; margin-top: 8px; }
  .log-line { font-size: 11px; color: #3fb950; padding: 1px 0; white-space: nowrap; }
  .log-line.warn { color: var(--yellow); }
  .log-line.crit { color: var(--red); }

  /* Traffic mode buttons */
  .mode-btns { display: flex; gap: 8px; margin-bottom: 8px; }
  .mode-btn { padding: 4px 14px; border-radius: 4px; font-size: 11px; font-weight: 700;
              background: #21262d; border: 1px solid var(--border); color: var(--text);
              cursor: pointer; font-family: var(--font); }
  .mode-btn.active { background: var(--accent); border-color: var(--blue); }
</style>
</head>
<body>

<header>
  <div class="dot"></div>
  <div>
    <h1>In-band Network Telemetry</h1>
    <p>Live packet-level visibility · BMv2 software switch</p>
  </div>
  <span class="status-collecting" id="hdr-status">● Collecting</span>
  <button class="badge" onclick="togglePause()" id="btn-pause">Pause</button>
  <button class="badge" onclick="triggerBurst()" id="btn-burst">Trigger Burst</button>
  <span id="hdr-time" style="margin-left:auto;color:var(--muted);font-size:11px;"></span>
</header>

<main>
  <!-- KPI cards -->
  <div class="card kpi">
    <div class="card-title">Avg Latency</div>
    <div class="val" id="kpi-avg">—</div>
    <div class="sub">across active flows</div>
    <span class="badge-status badge-normal" id="kpi-avg-badge">normal</span>
  </div>
  <div class="card kpi">
    <div class="card-title">Max Latency</div>
    <div class="val" id="kpi-max">—</div>
    <div class="sub" id="kpi-max-sub">peak this session</div>
  </div>
  <div class="card kpi">
    <div class="card-title">Reports / Sec</div>
    <div class="val" id="kpi-rps">—</div>
    <div class="sub">last 1s</div>
  </div>
  <div class="card kpi">
    <div class="card-title">Active Flows</div>
    <div class="val" id="kpi-flows">—</div>
    <div class="sub">5-tuple tracked</div>
  </div>

  <!-- Topology -->
  <div class="card wide2">
    <div class="card-title">Network Topology <span id="path-label" style="float:right;color:var(--blue);font-size:10px;"></span></div>
    <svg id="topology-svg" viewBox="0 0 420 150">
      <!-- Links -->
      <line class="topo-link" id="lnk-h1s1"  x1="40"  y1="75" x2="100" y2="75"/>
      <line class="topo-link" id="lnk-s1s2"  x1="120" y1="75" x2="180" y2="75"/>
      <line class="topo-link" id="lnk-s2s3"  x1="200" y1="75" x2="280" y2="75"/>
      <line class="topo-link" id="lnk-s3h2"  x1="300" y1="75" x2="360" y2="75"/>
      <line class="topo-link" id="lnk-s3col" x1="290" y1="90" x2="290" y2="130"/>
      <!-- S4 alternate path -->
      <line class="topo-link" id="lnk-s1s4"  x1="110" y1="88" x2="190" y2="128"/>
      <line class="topo-link" id="lnk-s4s3"  x1="210" y1="128" x2="280" y2="88"/>

      <!-- Nodes -->
      <circle cx="40"  cy="75" r="14" fill="#21262d" stroke="var(--border)" stroke-width="1.5"/>
      <circle cx="110" cy="75" r="16" fill="#1f3a5c" stroke="var(--blue)"   stroke-width="1.5" id="node-s1"/>
      <circle cx="200" cy="75" r="16" fill="#21262d" stroke="var(--border)" stroke-width="1.5" id="node-s2"/>
      <circle cx="290" cy="75" r="16" fill="#21262d" stroke="var(--border)" stroke-width="1.5" id="node-s3"/>
      <circle cx="370" cy="75" r="14" fill="#21262d" stroke="var(--border)" stroke-width="1.5"/>
      <circle cx="200" cy="128" r="14" fill="#21262d" stroke="var(--border)" stroke-width="1.5" id="node-s4"/>
      <circle cx="290" cy="135" r="12" fill="#1a2d1a" stroke="var(--green)" stroke-width="1"/>

      <!-- Labels -->
      <text class="topo-node" x="40"  y="79" fill="var(--muted)">h1</text>
      <text class="topo-node" x="110" y="79" fill="var(--blue)"  id="lbl-s1">S1</text>
      <text class="topo-node" x="200" y="79" fill="var(--text)"  id="lbl-s2">S2</text>
      <text class="topo-node" x="290" y="79" fill="var(--text)"  id="lbl-s3">S3</text>
      <text class="topo-node" x="370" y="79" fill="var(--muted)">h2</text>
      <text class="topo-node" x="200" y="132" fill="var(--muted)" id="lbl-s4">S4</text>
      <text class="topo-node" x="290" y="139" fill="var(--green)" font-size="8">collector</text>

      <!-- Role badges -->
      <text class="topo-label" x="110" y="100" id="role-s1">source</text>
      <text class="topo-label" x="200" y="100" id="role-s2">transit</text>
      <text class="topo-label" x="290" y="100" id="role-s3">sink</text>
      <text class="topo-label" x="200" y="148" id="role-s4">transit</text>
    </svg>
  </div>

  <!-- Latency history chart -->
  <div class="card wide2">
    <div class="card-title">Latency history <span style="float:right;color:var(--muted);font-size:9px;">last 60s</span></div>
    <div id="chart-wrap"></div>
    <div class="chart-labels"><span>oldest</span><span id="chart-peak"></span><span>now</span></div>
    <div class="anomaly-list" id="anomaly-list"></div>
  </div>

  <!-- Flow table -->
  <div class="card flow-table-wrap">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <span class="card-title" style="margin:0">Active Flows</span>
      <div class="mode-btns">
        <button class="mode-btn active" onclick="setMode('steady')">Steady</button>
        <button class="mode-btn" onclick="setMode('burst')">Burst</button>
        <button class="mode-btn" onclick="setMode('multi')">Multi-flow</button>
      </div>
    </div>
    <table>
      <thead>
        <tr>
          <th>Flow (5-tuple)</th>
          <th>Path</th>
          <th>Avg Lat</th>
          <th>Max Lat</th>
          <th>Queue</th>
          <th>Status</th>
          <th>Hops</th>
        </tr>
      </thead>
      <tbody id="flow-tbody"></tbody>
    </table>
  </div>

  <!-- Bottom row -->
  <div class="bottom-row">
    <!-- Instruction bitmap -->
    <div class="card">
      <div class="card-title">INT instruction bitmap <span style="float:right;color:var(--blue)">0xFC00</span></div>
      <div class="bit-grid">
        <div class="bit-cell"><div class="bc-name">Switch ID</div><div class="bc-size">4B</div></div>
        <div class="bit-cell"><div class="bc-name">Port IDs</div><div class="bc-size">4B</div></div>
        <div class="bit-cell"><div class="bc-name">Hop latency</div><div class="bc-size">4B</div></div>
        <div class="bit-cell"><div class="bc-name">Queue occ.</div><div class="bc-size">4B</div></div>
        <div class="bit-cell"><div class="bc-name">Ingress ts</div><div class="bc-size">8B</div></div>
        <div class="bit-cell"><div class="bc-name">Egress ts</div><div class="bc-size">8B</div></div>
        <div class="bit-cell" style="opacity:.3"><div class="bc-name">Queue cong.</div><div class="bc-size">4B</div></div>
        <div class="bit-cell" style="opacity:.3"><div class="bc-name">Egress util</div><div class="bc-size">4B</div></div>
      </div>
      <div class="bit-meta">Bytes per hop: 32B · Max overhead (6 hops): 192B + 16B fixed</div>
    </div>

    <!-- Telemetry log -->
    <div class="card">
      <div class="card-title">Telemetry log</div>
      <div id="log"></div>
    </div>
  </div>
</main>

<script>
let paused = false;
let prevReports = 0;
let logLines = [];
let activeMode = 'steady';

function togglePause() {
  paused = !paused;
  document.getElementById('btn-pause').textContent = paused ? 'Resume' : 'Pause';
  document.getElementById('btn-pause').classList.toggle('active', paused);
  document.getElementById('hdr-status').textContent = paused ? '⏸ Paused' : '● Collecting';
}

function triggerBurst() {
  fetch('/api/burst', {method:'POST'});
  addLog('BURST mode triggered', 'warn');
}

function setMode(m) {
  activeMode = m;
  document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  addLog(`Traffic mode: ${m}`, '');
}

function addLog(msg, cls='') {
  const now = new Date().toTimeString().slice(0,8);
  logLines.push({msg: `[${now}] ${msg}`, cls});
  if (logLines.length > 100) logLines.shift();
  const el = document.getElementById('log');
  el.innerHTML = logLines.map(l =>
    `<div class="log-line ${l.cls}">${l.msg}</div>`
  ).join('');
  el.scrollTop = el.scrollHeight;
}

function statusClass(s) {
  if (!s) return 'normal';
  return s.toLowerCase();
}

function render(d) {
  document.getElementById('hdr-time').textContent = d.timestamp;

  // KPIs
  const avgUs = d.global_avg_us;
  document.getElementById('kpi-avg').textContent = avgUs ? avgUs.toFixed(1) + 'µs' : '—';
  document.getElementById('kpi-max').textContent = d.global_max_us ? d.global_max_us.toFixed(1) + 'µs' : '—';
  document.getElementById('kpi-max-sub').textContent = `${d.session_max_us}µs peak this session`;
  const rps = d.reports_total - prevReports;
  prevReports = d.reports_total;
  document.getElementById('kpi-rps').textContent = rps;
  document.getElementById('kpi-flows').textContent = d.active_flows;

  const avgBadge = document.getElementById('kpi-avg-badge');
  if (avgUs > 500) { avgBadge.className = 'badge-status badge-critical'; avgBadge.textContent = 'critical'; }
  else if (avgUs > 100) { avgBadge.className = 'badge-status badge-warn'; avgBadge.textContent = 'high'; }
  else { avgBadge.className = 'badge-status badge-normal'; avgBadge.textContent = 'normal'; }

  // Latency bar chart
  const wrap = document.getElementById('chart-wrap');
  const bars = d.history || [];
  const maxH = Math.max(...bars, 1);
  wrap.innerHTML = bars.map(v => {
    const pct = Math.max(4, Math.round((v / maxH) * 80));
    const col = v > 500 ? 'var(--red)' : v > 100 ? 'var(--yellow)' : 'var(--accent)';
    return `<div class="bar" style="height:${pct}px;background:${col}" title="${v}µs"></div>`;
  }).join('');
  document.getElementById('chart-peak').textContent =
    maxH > 1 ? maxH.toFixed(0) + 'µs peak' : '';

  // Anomalies
  const anom = document.getElementById('anomaly-list');
  anom.innerHTML = '<div class="card-title" style="margin-top:8px">Anomalies</div>' +
    (d.anomalies || ['None detected']).map(a =>
      `<div class="anomaly-item ${a === 'None detected' ? '' : 'bad'}">${a}</div>`
    ).join('');

  // Path label + topology highlighting
  const flow = (d.flows || [])[0];
  if (flow) {
    document.getElementById('path-label').textContent = 'path: ' + flow.path.replace(/→/g,' → ');
    // Highlight active path nodes
    ['s1','s2','s3','s4'].forEach(sw => {
      const inPath = flow.path.toLowerCase().includes(sw);
      const node = document.getElementById('node-'+sw);
      if (node) {
        node.setAttribute('fill', inPath ? '#1f3a5c' : '#21262d');
        node.setAttribute('stroke', inPath ? 'var(--blue)' : 'var(--border)');
      }
    });
    // Animate active links
    ['h1s1','s1s2','s2s3','s3h2'].forEach(id => {
      const el = document.getElementById('lnk-'+id);
      if (el) el.className = 'topo-link active';
    });
  }

  // Flow table
  const tbody = document.getElementById('flow-tbody');
  tbody.innerHTML = (d.flows || []).map(f => {
    const queuePct = f.hops.length ? Math.max(...f.hops.map(h => h.queue_pct)) : 0;
    const segs = Math.min(5, Math.ceil(queuePct / 20));
    const queueHtml = '<div class="queue-bar-wrap">' +
      Array(segs).fill('<div class="queue-seg"></div>').join('') +
      `<span class="queue-pct">${queuePct.toFixed(0)}%</span></div>`;
    const sc = statusClass(f.status);
    return `<tr>
      <td>${f.flow}</td>
      <td>${f.path}</td>
      <td>${f.avg_lat_us}µs</td>
      <td>${f.max_lat_us}µs</td>
      <td>${queueHtml}</td>
      <td><span class="${sc}">${f.status}</span></td>
      <td>${f.hop_count}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="7" style="color:var(--muted);text-align:center">Waiting for reports…</td></tr>';

  // Log entry
  if (flow) {
    const cls = flow.status === 'Critical' ? 'crit' : flow.status === 'Warn' ? 'warn' : '';
    addLog(`RPT lat=${flow.avg_lat_us}µs path=${flow.path}`, cls);
  }
}

async function poll() {
  if (paused) return;
  try {
    const r = await fetch('/api/state');
    const d = await r.json();
    if (d.ready) render(d);
  } catch(e) { /* collector may be starting */ }
}

setInterval(poll, 1000);
poll();
addLog('Dashboard connected', '');
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):

    def log_message(self, *args):
        pass  # suppress request logging

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self._send(200, "text/html", HTML.encode())
        elif self.path == "/api/state":
            data = json.dumps(_build_state()).encode()
            self._send(200, "application/json", data)
        else:
            self._send(404, "text/plain", b"Not found")

    def do_POST(self):
        if self.path == "/api/burst":
            _burst_requested.set()
            self._send(200, "application/json", b'{"ok":true}')
        else:
            self._send(404, "text/plain", b"Not found")

    def _send(self, code, ct, body):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    global _controller

    print("[dashboard] Starting INT controller…")
    _controller = IntController()
    _controller.configure_topology()
    _controller.start_collection()

    # Background sampler for the history graph
    t = threading.Thread(target=_sample_loop, daemon=True)
    t.start()

    port = 8080
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"[dashboard] Listening on http://0.0.0.0:{port}")
    print(f"[dashboard] Open http://<collector-ip>:{port} in your browser")
    print("[dashboard] Ctrl+C to quit")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[dashboard] Shutting down")
        _controller.collector.stop()


if __name__ == "__main__":
    main()
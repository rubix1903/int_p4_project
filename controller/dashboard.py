"""
INT Telemetry Dashboard
Run inside Mininet collector host:
    python3 controller/dashboard.py
Then access http://localhost:8081 (via port-forward from host)
"""
import json, time, threading, sys, os, subprocess, signal
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from int_controller import IntController, COLLECTOR_HOST, COLLECTOR_PORT

# Shared state
# ---------------------
_controller   = None
_history      = []          # list of {avg, max} dicts, last 20 samples
_history_lock = threading.Lock()
_session_max  = 0.0
_traffic_proc = None        # subprocess for traffic_gen.py
_traffic_lock = threading.Lock()
_traffic_mode = None        # 'steady' | 'burst' | 'multi'

TRAFFIC_GEN = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "scripts", "traffic_gen.py")

def _start_traffic(mode):
    global _traffic_proc, _traffic_mode
    with _traffic_lock:
        if _traffic_proc and _traffic_proc.poll() is None:
            os.killpg(os.getpgid(_traffic_proc.pid), signal.SIGTERM)
            _traffic_proc = None
        if mode is None:
            _traffic_mode = None
            return
        extra = []
        if mode == "burst":
            extra = ["--pps", "5000"]
        elif mode == "multi":
            extra = ["--flows", "8"]
        # Finds  h1's network namespace PID and run traffic_gen inside it
        try:
            import glob
            h1_pid = None
            for f in glob.glob("/proc/*/net/dev"):
                try:
                    with open(f) as fh:
                        if "h1-eth0" in fh.read():
                            h1_pid = f.split("/")[2]
                            break
                except Exception:
                    pass
            if h1_pid:
                cmd = ["nsenter", "-t", h1_pid, "-n",
                       "python3", TRAFFIC_GEN,
                       "--mode", mode,
                       "--iface", "h1-eth0",
                       "--src",   "10.0.1.1",
                       "--dst",   "10.0.3.2",
                       "--duration", "3600"] + extra
            else:
                cmd = ["python3", TRAFFIC_GEN,
                       "--mode", mode,
                       "--iface", "h1-eth0",
                       "--src",   "10.0.1.1",
                       "--dst",   "10.0.3.2",
                       "--duration", "3600"] + extra
        except Exception:
            cmd = ["python3", TRAFFIC_GEN, "--mode", mode,
                   "--iface", "h1-eth0", "--src", "10.0.1.1",
                   "--dst", "10.0.3.2", "--duration", "3600"] + extra
        _traffic_proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid)
        _traffic_mode = mode

def _sampler():
    global _session_max
    while True:
        time.sleep(1)
        if _controller is None:
            continue
        stats = _controller.tracker.all_flow_stats()
        if not stats:
            continue
        avg = sum(s["avg_latency_us"] for s in stats) / len(stats)
        mx  = max(s["max_latency_us"] for s in stats)
        if mx > _session_max:
            _session_max = mx
        with _history_lock:
            _history.append({"avg": round(avg,1), "max": round(mx,1)})
            if len(_history) > 20:
                _history.pop(0)

def _build_state():
    if _controller is None:
        return {"ready": False}
    stats = _controller.tracker.all_flow_stats()
    col   = _controller.collector.stats
    avg_us = 0.0
    max_us = 0.0
    if stats:
        avg_us = round(sum(s["avg_latency_us"] for s in stats)/len(stats),1)
        max_us = round(max(s["max_latency_us"] for s in stats),1)
    flows_out = []
    for s in stats:
        key_str = s["flow"]
        # tracker.reports is keyed by FlowKey objects, not strings
        flow_key = None
        for k in _controller.tracker.reports:
            if str(k) == key_str:
                flow_key = k
                break
        reps = list(_controller.tracker.reports.get(flow_key, [])) if flow_key else []
        hops_data = []
        if reps:
            for h in reps[-1].hops:
                hops_data.append({
                    "switch_id":    h.switch_id,
                    "latency_us":   round(h.hop_latency_ns/1000,2),
                    "queue_pct":    round((h.queue_occupancy/1024)*100,1),
                    "ingress_port": h.ingress_port,
                    "egress_port":  h.egress_port,
                })
        path = "→".join(f"S{h['switch_id']}" for h in hops_data) if hops_data else "?"
        q_max = max((h["queue_pct"] for h in hops_data), default=0)
        status = "Critical" if avg_us > 500 else "Warn" if avg_us > 100 else "Normal"
        flows_out.append({
            "flow":       key_str,
            "path":       path,
            "avg_lat_us": round(s["avg_latency_us"],1),
            "max_lat_us": round(s["max_latency_us"],1),
            "hop_count":  s["hop_count"],
            "queue_pct":  round(q_max,1),
            "status":     status,
            "hops":       hops_data,
        })
    with _history_lock:
        hist = list(_history)
    anomalies = []
    for f in flows_out:
        if f["avg_lat_us"] > 500:
            anomalies.append(f"Critical latency {f['avg_lat_us']}µs")
        if f["queue_pct"] > 80:
            anomalies.append(f"Queue congestion {f['queue_pct']}%")
    return {
        "ready":        True,
        "timestamp":    datetime.now().strftime("%H:%M:%S"),
        "avg_us":       avg_us,
        "max_us":       max_us,
        "session_max":  round(_session_max,1),
        "reports_total":col["decoded"],
        "active_flows": len(stats),
        "flows":        flows_out,
        "history":      hist,
        "anomalies":    anomalies if anomalies else ["None detected"],
        "traffic_mode": _traffic_mode,
    }

# HTML ────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>INT Telemetry</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0e12;--surf:#111820;--surf2:#161e28;--border:#1e2d3d;
  --text:#cdd9e5;--muted:#546e7a;--green:#26a641;--green2:#39d353;
  --blue:#388bfd;--blue2:#58a6ff;--yellow:#bb8009;--red:#da3633;
  --accent:#1f6feb;--font:'JetBrains Mono',monospace;
}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:12px;line-height:1.5;min-height:100vh}

/* header */
header{background:var(--surf);border-bottom:1px solid var(--border);
  padding:10px 18px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.dot{width:8px;height:8px;border-radius:50%;background:var(--green2);
  box-shadow:0 0 8px var(--green2);flex-shrink:0;animation:blink 2s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
header h1{font-size:15px;font-weight:700;letter-spacing:.02em;color:var(--text)}
header p{font-size:10px;color:var(--muted)}
.hdr-collecting{color:var(--green2);font-size:11px;font-weight:700;margin-left:4px}
.hdr-btn{padding:4px 14px;border-radius:5px;font-size:11px;font-weight:600;
  background:#1c2a3a;border:1px solid var(--border);color:var(--text);
  cursor:pointer;font-family:var(--font);transition:all .15s}
.hdr-btn:hover{background:var(--accent);border-color:var(--blue)}
.hdr-btn.active{background:var(--accent);border-color:var(--blue2)}
.hdr-time{margin-left:auto;color:var(--muted);font-size:11px}

/* layout */
main{padding:14px 18px;display:grid;gap:12px;
  grid-template-columns:repeat(4,1fr);grid-template-rows:auto}

/* cards */
.card{background:var(--surf);border:1px solid var(--border);border-radius:6px;padding:14px 15px}
.ctitle{font-size:9px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;
  color:var(--muted);margin-bottom:10px}

/* KPI */
.kpi .val{font-size:26px;font-weight:700;line-height:1}
.kpi .sub{font-size:9px;color:var(--muted);margin-top:5px}
.kpi .pill{display:inline-block;margin-top:6px;padding:2px 8px;border-radius:3px;
  font-size:10px;font-weight:700}
.pill-normal{background:#0d2116;color:var(--green2)}
.pill-warn{background:#2a1f00;color:#e3b341}
.pill-critical{background:#2d0f0f;color:var(--red)}

/* topology + chart row */
.span2{grid-column:span 2}
.span4{grid-column:span 4}

/* topology SVG */
.topo-svg{width:100%;height:155px}
.node-circle{transition:fill .3s,stroke .3s}
.link-path{stroke:var(--border);stroke-width:1.5;fill:none}
.link-path.active{stroke:var(--blue);stroke-width:2;
  stroke-dasharray:6 3;animation:flow .8s linear infinite}
@keyframes flow{to{stroke-dashoffset:-9}}
.node-lbl{font-size:10px;font-weight:700;text-anchor:middle;dominant-baseline:central;font-family:var(--font)}
.node-sub{font-size:8px;text-anchor:middle;fill:var(--muted);font-family:var(--font)}
.path-badge{font-size:9px;font-weight:700;color:var(--blue2);float:right}

/* chart */
.chart-bars{display:flex;align-items:flex-end;gap:2px;height:72px;margin-top:6px}
.bar{flex:1;border-radius:2px 2px 0 0;min-width:2px;transition:height .3s,background .3s}
.chart-meta{display:flex;justify-content:space-between;font-size:9px;color:var(--muted);margin-top:3px}
.anomalies{margin-top:10px}
.anom-title{font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:4px}
.anom-line{font-size:10px;color:var(--muted);padding:1px 0}
.anom-line.bad{color:var(--red)}

/* flows table */
.flows-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.mode-btns{display:flex;gap:6px}
.mode-btn{padding:4px 12px;border-radius:4px;font-size:11px;font-weight:600;
  background:#1c2a3a;border:1px solid var(--border);color:var(--text);
  cursor:pointer;font-family:var(--font);transition:all .15s}
.mode-btn:hover{background:#1f3a5c;border-color:var(--blue)}
.mode-btn.active{background:var(--accent);border-color:var(--blue2);color:#fff}
table{width:100%;border-collapse:collapse}
th{font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
  color:var(--muted);padding:5px 8px;text-align:left;border-bottom:1px solid var(--border)}
td{padding:8px 8px;border-bottom:1px solid #111820;font-size:11px;vertical-align:middle}
tr:last-child td{border-bottom:none}
.q-wrap{display:flex;align-items:center;gap:3px}
.q-seg{width:16px;height:10px;border-radius:2px;background:var(--blue)}
.q-pct{font-size:9px;color:var(--muted)}
.status-normal{color:var(--green2)}
.status-warn{color:#e3b341}
.status-critical{color:var(--red)}

/* bottom row */
.bottom{grid-column:span 4;display:grid;grid-template-columns:1fr 1fr;gap:12px}

/* bitmap */
.bit-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:5px;margin-top:6px}
.bit-cell{background:#0d1929;border:1px solid var(--accent);border-radius:4px;
  padding:6px 4px;text-align:center}
.bit-cell.off{background:#111820;border-color:var(--border);opacity:.4}
.bc-name{font-size:9px;font-weight:700;color:var(--blue2)}
.bc-size{font-size:8px;color:var(--muted);margin-top:1px}
.bit-meta{margin-top:8px;font-size:9px;color:var(--muted)}

/* log */
#logbox{height:130px;overflow-y:auto;margin-top:6px;
  background:var(--bg);border-radius:4px;padding:4px 6px}
.log-line{font-size:10px;padding:1px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.log-green{color:var(--green2)}
.log-yellow{color:#e3b341}
.log-red{color:var(--red)}
</style>
</head>
<body>
<header>
  <div class="dot"></div>
  <div><h1>In-band Network Telemetry</h1><p>Live packet-level visibility · BMv2 software switch</p></div>
  <span class="hdr-collecting" id="hdr-status">● Collecting</span>
  <button class="hdr-btn" id="btn-pause" onclick="togglePause()">Pause</button>
  <button class="hdr-btn" onclick="triggerBurst()">Trigger Burst</button>
  <button class="hdr-btn" onclick="flipPath()">Path Flip</button>
  <span class="hdr-time" id="hdr-time"></span>
</header>

<main>
  <-- KPIs -->
  <div class="card kpi">
    <div class="ctitle">Avg Latency</div>
    <div class="val" id="k-avg">—</div>
    <div class="sub">across active flows</div>
    <span class="pill pill-normal" id="k-avg-pill">normal</span>
  </div>
  <div class="card kpi">
    <div class="ctitle">Max Latency</div>
    <div class="val" id="k-max">—</div>
    <div class="sub" id="k-max-sub">0µs peak this session</div>
  </div>
  <div class="card kpi">
    <div class="ctitle">Reports / Sec</div>
    <div class="val" id="k-rps">0</div>
    <div class="sub">last 1s</div>
  </div>
  <div class="card kpi">
    <div class="ctitle">Active Flows</div>
    <div class="val" id="k-flows">0</div>
    <div class="sub">5-tuple tracked</div>
  </div>

  <-- Topology -->
  <div class="card span2">
    <div class="ctitle">Network Topology <span class="path-badge" id="path-lbl"></span></div>
    <svg class="topo-svg" viewBox="0 0 400 145">
      <!-- links -->
      <line id="lk-h1s1"  class="link-path" x1="42" y1="72" x2="98"  y2="72"/>
      <line id="lk-s1s2"  class="link-path" x1="118" y1="72" x2="174" y2="72"/>
      <line id="lk-s2s3"  class="link-path" x1="194" y1="72" x2="262" y2="72"/>
      <line id="lk-s3h2"  class="link-path" x1="282" y1="72" x2="342" y2="72"/>
      <line id="lk-s1s4"  class="link-path" x1="108" y1="85" x2="178" y2="118"/>
      <line id="lk-s4s3"  class="link-path" x1="200" y1="118" x2="268" y2="85"/>
      <line id="lk-s3col" class="link-path" x1="272" y1="84" x2="272" y2="120"/>
      <!-- nodes -->
      <circle cx="30"  cy="72" r="12" fill="#1c2a3a" stroke="var(--border)" stroke-width="1.2"/>
      <circle cx="108" cy="72" r="16" class="node-circle" id="nc-s1" fill="#0d2035" stroke="var(--blue)" stroke-width="1.8"/>
      <circle cx="184" cy="72" r="16" class="node-circle" id="nc-s2" fill="#1c2a3a" stroke="var(--border)" stroke-width="1.2"/>
      <circle cx="272" cy="72" r="16" class="node-circle" id="nc-s3" fill="#1c2a3a" stroke="var(--border)" stroke-width="1.2"/>
      <circle cx="354" cy="72" r="12" fill="#1c2a3a" stroke="var(--border)" stroke-width="1.2"/>
      <circle cx="190" cy="120" r="13" class="node-circle" id="nc-s4" fill="#1c2a3a" stroke="var(--border)" stroke-width="1.2"/>
      <circle cx="272" cy="132" r="10" fill="#0d2016" stroke="var(--green)" stroke-width="1.2"/>
      <!-- labels -->
      <text class="node-lbl" x="30"  y="72" fill="var(--muted)" font-size="9">h1</text>
      <text class="node-lbl" x="108" y="72" fill="var(--blue2)" id="nl-s1">S1</text>
      <text class="node-lbl" x="184" y="72" fill="var(--text)"  id="nl-s2">S2</text>
      <text class="node-lbl" x="272" y="72" fill="var(--text)"  id="nl-s3">S3</text>
      <text class="node-lbl" x="354" y="72" fill="var(--muted)" font-size="9">h2</text>
      <text class="node-lbl" x="190" y="120" fill="var(--muted)" id="nl-s4" font-size="9">S4</text>
      <text class="node-lbl" x="272" y="132" fill="var(--green2)" font-size="7">collector</text>
      <!-- role labels -->
      <text class="node-sub" x="108" y="93">source</text>
      <text class="node-sub" x="184" y="93">transit</text>
      <text class="node-sub" x="272" y="93" id="role-s3">sink</text>
      <text class="node-sub" x="190" y="138">transit</text>
    </svg>
  </div>

  <-- Chart -->
  <div class="card span2">
    <div class="ctitle">Latency history <span style="float:right;font-size:9px;color:var(--muted)">last 20 reports</span></div>
    <div class="chart-bars" id="chart-bars"></div>
    <div class="chart-meta"><span>oldest</span><span id="chart-peak"></span><span>now</span></div>
    <div class="anomalies">
      <div class="anom-title">Anomalies</div>
      <div id="anom-list"></div>
    </div>
  </div>

  <-- Flow table -->
  <div class="card span4">
    <div class="flows-header">
      <span class="ctitle" style="margin:0">Active flows</span>
      <div class="mode-btns">
        <button class="mode-btn" id="mb-steady" onclick="setMode('steady')">Steady</button>
        <button class="mode-btn" id="mb-burst"  onclick="setMode('burst')">Burst</button>
        <button class="mode-btn" id="mb-multi"  onclick="setMode('multi')">Multi-flow</button>
        <button class="mode-btn" id="mb-stop"   onclick="setMode(null)">Stop</button>
      </div>
    </div>
    <table>
      <thead><tr>
        <th>Flow (5-tuple)</th><th>Path</th>
        <th>Avg Lat</th><th>Max Lat</th>
        <th>Queue</th><th>Status</th><th>Hops</th>
      </tr></thead>
      <tbody id="flow-body"></tbody>
    </table>
  </div>

  <-- Bottom -->
  <div class="bottom">
    <div class="card">
      <div class="ctitle">INT instruction bitmap <span style="float:right;color:var(--blue2)">0xFC00</span></div>
      <div class="bit-grid">
        <div class="bit-cell"><div class="bc-name">Switch ID</div><div class="bc-size">4B</div></div>
        <div class="bit-cell"><div class="bc-name">Port IDs</div><div class="bc-size">4B</div></div>
        <div class="bit-cell"><div class="bc-name">Hop latency</div><div class="bc-size">4B</div></div>
        <div class="bit-cell"><div class="bc-name">Queue occ.</div><div class="bc-size">4B</div></div>
        <div class="bit-cell"><div class="bc-name">Ingress ts</div><div class="bc-size">8B</div></div>
        <div class="bit-cell"><div class="bc-name">Egress ts</div><div class="bc-size">8B</div></div>
        <div class="bit-cell off"><div class="bc-name">Queue cong.</div><div class="bc-size">4B</div></div>
        <div class="bit-cell off"><div class="bc-name">Egress util</div><div class="bc-size">4B</div></div>
      </div>
      <div class="bit-meta">Bytes per hop: 32B · Max overhead (6 hops): 192B + 16B fixed</div>
    </div>
    <div class="card">
      <div class="ctitle">Telemetry log</div>
      <div id="logbox"></div>
    </div>
  </div>
</main>

<script>
let paused=false, prevRpts=0, logLines=[], curMode=null;

function addLog(msg,cls='log-green'){
  const t=new Date().toTimeString().slice(0,8);
  logLines.push(`<div class="log-line ${cls}">[${t}] ${msg}</div>`);
  if(logLines.length>80)logLines.shift();
  const b=document.getElementById('logbox');
  b.innerHTML=logLines.join('');
  b.scrollTop=b.scrollHeight;
}

function togglePause(){
  paused=!paused;
  const b=document.getElementById('btn-pause');
  b.textContent=paused?'Resume':'Pause';
  b.classList.toggle('active',paused);
  document.getElementById('hdr-status').textContent=paused?'⏸ Paused':'● Collecting';
}

function triggerBurst(){
  fetch('/api/mode',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({mode:'burst'})});
  setModeUI('burst');
  addLog('Burst mode triggered','log-yellow');
}

function flipPath(){
  addLog('Path flip requested (manual routing change via switch CLI)','log-yellow');
}

function setMode(m){
  fetch('/api/mode',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({mode:m})});
  setModeUI(m);
  addLog(m?`Traffic mode: ${m}`:'Traffic stopped', m?'log-green':'log-yellow');
}

function setModeUI(m){
  curMode=m;
  ['steady','burst','multi'].forEach(x=>{
    const b=document.getElementById('mb-'+x);
    if(b)b.classList.toggle('active',m===x);
  });
}

function sc(s){return s?s.toLowerCase():'normal'}

function render(d){
  document.getElementById('hdr-time').textContent=d.timestamp;
  // KPIs
  const avg=d.avg_us, mx=d.max_us;
  document.getElementById('k-avg').textContent=avg?avg+'µs':'—';
  document.getElementById('k-max').textContent=mx?mx+'µs':'—';
  document.getElementById('k-max-sub').textContent=`${d.session_max}µs peak this session`;
  const rps=d.reports_total-prevRpts; prevRpts=d.reports_total;
  document.getElementById('k-rps').textContent=Math.max(0,rps);
  document.getElementById('k-flows').textContent=d.active_flows;
  const pill=document.getElementById('k-avg-pill');
  if(avg>500){pill.className='pill pill-critical';pill.textContent='critical';}
  else if(avg>100){pill.className='pill pill-warn';pill.textContent='high';}
  else{pill.className='pill pill-normal';pill.textContent='normal';}

  // chart
  const hist=d.history||[];
  const maxH=Math.max(...hist.map(h=>h.avg),1);
  document.getElementById('chart-bars').innerHTML=hist.map(h=>{
    const pct=Math.max(4,Math.round((h.avg/maxH)*72));
    const col=h.avg>500?'var(--red)':h.avg>100?'#bb8009':'var(--accent)';
    return `<div class="bar" style="height:${pct}px;background:${col}" title="${h.avg}µs"></div>`;
  }).join('');
  document.getElementById('chart-peak').textContent=
    hist.length?`${Math.max(...hist.map(h=>h.avg))}µs peak`:'';

  // anomalies
  document.getElementById('anom-list').innerHTML=
    (d.anomalies||['None detected']).map(a=>
      `<div class="anom-line ${a==='None detected'?'':'bad'}">${a}</div>`
    ).join('');

  // topology
  const flow=d.flows&&d.flows[0];
  if(flow){
    document.getElementById('path-lbl').textContent='path: '+flow.path.replace(/→/g,'→');
    const inPath=id=>flow.path.toLowerCase().includes(id);
    ['s1','s2','s3','s4'].forEach(sw=>{
      const nc=document.getElementById('nc-'+sw);
      if(!nc)return;
      if(inPath(sw)){
        nc.setAttribute('fill','#0d2035');
        nc.setAttribute('stroke','var(--blue)');
        nc.setAttribute('stroke-width','2');
      } else {
        nc.setAttribute('fill','#1c2a3a');
        nc.setAttribute('stroke','var(--border)');
        nc.setAttribute('stroke-width','1.2');
      }
    });
    // animate active links
    ['lk-h1s1','lk-s1s2','lk-s2s3','lk-s3h2'].forEach(id=>{
      const el=document.getElementById(id);
      if(el)el.className='link-path active';
    });
  }

  // flow table
  document.getElementById('flow-body').innerHTML=
    (d.flows||[]).map(f=>{
      const segs=Math.min(5,Math.ceil(f.queue_pct/20));
      const qhtml='<div class="q-wrap">'+
        Array(segs).fill('<div class="q-seg"></div>').join('')+
        `<span class="q-pct">${f.queue_pct.toFixed(0)}%</span></div>`;
      return `<tr>
        <td>${f.flow}</td>
        <td>${f.path}</td>
        <td>${f.avg_lat_us}µs</td>
        <td>${f.max_lat_us}µs</td>
        <td>${qhtml}</td>
        <td><span class="status-${sc(f.status)}">${f.status}</span></td>
        <td>${f.hop_count}</td>
      </tr>`;
    }).join('')||
    '<tr><td colspan="7" style="color:var(--muted);text-align:center;padding:16px">Waiting for reports…</td></tr>';

  // sync mode buttons
  if(d.traffic_mode!==curMode)setModeUI(d.traffic_mode);

  // log
  if(flow){
    const cls=flow.status==='Critical'?'log-red':flow.status==='Warn'?'log-yellow':'log-green';
    addLog(`RPT lat=${flow.avg_lat_us}µs path=${flow.path}`,cls);
  }
}

async function poll(){
  if(paused)return;
  try{const r=await fetch('/api/state');const d=await r.json();if(d.ready)render(d);}
  catch(e){}
}
setInterval(poll,1000);poll();
addLog('Dashboard connected');
</script>
</body>
</html>"""

# HTTP handler ───────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*a):pass
    def do_GET(self):
        if self.path in('/','index.html'):
            self._send(200,'text/html',HTML.encode())
        elif self.path=='/api/state':
            self._send(200,'application/json',json.dumps(_build_state()).encode())
        else:
            self._send(404,'text/plain',b'Not found')
    def do_POST(self):
        if self.path=='/api/mode':
            length=int(self.headers.get('Content-Length',0))
            body=json.loads(self.rfile.read(length))
            _start_traffic(body.get('mode'))
            self._send(200,'application/json',b'{"ok":true}')
        else:
            self._send(404,'text/plain',b'Not found')
    def _send(self,code,ct,body):
        self.send_response(code)
        self.send_header('Content-Type',ct)
        self.send_header('Content-Length',len(body))
        self.send_header('Access-Control-Allow-Origin','*')
        self.end_headers()
        self.wfile.write(body)

# main ─────────────
def main():
    global _controller
    print('[dashboard] Starting INT controller…')
    _controller=IntController()
    _controller.configure_topology()
    _controller.start_collection()
    threading.Thread(target=_sampler,daemon=True).start()
    port=8080
    server=HTTPServer(('0.0.0.0',port),Handler)
    print(f'[dashboard] http://0.0.0.0:{port}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _start_traffic(None)
        _controller.collector.stop()

if __name__=='__main__':
    main()
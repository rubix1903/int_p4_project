# In-band Network Telemetry (INT) — P4_16 Project

> **"The killer app of P4"** — real-time, packet-level visibility into the network
> fabric that traditional fixed-function switches cannot provide.

---

## What This Project Does

Every packet traveling through the network silently carries a **microscopic flight recorder**.
Each switch stamps its own telemetry into the packet header:

| Metadata | Description |
|---|---|
| `switch_id` | Which switch processed this packet |
| `port_ids` | Ingress and egress port numbers |
| `hop_latency` | Nanoseconds spent inside this switch |
| `queue_occupancy` | How full was the queue when packet arrived |
| `ingress_timestamp` | Nanosecond-precise arrival time |
| `egress_timestamp` | Departure time |

At the **sink node**, this data is stripped from the packet (so the end host sees a clean packet),
and a **telemetry report** is sent to a collector. The result: **complete path visibility**,
hop-by-hop, for every single packet, with nanosecond precision.

Traditional switches can only sample (NetFlow/sFlow) or aggregate (SNMP). INT sees **everything**.

---

## Project Structure

```
int_p4_project/
├── p4src/
│   └── int.p4              # Core P4_16 program (parser → ingress → egress → deparser)
├── controller/
│   └── int_controller.py   # Python: table config + UDP telemetry collector
├── topology/
│   └── int_topology.py     # Mininet topology (4 switches, 2 hosts, 1 collector)
├── scripts/
│   ├── traffic_gen.py      # Scapy traffic generator (steady/burst/multi/tcp modes)
│   └── int_tests.py        # Automated test suite (21 tests, all passing ✓)
└── README.md
```

---

## Architecture

```
                         ┌──────────────────────┐
                         │      S2 (Transit)    │
                         │  Appends hop metadata │
              ┌──────────┤  SW_ID=2, lat, queue ├──────────┐
              │          └──────────────────────┘          │
              │                                            │
 ┌───┐   ┌───┴────────┐                         ┌─────────┴──┐   ┌───┐
 │h1 ├───┤ S1 (Source)│                         │ S3 (Sink)  ├───┤h2 │
 └───┘   │ Stamps INT │                         │ Strip INT  │   └───┘
         │ headers on │                         │ Send report│
         │ h1→h2 flows│                         │ to collect.│
         └───┬────────┘                         └─────────┬──┘
              │          ┌──────────────────────┐          │    ┌───────────┐
              │          │      S4 (Transit)    │          │    │ Collector │
              └──────────┤  Alternate path ECMP ├──────────┘    │  :54321  │
                         └──────────────────────┘               └───────────┘
```

**S1 = INT Source**: Inserts INT shim + header + first hop's metadata into matching packets.
**S2, S4 = INT Transit**: Decrements `remaining_hop_cnt`, prepends its own metadata stack entry.
**S3 = INT Sink**: Adds its metadata, clones packet to collector (mirror session 500), strips INT headers.

---

## INT Header Stack (Wire Format)

```
┌─────────────────────────────────────────────┐
│          Ethernet Header (14B)              │
├─────────────────────────────────────────────┤
│            IPv4 Header (20B)                │
│            DSCP = 0x17 (INT-marked)         │
├─────────────────────────────────────────────┤
│    TCP / UDP Header (20B / 8B)              │
├─────────────────────────────────────────────┤
│      INT Shim Header (4B)                   │
│      int_type=1 | length | orig_dscp        │
├─────────────────────────────────────────────┤
│      INT Header (8B)                        │
│      ver | hop_meta_len | remaining_hops    │
│      instruction_mask (16 bits)             │
├─────────────────────────────────────────────┤
│  ┌──────────────────────────────────────┐   │
│  │  Hop N metadata (most recent first)  │   │
│  │  switch_id (32b)                     │   │
│  │  ingress_port (16b) egress_port(16b) │   │
│  │  hop_latency (32b)  [nanoseconds]    │   │
│  │  q_id (8b) q_occupancy (24b)         │   │
│  │  ingress_timestamp (64b)             │   │
│  └──────────────────────────────────────┘   │
│  ┌──────────────────────────────────────┐   │
│  │  Hop N-1 metadata ...                │   │
│  └──────────────────────────────────────┘   │
│  ...                                        │
├─────────────────────────────────────────────┤
│      INT Tail (4B)                          │
├─────────────────────────────────────────────┤
│      Original Payload                       │
└─────────────────────────────────────────────┘
```

---

## Instruction Bitmap

The `instruction_mask` field (16 bits) controls what each switch collects:

| Bit | Mask   | Field Collected          | Size  |
|-----|--------|--------------------------|-------|
| 15  | 0x8000 | Switch ID                | 4B    |
| 14  | 0x4000 | Ingress + Egress Port IDs| 4B    |
| 13  | 0x2000 | Hop Latency              | 4B    |
| 12  | 0x1000 | Queue Occupancy          | 4B    |
| 11  | 0x0800 | Ingress Timestamp        | 8B    |
| 10  | 0x0400 | Egress Timestamp         | 8B    |
| 9   | 0x0200 | Queue Congestion Status  | 4B    |
| 8   | 0x0100 | Egress Port TX Util      | 4B    |

Default mask `0xFC00` = all 6 standard fields = **20 bytes per hop**.

---

## Running the Project

### 1. Prerequisites

```bash
# Ubuntu 20.04/22.04
sudo apt install -y git python3 python3-pip
pip3 install scapy

# BMv2 (P4 software switch)
git clone https://github.com/p4lang/behavioral-model
cd behavioral-model && ./install_deps.sh && ./autogen.sh
./configure && make -j$(nproc) && sudo make install

# P4C compiler
git clone --recursive https://github.com/p4lang/p4c
cd p4c && mkdir build && cd build
cmake .. && make -j$(nproc) && sudo make install

# Mininet
git clone https://github.com/mininet/mininet
cd mininet && sudo ./util/install.sh -nfv

# p4utils (optional but recommended)
pip3 install p4utils
```

### 2. Compile the P4 Program

```bash
cd int_p4_project
mkdir build
p4c-bm2-ss --p4v 16 \
    --p4runtime-files build/int.p4info.txt \
    -o build/int.json \
    p4src/int.p4
```

### 3. Start the Topology

```bash
sudo python3 topology/int_topology.py --compile
```

### 4. Start the Telemetry Collector (in Mininet CLI)

```
mininet> collector python3 controller/int_controller.py &
```

### 5. Generate Traffic

```bash
# Steady 1000pps flow (watch latency)
mininet> h1 sudo python3 scripts/traffic_gen.py --mode steady --iface h1-eth0

# Burst mode (triggers congestion events)
mininet> h1 sudo python3 scripts/traffic_gen.py --mode burst --pps 5000

# Multi-flow (observe ECMP path diversity)
mininet> h1 sudo python3 scripts/traffic_gen.py --mode multi --flows 8
```

### 6. Run Tests (no hardware required)

```bash
python3 scripts/int_tests.py
# Expected: 21 tests, 0 failures
```

---

## What to Observe

### Path Change Detection
When traffic shifts from S2 to S4 path (ECMP rerouting or link failure simulation),
the controller immediately logs:
```
⚡ PATH CHANGE for 10.0.1.1:12345 → 10.0.3.2:5001 [UDP]:
   OLD: SW1[p1→p2] ▶ SW2[p1→p2] ▶ SW3[p1→p2]
   NEW: SW1[p1→p3] ▶ SW4[p1→p2] ▶ SW3[p1→p2]
```

### Congestion Detection
When burst traffic fills queues, INT reveals exactly *which* switch is congested:
```
🔴 CRITICAL queue at SW2: 94%
```
Traditional monitoring would only show aggregate throughput drop — INT pinpoints the exact hop.

### Latency Breakdown
Every report shows per-hop latency:
```
  Hop 1: SW1 port 1→2 | lat=2.1µs  | q=12
  Hop 2: SW2 port 1→2 | lat=47.8µs | q=923   ← congested!
  Hop 3: SW3 port 1→2 | lat=1.9µs  | q=8
```

---

## Recommended JetBrains IDE

**CLion** is the ideal JetBrains IDE for this project. Here's why:

| Feature | Benefit for INT/P4 |
|---|---|
| C/C++ parser | P4 syntax is C-like; CLion's parser provides best-effort highlighting |
| **File Watcher** | Auto-recompile `int.p4` on save via `p4c-bm2-ss` |
| **Terminal** | Integrated Mininet + BMv2 process management |
| **Python Plugin** | Full IDE support for `int_controller.py`, `traffic_gen.py` |
| **Remote SSH** | Deploy to a Linux VM/server for BMv2 execution |
| Run Configurations | One-click: compile → topology → controller → traffic |
| Database tool | Inspect telemetry reports stored in SQLite/InfluxDB |

### CLion Setup for P4

1. Install **Python** plugin (bundled in CLion 2023+)
2. Create a **File Watcher** (Settings → Tools → File Watchers):
   - File type: `Other`
   - Scope: `p4src/*.p4`
   - Program: `p4c-bm2-ss`
   - Arguments: `--p4v 16 -o build/int.json $FilePath$`
3. Add a `.editorconfig` with `indent_size = 4` for P4 files
4. Create **Run Configurations**:
   - `Compile P4`: shell script calling `p4c-bm2-ss`
   - `INT Tests`: Python → `scripts/int_tests.py`
   - `INT Controller`: Python → `controller/int_controller.py`
   - `Traffic Gen (Steady)`: Python → `scripts/traffic_gen.py --mode steady`

**Alternative**: **PyCharm Professional** if you focus more on the Python controller/analytics
side, with the C/C++ plugin for P4 syntax support.

---

## Why INT Proves P4's Uniqueness

| Capability | SNMP/NetFlow | INT (P4) |
|---|---|---|
| Granularity | Per-interface, per-minute | Per-packet, nanosecond |
| Path visibility | Source/dest only | Every hop |
| Queue depth | Aggregate polls | Real-time per-packet |
| Latency | RTT estimate only | Per-hop breakdown |
| Path changes | Detected on next poll | Instantaneous |
| Congestion location | Unknown (just dropped pkts) | Exact switch + queue |
| Overhead | Separate OOB traffic | Piggybacked on data |

INT is impossible on fixed-function ASICs because inserting/processing arbitrary headers
in the data plane requires programmability. P4 makes it trivial.

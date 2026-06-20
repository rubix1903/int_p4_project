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
**S3 = INT Sink**: Triggers an ingress-to-egress clone to the collector as soon as it recognizes
itself as the sink (so the report reflects the path *up to* S3, not including S3's own hop), then
strips the INT stack from the original packet before it reaches h2.

---

## INT Header Stack (Wire Format)

```
┌─────────────────────────────────────────────┐
│          Ethernet Header (14B)              │
├─────────────────────────────────────────────┤
│            IPv4 Header (20B)                │
│            DSCP = 0x17 (INT-marked)         │
│            protocol = 0xFD while INT present │
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
│  │  egress_timestamp (64b)              │   │
│  └──────────────────────────────────────┘   │
│  ┌──────────────────────────────────────┐   │
│  │  Hop N-1 metadata ...                │   │
│  └──────────────────────────────────────┘   │
│  ...                                        │
├─────────────────────────────────────────────┤
│      INT Tail (4B)                          │
│      next_proto | dest_port | dscp          │
├─────────────────────────────────────────────┤
│   Original TCP / UDP Header (20B / 8B)      │
├─────────────────────────────────────────────┤
│      Original Payload                       │
└─────────────────────────────────────────────┘
```

The original L4 header now sits *after* the INT stack rather than before it - `ipv4.protocol`
gets overwritten with the INT marker (`0xFD`) at the source so every downstream parser knows to
branch into INT parsing instead of treating the shim/header/metadata bytes as a TCP/UDP header.
`int_tail.next_proto` preserves the true protocol so the sink can restore it before the packet
reaches its original destination. See "Issues Found & Fixed" below.

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

Default mask `0xFC00` = all 6 standard fields = **32 bytes per hop** (4+4+4+4+8+8).

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

---

## Issues Found & Fixed

This codebase went through a debugging pass that found and fixed ten separate, interacting
bugs spanning the parser, the egress pipeline, the deparser, and the Python controller. None
of them were syntax errors - everything compiled and ran without crashing, but the telemetry
data was either empty, malformed, or silently never reached the collector at all. Listed
roughly in the order they were found:

1. **Parser only ever extracted a single `switch_id`, once.** `IntParser` had no loop over
   hops and never touched `port_ids`, `hop_latency`, `q_occupancy`, or either timestamp -
   multi-hop parsing was fundamentally broken. Rewritten as a proper looping state machine
   over `parse_int_hop`.

2. **Deparser emitted metadata field-major; the controller decoder assumed hop-major.**
   The original deparser wrote all switch_ids, then all port_ids, etc., across every hop.
   The decoder (and the wire format documented above) expects all of one hop's fields
   together before moving to the next hop. Fixed by unrolling the deparser's emit calls
   per-hop instead of per-field.

3. **`hop_metadata_len` hardcoded to 5 words; the actual field count was 6 (8 once the
   egress timestamp is included).** This threw off every word-count calculation downstream,
   including the decoder's hop-count math. Now set to 8 and computed consistently in both
   the P4 source action and the Python decoder.

4. **Dead `instruction_mask` bit.** The default mask claimed to also collect
   `egress_timestamp`, but no action ever added it. Added
   `int_transit_add_egress_tstamp()` and wired it into the instruction-bitmap branch.

5. **`ipv4.protocol` was never rewritten to mark INT's presence.** This is the most
   fundamental bug in the project: `PROTO_INT_SHIM` (`0xFD`) is defined and the parser's
   `parse_ipv4` state already branches on it, but nothing ever actually *set*
   `hdr.ipv4.protocol = PROTO_INT_SHIM` at the source, or restored the original protocol at
   the sink. Without that rewrite, every switch after the source would see the original
   TCP/UDP protocol number, parse straight past the INT stack as if it were an ordinary L4
   header, and never reach any of the INT parsing logic at all. Fixed by saving the true
   protocol into `int_tail.next_proto` and overwriting `ipv4.protocol` at the source, then
   restoring it from `int_tail.next_proto` at the sink before the INT stack is stripped.
   This also means the original L4 header now sits *after* the INT stack on the wire rather
   than before it (see the updated wire-format diagram above) - the controller's decoder was
   restructured to match.

6. **Queueing metadata copied in ingress, where it isn't valid yet.** `deq_qdepth`,
   `deq_timedelta`, and `enq_qdepth` were being copied from `standard_metadata` during
   ingress processing, but BMv2 only populates those fields once a packet has actually been
   enqueued and dequeued - i.e. from egress onward. Every hop's reported latency and queue
   occupancy was always 0. Fixed by reading `standard_metadata` directly in the egress
   actions that use these fields, instead of going through a stale ingress-time copy.

7. **Report clone used `E2E` (egress-to-egress) instead of `I2E`.** The sink cloned the
   packet to the collector and then stripped the INT headers in the same egress pass,
   assuming the clone had already captured a snapshot. BMv2's E2E clone actually snapshots
   packet state at the *end* of egress processing - by which point the strip had already
   happened, so the report arriving at the collector was always empty. Switched to an `I2E`
   clone, requested from ingress the moment the sink role is recognized; `I2E` snapshots the
   packet as it looked on arrival, before this switch's own modifications. The tradeoff
   (confirmed against a working reference INT implementation using the same pattern) is that
   the sink's own hop isn't included in the report - only the hops upstream of it.

8. **No outer encapsulation around the report.** The cloned "report" packet was just the
   original packet, unmodified and still addressed to its original destination - it was
   never going to reach the collector's socket. Added `report_eth` / `report_ipv4` /
   `report_udp` headers plus `report_group_header_t` / `report_individual_header_t`,
   populated from a new `int_report_config` table (keyed on `sink == 1`) that needs a
   `table_add` entry on the sink switch - see `topology/s3_commands.txt`.

9. **Controller listened on a normal UDP socket; the report can't get there that way.**
   `IntCollector` bound an `AF_INET`/`SOCK_DGRAM` socket, but a mirrored switch frame isn't
   delivered through the host's IP/UDP stack the way a normal application packet is. Fixed
   by switching to a raw `AF_PACKET`/`SOCK_RAW` socket bound to the collector's interface
   (`col-eth0`), with a small pre-filter so only frames addressed to the right UDP port get
   handed to the decoder.

10. **Dead code removed**: the unused `int_metadata_insert` table and `set_mirror_session()`
    action were never reachable from `apply()` and have been deleted.

**Validation:** all 21 tests in `scripts/int_tests.py` pass, and the test fixtures themselves
were updated to build packets in the real wire format above rather than the old, inconsistent
one - several previously just asserted "decoder didn't crash" without checking that the
decoded values were actually correct. A standalone byte-level test was also used during
debugging to confirm exact field-for-field round-tripping across a multi-hop path. This has
**not** been validated against a live BMv2/p4c compile (the sandbox used for this pass
couldn't build BMv2's full toolchain) - run `p4c-bm2-ss` against `p4src/int.p4` before
deploying to a real topology.
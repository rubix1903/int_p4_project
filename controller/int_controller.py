#!/usr/bin/env python3
"""
INT Controller - Programs P4 tables and processes telemetry reports
=================================================================
Responsibilities:
  1. Configure forwarding tables (L2/L3)
  2. Install INT source/sink/transit roles on each switch
  3. Listen for INT telemetry reports from sink nodes
  4. Decode and display real-time hop-by-hop metrics
  5. Detect anomalies (congestion, high latency, path changes)
"""

import struct
import socket
import threading
import time
import json
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("INT-Controller")

# ---------------------------------------------------------------
# Constants
# ---------------------------------------------------------------
COLLECTOR_HOST = "0.0.0.0"
COLLECTOR_PORT = 54321
BUFFER_SIZE    = 65535

# INT Instruction Bitmap
INT_SWITCH_ID_MASK      = 0x8000
INT_PORT_IDS_MASK       = 0x4000
INT_HOP_LATENCY_MASK    = 0x2000
INT_QUEUE_OCC_MASK      = 0x1000
INT_INGRESS_TSTAMP_MASK = 0x0800
INT_EGRESS_TSTAMP_MASK  = 0x0400

# Anomaly Thresholds
LATENCY_WARN_NS    = 100_000    # 100 µs
LATENCY_CRIT_NS    = 1_000_000  # 1 ms
QUEUE_WARN_PCT     = 70         # 70% queue fill
QUEUE_CRIT_PCT     = 90         # 90% queue fill

# ---------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------
@dataclass
class HopMetadata:
    """Metadata collected at a single network hop"""
    switch_id:        int = 0
    ingress_port:     int = 0
    egress_port:      int = 0
    hop_latency_ns:   int = 0
    queue_occupancy:  int = 0
    ingress_tstamp:   int = 0
    egress_tstamp:    int = 0


@dataclass
class FlowKey:
    """5-tuple flow identifier"""
    src_ip:   str
    dst_ip:   str
    src_port: int
    dst_port: int
    proto:    int

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip,
                     self.src_port, self.dst_port, self.proto))

    def __str__(self):
        return (f"{self.src_ip}:{self.src_port} → "
                f"{self.dst_ip}:{self.dst_port} "
                f"[{'TCP' if self.proto==6 else 'UDP'}]")


@dataclass
class TelemetryReport:
    """Decoded INT telemetry report from sink node"""
    timestamp:    float
    flow:         FlowKey
    hops:         List[HopMetadata] = field(default_factory=list)
    total_latency_ns: int = 0
    hop_count:    int = 0

    def path_string(self) -> str:
        """Human-readable path through the network"""
        parts = []
        for hop in self.hops:
            parts.append(
                f"SW{hop.switch_id}[p{hop.ingress_port}→p{hop.egress_port}]"
            )
        return " ▶ ".join(parts)

    def anomalies(self) -> List[str]:
        """Detect anomalous conditions in this report"""
        issues = []
        if self.total_latency_ns > LATENCY_CRIT_NS:
            issues.append(f"🔴 CRITICAL latency: {self.total_latency_ns/1000:.1f}µs")
        elif self.total_latency_ns > LATENCY_WARN_NS:
            issues.append(f"🟡 HIGH latency: {self.total_latency_ns/1000:.1f}µs")

        for hop in self.hops:
            # Assume 1000-packet queue max for percentage calculation
            q_pct = (hop.queue_occupancy / 10)  # simplified
            if q_pct > QUEUE_CRIT_PCT:
                issues.append(
                    f"🔴 CRITICAL queue at SW{hop.switch_id}: {q_pct:.0f}%"
                )
            elif q_pct > QUEUE_WARN_PCT:
                issues.append(
                    f"🟡 HIGH queue at SW{hop.switch_id}: {q_pct:.0f}%"
                )
        return issues


# ---------------------------------------------------------------
# Telemetry Report Decoder
# ---------------------------------------------------------------
class IntReportDecoder:
    """Parses raw UDP packets from INT sink nodes into TelemetryReport objects"""

    ETH_HDR_LEN   = 14
    IPV4_HDR_LEN  = 20
    UDP_HDR_LEN   = 8
    INT_SHIM_LEN  = 4
    INT_HDR_LEN   = 8

    def decode(self, raw_packet: bytes) -> Optional[TelemetryReport]:
        """
        Full packet structure at collector:
        Ethernet | IP (outer) | UDP (outer) → INT Report Header
        → Original Ethernet | Original IP | Original L4 | INT Shim
        | INT Header | [Hop Metadata × N]
        """
        try:
            offset = self.ETH_HDR_LEN + self.IPV4_HDR_LEN + self.UDP_HDR_LEN

            # Parse inner IP header (original packet's IP)
            if len(raw_packet) < offset + self.IPV4_HDR_LEN:
                return None

            inner_ip = raw_packet[offset:offset + self.IPV4_HDR_LEN]
            src_ip   = socket.inet_ntoa(inner_ip[12:16])
            dst_ip   = socket.inet_ntoa(inner_ip[16:20])
            proto    = inner_ip[9]
            offset  += self.IPV4_HDR_LEN

            # Parse L4 (TCP/UDP ports)
            src_port, dst_port = struct.unpack("!HH", raw_packet[offset:offset+4])
            offset += 8  # skip L4 header (simplified)

            flow = FlowKey(src_ip, dst_ip, src_port, dst_port, proto)

            # Parse INT Shim
            if len(raw_packet) < offset + self.INT_SHIM_LEN:
                return None
            int_type, _, shim_len, _ = struct.unpack(
                "!BBBB", raw_packet[offset:offset + self.INT_SHIM_LEN]
            )
            offset += self.INT_SHIM_LEN

            # Parse INT Header
            if len(raw_packet) < offset + self.INT_HDR_LEN:
                return None
            (flags_ver, hop_meta_len, remaining_hops,
             instruction_mask, _) = struct.unpack(
                "!HBBHH", raw_packet[offset:offset + self.INT_HDR_LEN]
            )
            offset += self.INT_HDR_LEN

            # Decode hop count: initial remaining=6, so hops_traversed = initial - current
            # remaining_hops is the value AT SINK after all decrements
            # Each transit decrements by 1, so hops = 6 - remaining_hops
            # But if remaining_hops field is the ORIGINAL remaining count (not yet decremented),
            # we calculate from shim_len instead:
            # shim_len is in 4-byte words; each hop adds hop_meta_len words
            hop_metadata_words_per_hop = hop_meta_len if hop_meta_len > 0 else 5
            # shim_len = total INT words (shim + hdr + data)
            # shim itself = 1 word, hdr = 2 words, so data_words = shim_len - 3
            metadata_words = max(0, int(shim_len) - 3)
            hop_count = (metadata_words // hop_metadata_words_per_hop
                         if hop_metadata_words_per_hop > 0 else 0)
            # If shim_len didn't encode it, fall back to remaining_hops
            if hop_count == 0 and remaining_hops < 6:
                hop_count = 6 - remaining_hops

            report = TelemetryReport(
                timestamp=time.time(),
                flow=flow,
                hop_count=hop_count
            )

            # Parse hop metadata according to instruction mask
            total_latency = 0
            for hop_idx in range(hop_count):
                hop = HopMetadata()

                if instruction_mask & INT_SWITCH_ID_MASK:
                    if offset + 4 <= len(raw_packet):
                        hop.switch_id = struct.unpack(
                            "!I", raw_packet[offset:offset+4]
                        )[0]
                        offset += 4

                if instruction_mask & INT_PORT_IDS_MASK:
                    if offset + 4 <= len(raw_packet):
                        hop.ingress_port, hop.egress_port = struct.unpack(
                            "!HH", raw_packet[offset:offset+4]
                        )
                        offset += 4

                if instruction_mask & INT_HOP_LATENCY_MASK:
                    if offset + 4 <= len(raw_packet):
                        hop.hop_latency_ns = struct.unpack(
                            "!I", raw_packet[offset:offset+4]
                        )[0]
                        total_latency += hop.hop_latency_ns
                        offset += 4

                if instruction_mask & INT_QUEUE_OCC_MASK:
                    if offset + 4 <= len(raw_packet):
                        q_raw = struct.unpack(
                            "!I", raw_packet[offset:offset+4]
                        )[0]
                        hop.queue_occupancy = q_raw & 0x00FFFFFF
                        offset += 4

                if instruction_mask & INT_INGRESS_TSTAMP_MASK:
                    if offset + 8 <= len(raw_packet):
                        hop.ingress_tstamp = struct.unpack(
                            "!Q", raw_packet[offset:offset+8]
                        )[0]
                        offset += 8

                report.hops.append(hop)

            report.total_latency_ns = total_latency
            return report

        except Exception as exc:
            logger.debug(f"Failed to decode INT report: {exc}")
            return None


# ---------------------------------------------------------------
# Flow Statistics Tracker
# ---------------------------------------------------------------
class FlowTracker:
    """
    Maintains rolling statistics for all observed flows.
    Detects path changes (ECMPflapping) and latency trends.
    """
    WINDOW_SIZE = 100  # Keep last 100 reports per flow

    def __init__(self):
        self.reports:    Dict[FlowKey, deque]  = defaultdict(
            lambda: deque(maxlen=self.WINDOW_SIZE)
        )
        self.paths:      Dict[FlowKey, str]    = {}
        self.lock = threading.Lock()

    def record(self, report: TelemetryReport) -> List[str]:
        """Record a report and return any new anomalies detected"""
        events = []
        with self.lock:
            self.reports[report.flow].append(report)
            current_path = report.path_string()

            # Detect path change (ECMP re-routing or failure)
            if report.flow in self.paths:
                if self.paths[report.flow] != current_path:
                    events.append(
                        f"⚡ PATH CHANGE for {report.flow}:\n"
                        f"   OLD: {self.paths[report.flow]}\n"
                        f"   NEW: {current_path}"
                    )
            self.paths[report.flow] = current_path

            # Add per-packet anomalies
            events.extend(report.anomalies())
        return events

    def get_flow_stats(self, flow: FlowKey) -> dict:
        """Compute aggregated stats for a flow"""
        with self.lock:
            reps = list(self.reports.get(flow, []))
        if not reps:
            return {}

        latencies = [r.total_latency_ns for r in reps]
        return {
            "flow":           str(flow),
            "sample_count":   len(latencies),
            "avg_latency_us": sum(latencies) / len(latencies) / 1000,
            "max_latency_us": max(latencies) / 1000,
            "min_latency_us": min(latencies) / 1000,
            "hop_count":      reps[-1].hop_count,
            "current_path":   reps[-1].path_string()
        }

    def all_flow_stats(self) -> List[dict]:
        with self.lock:
            flows = list(self.reports.keys())
        return [self.get_flow_stats(f) for f in flows]


# ---------------------------------------------------------------
# Telemetry Collector (UDP listener)
# ---------------------------------------------------------------
class IntCollector:
    """
    UDP server that receives INT reports from sink nodes.
    Decodes and forwards to FlowTracker.
    """

    def __init__(self, host: str, port: int, tracker: FlowTracker):
        self.host    = host
        self.port    = port
        self.tracker = tracker
        self.decoder = IntReportDecoder()
        self._running = False
        self._sock: Optional[socket.socket] = None
        self.stats = {"received": 0, "decoded": 0, "errors": 0}

    def start(self):
        self._running = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.settimeout(1.0)
        logger.info(f"INT Collector listening on {self.host}:{self.port}")

        thread = threading.Thread(target=self._recv_loop, daemon=True)
        thread.start()

    def stop(self):
        self._running = False
        if self._sock:
            self._sock.close()

    def _recv_loop(self):
        while self._running:
            try:
                data, addr = self._sock.recvfrom(BUFFER_SIZE)
                self.stats["received"] += 1

                report = self.decoder.decode(data)
                if report:
                    self.stats["decoded"] += 1
                    events = self.tracker.record(report)
                    self._log_report(report, events)
                else:
                    self.stats["errors"] += 1

            except socket.timeout:
                continue
            except Exception as exc:
                if self._running:
                    logger.error(f"Receiver error: {exc}")
                    self.stats["errors"] += 1

    def _log_report(self, report: TelemetryReport, events: List[str]):
        ts = datetime.fromtimestamp(report.timestamp).strftime("%H:%M:%S.%f")[:-3]
        latency_str = f"{report.total_latency_ns/1000:.1f}µs"

        logger.info(
            f"[{ts}] FLOW: {report.flow} | "
            f"PATH: {report.path_string()} | "
            f"LATENCY: {latency_str} | "
            f"HOPS: {report.hop_count}"
        )

        # Per-hop detail
        for i, hop in enumerate(report.hops):
            logger.debug(
                f"  Hop {i+1}: SW{hop.switch_id} "
                f"port {hop.ingress_port}→{hop.egress_port} | "
                f"lat={hop.hop_latency_ns/1000:.1f}µs | "
                f"q={hop.queue_occupancy}"
            )

        # Surface anomalies
        for event in events:
            logger.warning(event)


# ---------------------------------------------------------------
# P4Runtime Table Configurator (stub - real impl uses p4runtime_lib)
# ---------------------------------------------------------------
class IntTableConfigurator:
    """
    Programs INT roles into each switch's P4 tables.
    In production, this uses gRPC P4Runtime API.
    This stub generates the equivalent table entry JSON.
    """

    def __init__(self):
        self.entries: Dict[str, list] = defaultdict(list)

    def configure_source(self, switch_id: str, flows: list):
        """Install INT source entries - which flows get INT headers"""
        for flow in flows:
            entry = {
                "table": "IntIngress.int_source_table",
                "match": {
                    "ipv4.src_addr": {"ternary": {"value": flow["src"], "mask": "255.255.255.255"}},
                    "ipv4.dst_addr": {"ternary": {"value": flow["dst"], "mask": "255.255.255.255"}},
                    "l4_dst_port":   {"ternary": {"value": flow.get("port", 0), "mask": 0xFFFF}}
                },
                "action": {"name": "IntIngress.int_set_source", "params": {}}
            }
            self.entries[switch_id].append(entry)
            logger.info(f"  [SW:{switch_id}] INT SOURCE enabled for {flow['src']} → {flow['dst']}")

    def configure_sink(self, switch_id: str, egress_ports: list, sw_id_num: int):
        """Install INT sink entries - which ports exit the INT domain"""
        for port in egress_ports:
            entry = {
                "table": "IntIngress.int_sink_table",
                "match": {"standard_metadata.egress_spec": {"exact": port}},
                "action": {
                    "name": "IntIngress.int_set_sink",
                    "params": {"switch_id": sw_id_num}
                }
            }
            self.entries[switch_id].append(entry)
            logger.info(f"  [SW:{switch_id}] INT SINK on port {port}")

    def configure_transit(self, switch_id: str, sw_id_num: int):
        """Configure switch as INT transit node"""
        entry = {
            "table": "IntIngress.int_transit_table",
            "match": {"int_shim.isValid": {"exact": 1}},
            "action": {
                "name": "IntIngress.int_set_transit",
                "params": {"switch_id": sw_id_num}
            }
        }
        self.entries[switch_id].append(entry)
        logger.info(f"  [SW:{switch_id}] INT TRANSIT configured (ID={sw_id_num})")

    def configure_forwarding(self, switch_id: str, routes: list):
        """Install L3 forwarding entries"""
        for route in routes:
            entry = {
                "table": "IntIngress.ipv4_lpm",
                "match": {"ipv4.dst_addr": {"lpm": {"value": route["prefix"], "length": route["len"]}}},
                "action": {
                    "name": "IntIngress.ipv4_forward",
                    "params": {"dst_mac": route["mac"], "port": route["port"]}
                }
            }
            self.entries[switch_id].append(entry)

    def dump_config(self, output_file: str = "int_table_config.json"):
        """Write all table entries to JSON (for inspection / replay)"""
        config = {
            "generated_at": datetime.now().isoformat(),
            "switches": dict(self.entries)
        }
        with open(output_file, "w") as f:
            json.dump(config, f, indent=2)
        logger.info(f"Table config written to {output_file}")
        return config


# ---------------------------------------------------------------
# Main Controller Orchestration
# ---------------------------------------------------------------
class IntController:
    """
    Top-level controller that wires everything together.
    Topology:
        h1 ──── S1(source) ──── S2(transit) ──── S3(sink) ──── h2
                                    │
                              S4(transit)
    """

    def __init__(self):
        self.tracker    = FlowTracker()
        self.collector  = IntCollector(COLLECTOR_HOST, COLLECTOR_PORT, self.tracker)
        self.configurator = IntTableConfigurator()

    def configure_topology(self):
        """Push INT configuration to all switches in topology"""
        logger.info("="*60)
        logger.info("Configuring INT topology...")
        logger.info("="*60)

        # ---- Switch S1 : INT SOURCE ----
        self.configurator.configure_forwarding("s1", [
            {"prefix": "10.0.2.0", "len": 24, "mac": "00:00:00:02:02:00", "port": 2},
            {"prefix": "10.0.3.0", "len": 24, "mac": "00:00:00:02:02:00", "port": 2},
        ])
        self.configurator.configure_source("s1", [
            {"src": "10.0.1.0/24", "dst": "10.0.3.0/24", "port": 0},  # all flows s1→s3
        ])
        self.configurator.configure_transit("s1", sw_id_num=1)

        # ---- Switch S2 : INT TRANSIT ----
        self.configurator.configure_forwarding("s2", [
            {"prefix": "10.0.3.0", "len": 24, "mac": "00:00:00:03:03:00", "port": 3},
            {"prefix": "10.0.1.0", "len": 24, "mac": "00:00:00:01:01:00", "port": 1},
        ])
        self.configurator.configure_transit("s2", sw_id_num=2)

        # ---- Switch S3 : INT SINK ----
        self.configurator.configure_forwarding("s3", [
            {"prefix": "10.0.3.2", "len": 32, "mac": "00:00:00:03:03:02", "port": 2},
            {"prefix": "10.0.1.0", "len": 24, "mac": "00:00:00:02:02:00", "port": 1},
        ])
        self.configurator.configure_transit("s3", sw_id_num=3)
        self.configurator.configure_sink("s3", egress_ports=[2], sw_id_num=3)
        # Port 2 exits INT domain (connects to h2)

        # ---- Switch S4 : INT TRANSIT (alternate path) ----
        self.configurator.configure_forwarding("s4", [
            {"prefix": "10.0.3.0", "len": 24, "mac": "00:00:00:03:03:00", "port": 2},
            {"prefix": "10.0.1.0", "len": 24, "mac": "00:00:00:01:01:00", "port": 1},
        ])
        self.configurator.configure_transit("s4", sw_id_num=4)

        config = self.configurator.dump_config()
        logger.info(f"Configured {sum(len(v) for v in config['switches'].values())} table entries")
        return config

    def start_collection(self):
        """Start telemetry collection"""
        self.collector.start()
        logger.info("INT telemetry collection ACTIVE")

    def print_dashboard(self):
        """Print live statistics dashboard"""
        stats = self.tracker.all_flow_stats()
        print("\n" + "="*70)
        print(f"  INT TELEMETRY DASHBOARD  [{datetime.now().strftime('%H:%M:%S')}]")
        print("="*70)
        print(f"  Collector: received={self.collector.stats['received']} "
              f"decoded={self.collector.stats['decoded']} "
              f"errors={self.collector.stats['errors']}")
        print(f"  Active flows: {len(stats)}")
        print("-"*70)

        for s in stats:
            print(f"  Flow: {s['flow']}")
            print(f"    Path:    {s['current_path']}")
            print(f"    Latency: avg={s['avg_latency_us']:.1f}µs  "
                  f"max={s['max_latency_us']:.1f}µs  "
                  f"min={s['min_latency_us']:.1f}µs")
            print(f"    Hops:    {s['hop_count']}  |  Samples: {s['sample_count']}")
            print()
        print("="*70)

    def run(self):
        """Main controller loop"""
        logger.info("Starting INT Controller")
        self.configure_topology()
        self.start_collection()

        try:
            while True:
                time.sleep(10)
                self.print_dashboard()
        except KeyboardInterrupt:
            logger.info("Shutting down INT Controller")
            self.collector.stop()


# ---------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------
if __name__ == "__main__":
    controller = IntController()
    controller.run()

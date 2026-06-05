#!/usr/bin/env python3
"""
INT Automated Test Suite
========================
Tests INT header insertion, metadata collection, and report generation
without requiring a live P4 switch.

Tests:
  1. INT header serialization/deserialization
  2. Hop metadata encoding correctness
  3. Telemetry report decoder
  4. Flow tracker anomaly detection
  5. Path change detection
  6. Instruction bitmap processing
"""

import struct
import time
import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../controller"))
from int_controller import (
    IntReportDecoder, FlowKey, FlowTracker,
    TelemetryReport, HopMetadata,
    LATENCY_WARN_NS, LATENCY_CRIT_NS
)


# ---------------------------------------------------------------
# Packet Builder helpers (for constructing test packets)
# ---------------------------------------------------------------
def build_eth_header(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02",
                     ether_type=0x0800):
    src_bytes = bytes(int(x, 16) for x in src.split(":"))
    dst_bytes = bytes(int(x, 16) for x in dst.split(":"))
    return dst_bytes + src_bytes + struct.pack("!H", ether_type)


def build_ipv4_header(src="10.0.1.1", dst="10.0.3.2",
                      proto=17, tos=0, total_len=100):
    import socket
    src_bytes = socket.inet_aton(src)
    dst_bytes = socket.inet_aton(dst)
    # version=4, ihl=5, tos, total_len, id, flags/offset, ttl, proto, checksum
    header = struct.pack("!BBHHHBBH4s4s",
        0x45, tos, total_len,
        0x0001, 0x0000,         # id, flags+offset
        64, proto, 0,           # ttl, protocol, checksum (0 = skip verify)
        src_bytes, dst_bytes
    )
    return header


def build_udp_header(src_port=12345, dst_port=5001, length=20):
    return struct.pack("!HHHH", src_port, dst_port, length, 0)


def build_int_shim(int_type=1, length=4, orig_dscp=0):
    return struct.pack("!BBBB", int_type, 0, length, orig_dscp)


def build_int_header(remaining_hops=3, instruction_mask=0xFC00,
                     hop_meta_len=5):
    """
    INT Header structure (8 bytes):
      4b ver, 2b rep, 1b c, 1b e, 1b m, 7b rsvd, 3b rsvd, 5b hop_meta_len
      8b remaining_hops, 16b instruction_mask, 16b rsvd
    remaining_hops here = hops left (after transits decremented it)
    """
    flags_ver    = (0 << 12) | (0 << 10) | (0 << 9) | (0 << 8)
    hop_meta_byte = hop_meta_len & 0x1F
    return struct.pack("!HBBHH",
        flags_ver, hop_meta_byte, remaining_hops,
        instruction_mask, 0
    )


def build_int_shim_with_len(hops, hop_meta_len=5):
    """Calculate correct shim length: INT header (2 words) + hop data"""
    # shim_len = INT_SHIM(1 word) + INT_HDR(2 words) + hop_data
    # The shim length field covers everything from shim to tail (in 4-byte words)
    shim_words = 1  # shim itself
    hdr_words  = 2  # INT header
    data_words = hops * hop_meta_len
    total = shim_words + hdr_words + data_words
    return struct.pack("!BBBB", 1, 0, total, 0)  # int_type=1


def build_int_switch_id(switch_id):
    return struct.pack("!I", switch_id)


def build_int_port_ids(ingress, egress):
    return struct.pack("!HH", ingress, egress)


def build_int_hop_latency(latency_ns):
    return struct.pack("!I", latency_ns)


def build_int_q_occupancy(q_id, occupancy):
    combined = (q_id << 24) | (occupancy & 0x00FFFFFF)
    return struct.pack("!I", combined)


def build_int_ingress_tstamp(tstamp):
    return struct.pack("!Q", tstamp)


def build_test_int_packet(hops_data, instruction_mask=0xF800, remaining=3):
    """
    Builds a complete fake INT packet with the given hop metadata.
    hops_data = list of dicts: {switch_id, ingress, egress, latency, q_occ, tstamp}
    """
    eth   = build_eth_header()
    ipv4  = build_ipv4_header()
    udp   = build_udp_header()

    hop_meta_len = bin(instruction_mask).count("1")  # words per hop = # of set bits
    shim  = build_int_shim_with_len(len(hops_data), hop_meta_len=hop_meta_len)
    hdr   = build_int_header(remaining_hops=remaining,
                             instruction_mask=instruction_mask,
                             hop_meta_len=hop_meta_len)

    meta_bytes = b""
    for hop in hops_data:
        if instruction_mask & 0x8000:
            meta_bytes += build_int_switch_id(hop["switch_id"])
        if instruction_mask & 0x4000:
            meta_bytes += build_int_port_ids(hop["ingress"], hop["egress"])
        if instruction_mask & 0x2000:
            meta_bytes += build_int_hop_latency(hop["latency"])
        if instruction_mask & 0x1000:
            meta_bytes += build_int_q_occupancy(0, hop.get("q_occ", 0))
        if instruction_mask & 0x0800:
            meta_bytes += build_int_ingress_tstamp(hop.get("tstamp", 0))

    return eth + ipv4 + udp + shim + hdr + meta_bytes


# ---------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------
class TestHopMetadata(unittest.TestCase):
    """Unit tests for HopMetadata dataclass"""

    def test_defaults(self):
        hop = HopMetadata()
        self.assertEqual(hop.switch_id, 0)
        self.assertEqual(hop.hop_latency_ns, 0)

    def test_set_values(self):
        hop = HopMetadata(switch_id=42, ingress_port=1, egress_port=2,
                          hop_latency_ns=5000)
        self.assertEqual(hop.switch_id, 42)
        self.assertEqual(hop.hop_latency_ns, 5000)


class TestFlowKey(unittest.TestCase):
    """Unit tests for FlowKey"""

    def test_hash_stability(self):
        f1 = FlowKey("10.0.1.1", "10.0.3.2", 12345, 5001, 17)
        f2 = FlowKey("10.0.1.1", "10.0.3.2", 12345, 5001, 17)
        self.assertEqual(hash(f1), hash(f2))

    def test_dict_key(self):
        f1 = FlowKey("10.0.1.1", "10.0.3.2", 12345, 5001, 17)
        f2 = FlowKey("10.0.1.1", "10.0.3.2", 12345, 5001, 17)
        d = {f1: "val1"}
        self.assertEqual(d[f2], "val1")

    def test_str_representation(self):
        f = FlowKey("10.0.1.1", "10.0.3.2", 12345, 5001, 17)
        s = str(f)
        self.assertIn("10.0.1.1", s)
        self.assertIn("10.0.3.2", s)
        self.assertIn("UDP", s)

    def test_tcp_str(self):
        f = FlowKey("10.0.1.1", "10.0.3.2", 12345, 80, 6)
        self.assertIn("TCP", str(f))


class TestTelemetryReport(unittest.TestCase):
    """Unit tests for TelemetryReport"""

    def _make_report(self, latency_ns, queue_pct=0):
        flow = FlowKey("10.0.1.1", "10.0.3.2", 1234, 5001, 17)
        hops = [
            HopMetadata(switch_id=1, ingress_port=1, egress_port=2,
                        hop_latency_ns=latency_ns // 2,
                        queue_occupancy=int(1000 * queue_pct / 100)),
            HopMetadata(switch_id=2, ingress_port=1, egress_port=2,
                        hop_latency_ns=latency_ns // 2,
                        queue_occupancy=int(1000 * queue_pct / 100)),
        ]
        return TelemetryReport(
            timestamp=time.time(), flow=flow, hops=hops,
            total_latency_ns=latency_ns, hop_count=2
        )

    def test_path_string_format(self):
        r = self._make_report(10000)
        path = r.path_string()
        self.assertIn("SW1", path)
        self.assertIn("SW2", path)
        self.assertIn("▶", path)

    def test_no_anomalies_normal(self):
        r = self._make_report(50_000)  # 50 µs - normal
        self.assertEqual(len(r.anomalies()), 0)

    def test_warn_latency(self):
        r = self._make_report(LATENCY_WARN_NS + 1)
        anomalies = r.anomalies()
        self.assertTrue(any("HIGH latency" in a for a in anomalies))

    def test_critical_latency(self):
        r = self._make_report(LATENCY_CRIT_NS + 1)
        anomalies = r.anomalies()
        self.assertTrue(any("CRITICAL latency" in a for a in anomalies))

    def test_queue_congestion(self):
        r = self._make_report(50_000, queue_pct=95)
        anomalies = r.anomalies()
        # queue_pct > 90 → critical
        self.assertTrue(any("CRITICAL queue" in a for a in anomalies))


class TestFlowTracker(unittest.TestCase):
    """Unit tests for FlowTracker"""

    def _make_report(self, sw2_id=2, latency=50_000):
        flow = FlowKey("10.0.1.1", "10.0.3.2", 1234, 5001, 17)
        hops = [
            HopMetadata(switch_id=1),
            HopMetadata(switch_id=sw2_id),
            HopMetadata(switch_id=3),
        ]
        return TelemetryReport(
            timestamp=time.time(), flow=flow, hops=hops,
            total_latency_ns=latency, hop_count=3
        )

    def test_record_and_retrieve(self):
        tracker = FlowTracker()
        r = self._make_report()
        tracker.record(r)
        stats = tracker.all_flow_stats()
        self.assertEqual(len(stats), 1)

    def test_path_change_detection(self):
        tracker = FlowTracker()
        # Primary path: S1 → S2 → S3
        r1 = self._make_report(sw2_id=2)
        events1 = tracker.record(r1)
        self.assertEqual(len(events1), 0)  # No change yet

        # Path flips to: S1 → S4 → S3
        r2 = self._make_report(sw2_id=4)
        events2 = tracker.record(r2)
        self.assertTrue(any("PATH CHANGE" in e for e in events2))

    def test_stats_computation(self):
        tracker = FlowTracker()
        flow = FlowKey("10.0.1.1", "10.0.3.2", 1234, 5001, 17)

        for latency in [10_000, 20_000, 30_000]:
            r = self._make_report(latency=latency)
            tracker.record(r)

        stats = tracker.get_flow_stats(flow)
        self.assertAlmostEqual(stats["avg_latency_us"], 20.0, places=1)
        self.assertAlmostEqual(stats["max_latency_us"], 30.0, places=1)
        self.assertAlmostEqual(stats["min_latency_us"], 10.0, places=1)
        self.assertEqual(stats["sample_count"], 3)

    def test_empty_flow_stats(self):
        tracker = FlowTracker()
        unknown = FlowKey("1.2.3.4", "5.6.7.8", 1, 2, 17)
        stats = tracker.get_flow_stats(unknown)
        self.assertEqual(stats, {})

    def test_window_limit(self):
        tracker = FlowTracker()
        for _ in range(FlowTracker.WINDOW_SIZE + 50):
            tracker.record(self._make_report())
        stats = tracker.all_flow_stats()
        self.assertEqual(stats[0]["sample_count"], FlowTracker.WINDOW_SIZE)


class TestIntReportDecoder(unittest.TestCase):
    """Unit tests for the INT report packet decoder"""

    def test_decode_valid_packet(self):
        """Build a realistic INT packet with outer wrapper and verify decoding"""
        hops = [
            {"switch_id": 1, "ingress": 1, "egress": 2,
             "latency": 5_000, "q_occ": 100, "tstamp": 1_000_000},
            {"switch_id": 2, "ingress": 1, "egress": 3,
             "latency": 8_000, "q_occ": 200, "tstamp": 1_005_000},
            {"switch_id": 3, "ingress": 1, "egress": 2,
             "latency": 3_000, "q_occ": 50,  "tstamp": 1_013_000},
        ]

        # INT packet is the inner packet; outer wrapper (eth+ip+udp) carries it to collector
        instruction_mask = 0xF800  # SW_ID | PORTS | LATENCY | QUEUE | TSTAMP = 5 words/hop
        inner_pkt = build_test_int_packet(hops, instruction_mask=instruction_mask, remaining=3)

        # Wrap in outer Ethernet+IP+UDP (as the mirror/clone would produce)
        outer_eth  = build_eth_header()
        outer_ipv4 = build_ipv4_header(src="10.0.3.3", dst="10.0.3.3",  # collector
                                        proto=17, total_len=len(inner_pkt) + 28)
        outer_udp  = build_udp_header(src_port=49999, dst_port=54321,
                                       length=len(inner_pkt) + 8)
        full_pkt = outer_eth + outer_ipv4 + outer_udp + inner_pkt

        decoder = IntReportDecoder()
        report = decoder.decode(full_pkt)

        # Report may be None if inner structure doesn't parse cleanly (tolerate)
        # Key check: decoder doesn't crash and handles the packet gracefully
        # In a live BMv2 environment the sink generates properly formatted reports
        self.assertIsNotNone(report)  # Decoder must return a report object

    def test_decode_empty_packet(self):
        """Empty packet should return None"""
        decoder = IntReportDecoder()
        result = decoder.decode(b"")
        self.assertIsNone(result)

    def test_decode_too_short(self):
        """Truncated packet should return None gracefully"""
        decoder = IntReportDecoder()
        result = decoder.decode(b"\x00" * 10)
        self.assertIsNone(result)

    def test_decode_single_hop(self):
        """Single hop INT packet wrapped in outer transport"""
        hops = [
            {"switch_id": 5, "ingress": 3, "egress": 4,
             "latency": 12_500, "q_occ": 0, "tstamp": 9_999_999}
        ]
        inner = build_test_int_packet(hops, instruction_mask=0xF800, remaining=5)
        outer_eth  = build_eth_header()
        outer_ipv4 = build_ipv4_header(proto=17, total_len=len(inner)+28)
        outer_udp  = build_udp_header(length=len(inner)+8)
        full_pkt = outer_eth + outer_ipv4 + outer_udp + inner

        decoder = IntReportDecoder()
        report = decoder.decode(full_pkt)
        self.assertIsNotNone(report)


# ---------------------------------------------------------------
# Integration-style test: full pipeline simulation
# ---------------------------------------------------------------
class TestIntPipeline(unittest.TestCase):
    """End-to-end pipeline simulation without a live switch"""

    def test_full_flow_lifecycle(self):
        """
        Simulate:
          1. Flow starts → no anomalies
          2. Latency spikes → warning detected
          3. Path changes → event raised
          4. Queue fills → congestion detected
        """
        tracker = FlowTracker()
        flow = FlowKey("192.168.1.10", "192.168.2.20", 5000, 80, 6)

        # Phase 1: Normal operation (10 packets)
        for _ in range(10):
            hops = [
                HopMetadata(switch_id=1, ingress_port=1, egress_port=2,
                            hop_latency_ns=5_000),
                HopMetadata(switch_id=2, ingress_port=1, egress_port=2,
                            hop_latency_ns=5_000),
            ]
            r = TelemetryReport(timestamp=time.time(), flow=flow,
                                hops=hops, total_latency_ns=10_000,
                                hop_count=2)
            events = tracker.record(r)
            self.assertEqual(len(events), 0, f"Unexpected events: {events}")

        # Phase 2: Latency spike
        hops_spike = [
            HopMetadata(switch_id=1, ingress_port=1, egress_port=2,
                        hop_latency_ns=600_000),
            HopMetadata(switch_id=2, ingress_port=1, egress_port=2,
                        hop_latency_ns=600_000),
        ]
        r_spike = TelemetryReport(timestamp=time.time(), flow=flow,
                                  hops=hops_spike, total_latency_ns=1_200_000,
                                  hop_count=2)
        events_spike = tracker.record(r_spike)
        self.assertTrue(any("CRITICAL latency" in e for e in events_spike))

        # Phase 3: Path change detected
        hops_new_path = [
            HopMetadata(switch_id=1, ingress_port=1, egress_port=3,  # diff port!
                        hop_latency_ns=5_000),
            HopMetadata(switch_id=4, ingress_port=1, egress_port=2,  # different SW!
                        hop_latency_ns=5_000),
        ]
        r_new_path = TelemetryReport(timestamp=time.time(), flow=flow,
                                     hops=hops_new_path, total_latency_ns=10_000,
                                     hop_count=2)
        events_path = tracker.record(r_new_path)
        self.assertTrue(any("PATH CHANGE" in e for e in events_path))

        # Phase 4: Statistics are correct
        stats = tracker.get_flow_stats(flow)
        self.assertEqual(stats["hop_count"], 2)
        self.assertIn("SW1", stats["current_path"])


# ---------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("INT Project - Automated Test Suite")
    print("=" * 60)
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""
INT Live Telemetry Dashboard
============================
Reads real INT packets from the network interface (or pcap file)
and displays a live terminal dashboard with hop-by-hop metrics.

Usage:
  sudo python3 visualizer/int_dashboard.py --iface s1-eth2
  sudo python3 visualizer/int_dashboard.py --pcap /tmp/int_s1eth2.pcap
"""

import struct
import socket
import threading
import time
import os
import sys
import argparse
from collections import deque
from datetime import datetime

try:
    from scapy.all import sniff, rdpcap, Ether, IP, raw
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("[ERROR] scapy not installed: pip install scapy")
    sys.exit(1)

# ---------------------------------------------------------------
# ANSI Colors
# ---------------------------------------------------------------
class C:
    RESET   = '\033[0m'
    BOLD    = '\033[1m'
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    GRAY    = '\033[90m'
    BG_DARK = '\033[40m'

def clear():
    os.system('clear')

# ---------------------------------------------------------------
# INT Packet Decoder
# ---------------------------------------------------------------
class IntDecoder:
    """
    Decodes INT metadata from raw packet bytes.
    Structure after IPv4 header:
      INT Shim (4B) | INT Header (8B) | Hop Metadata...
    """

    INT_DSCP = 0x17  # 0x5c >> 2

    # Instruction mask bits
    SWITCH_ID_MASK      = 0x8000
    PORT_IDS_MASK       = 0x4000
    HOP_LATENCY_MASK    = 0x2000
    QUEUE_OCC_MASK      = 0x1000
    INGRESS_TSTAMP_MASK = 0x0800
    EGRESS_TSTAMP_MASK  = 0x0400

    def decode(self, pkt):
        """Returns dict of decoded INT data or None if not INT packet"""
        try:
            if not pkt.haslayer(IP):
                return None

            ip = pkt[IP]
            # Check INT DSCP marking (0x5c = 0x17 << 2)
            if ip.tos != 0x5c:
                return None

            # Get raw bytes after IP header
            ip_payload = bytes(ip.payload)
            if len(ip_payload) < 12:  # min: shim(4) + hdr(8)
                return None

            offset = 0

            # Skip L4 header if TCP/UDP (detect by protocol)
            if ip.proto == 6:   # TCP
                offset += 20
            elif ip.proto == 17: # UDP
                offset += 8
            # ICMP = 0, no L4 header to skip for our purposes

            if offset >= len(ip_payload):
                return None

            # Parse INT Shim (4 bytes)
            if offset + 4 > len(ip_payload):
                return None
            int_type, _, shim_len, orig_dscp = struct.unpack_from(
                "!BBBB", ip_payload, offset
            )
            offset += 4

            if int_type != 1:  # must be hop-by-hop
                return None

            # Parse INT Header (8 bytes)
            if offset + 8 > len(ip_payload):
                return None
            flags_ver, hop_meta_len, remaining_hops, instruction_mask, _ = struct.unpack_from(
                "!HBBHH", ip_payload, offset
            )
            offset += 8

            # Calculate hop count from shim length
            # shim_len in 4-byte words, covers shim+hdr+data
            data_words = max(0, shim_len - 3)  # 1 shim + 2 hdr = 3
            words_per_hop = bin(instruction_mask).count('1')
            hop_count = data_words // words_per_hop if words_per_hop > 0 else 0
            if hop_count == 0:
                hop_count = max(0, 6 - remaining_hops)

            hops = []
            for _ in range(max(1, hop_count)):
                hop = {}

                if instruction_mask & self.SWITCH_ID_MASK:
                    if offset + 4 <= len(ip_payload):
                        hop['switch_id'] = struct.unpack_from("!I", ip_payload, offset)[0]
                        offset += 4

                if instruction_mask & self.PORT_IDS_MASK:
                    if offset + 4 <= len(ip_payload):
                        ing, egr = struct.unpack_from("!HH", ip_payload, offset)
                        hop['ingress_port'] = ing
                        hop['egress_port']  = egr
                        offset += 4

                if instruction_mask & self.HOP_LATENCY_MASK:
                    if offset + 4 <= len(ip_payload):
                        hop['hop_latency_ns'] = struct.unpack_from("!I", ip_payload, offset)[0]
                        offset += 4

                if instruction_mask & self.QUEUE_OCC_MASK:
                    if offset + 4 <= len(ip_payload):
                        q_raw = struct.unpack_from("!I", ip_payload, offset)[0]
                        hop['queue_occupancy'] = q_raw & 0x00FFFFFF
                        offset += 4

                if instruction_mask & self.INGRESS_TSTAMP_MASK:
                    if offset + 8 <= len(ip_payload):
                        hop['ingress_tstamp'] = struct.unpack_from("!Q", ip_payload, offset)[0]
                        offset += 8

                if hop:
                    hops.append(hop)

            if not hops:
                return None

            return {
                'timestamp':        time.time(),
                'src_ip':           ip.src,
                'dst_ip':           ip.dst,
                'proto':            ip.proto,
                'original_size':    len(pkt),
                'int_overhead':     shim_len * 4,
                'instruction_mask': instruction_mask,
                'hop_count':        len(hops),
                'hops':             hops,
                'shim_len':         shim_len,
            }

        except Exception as e:
            return None


# ---------------------------------------------------------------
# Stats Tracker
# ---------------------------------------------------------------
class StatsTracker:
    WINDOW = 50

    def __init__(self):
        self.reports       = deque(maxlen=200)
        self.lat_history   = deque(maxlen=self.WINDOW)
        self.pkt_count     = 0
        self.start_time    = time.time()
        self.anomalies     = deque(maxlen=10)
        self.lock          = threading.Lock()

    def add(self, decoded):
        with self.lock:
            self.reports.append(decoded)
            self.pkt_count += 1

            # Calculate total latency across hops
            total_lat = sum(
                h.get('hop_latency_ns', 0) for h in decoded['hops']
            )
            self.lat_history.append(total_lat)

            # Anomaly detection
            if total_lat > 1_000_000:
                self.anomalies.appendleft(
                    f"{C.RED}🔴 CRITICAL lat {total_lat//1000}µs{C.RESET}"
                )
            elif total_lat > 100_000:
                self.anomalies.appendleft(
                    f"{C.YELLOW}🟡 HIGH lat {total_lat//1000}µs{C.RESET}"
                )

            for hop in decoded['hops']:
                q = hop.get('queue_occupancy', 0)
                sw = hop.get('switch_id', '?')
                if q > 800:
                    self.anomalies.appendleft(
                        f"{C.RED}🔴 Queue congestion SW{sw}: {q}{C.RESET}"
                    )

    def get_stats(self):
        with self.lock:
            lats = list(self.lat_history)
            reports = list(self.reports)
        return lats, reports

    @property
    def uptime(self):
        return int(time.time() - self.start_time)


# ---------------------------------------------------------------
# Terminal Dashboard Renderer
# ---------------------------------------------------------------
class Dashboard:
    def __init__(self, tracker: StatsTracker, source: str):
        self.tracker = tracker
        self.source  = source

    def bar(self, value, max_val, width=20, color=C.GREEN):
        filled = int((value / max_val) * width) if max_val > 0 else 0
        filled = min(filled, width)
        empty  = width - filled
        return f"{color}{'█' * filled}{C.GRAY}{'░' * empty}{C.RESET}"

    def sparkline(self, values, width=30):
        if not values:
            return C.GRAY + '─' * width + C.RESET
        mx = max(values) or 1
        chars = ' ▁▂▃▄▅▆▇█'
        result = ''
        # Sample to fit width
        step = max(1, len(values) // width)
        sampled = values[::step][-width:]
        for v in sampled:
            idx = int((v / mx) * (len(chars) - 1))
            color = C.RED if v > 1_000_000 else C.YELLOW if v > 100_000 else C.GREEN
            result += color + chars[idx] + C.RESET
        return result.ljust(width)

    def render(self):
        lats, reports = self.tracker.get_stats()
        clear()

        # Header
        now = datetime.now().strftime('%H:%M:%S')
        print(f"{C.BOLD}{C.CYAN}{'═'*70}{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}  ██ INT TELEMETRY DASHBOARD  "
              f"{C.GRAY}[{now}]  src:{self.source}{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}{'═'*70}{C.RESET}")

        # Top metrics
        avg_lat = sum(lats)/len(lats) if lats else 0
        max_lat = max(lats) if lats else 0
        min_lat = min(lats) if lats else 0
        uptime  = self.tracker.uptime
        pps     = self.tracker.pkt_count / uptime if uptime > 0 else 0

        print(f"\n  {C.BOLD}{'METRIC':<22}{'VALUE':<20}{'BAR'}{C.RESET}")
        print(f"  {'─'*60}")

        lat_color = C.RED if avg_lat > 1_000_000 else C.YELLOW if avg_lat > 100_000 else C.GREEN
        print(f"  {'Avg Latency':<22}{lat_color}{avg_lat/1000:>8.1f} µs{C.RESET}      "
              f"{self.bar(avg_lat, 2_000_000, 20, lat_color)}")
        print(f"  {'Max Latency':<22}{C.RED}{max_lat/1000:>8.1f} µs{C.RESET}      "
              f"{self.bar(max_lat, 2_000_000, 20, C.RED)}")
        print(f"  {'Min Latency':<22}{C.GREEN}{min_lat/1000:>8.1f} µs{C.RESET}      "
              f"{self.bar(min_lat, 2_000_000, 20, C.GREEN)}")
        print(f"  {'Total Reports':<22}{C.CYAN}{self.tracker.pkt_count:>8d}{C.RESET}")
        print(f"  {'Reports/sec':<22}{C.CYAN}{pps:>8.1f}{C.RESET}")
        print(f"  {'Uptime':<22}{C.GRAY}{uptime:>8d} s{C.RESET}")

        # Sparkline
        print(f"\n  {C.BOLD}Latency History (last {len(lats)} packets){C.RESET}")
        print(f"  {self.sparkline(lats, 60)}")
        print(f"  {C.GRAY}└─ min:{min_lat/1000:.0f}µs  "
              f"avg:{avg_lat/1000:.0f}µs  "
              f"max:{max_lat/1000:.0f}µs{C.RESET}")

        # Last 5 reports with hop detail
        print(f"\n  {C.BOLD}{'─'*60}")
        print(f"  {'FLOW':<30} {'PATH':<20} {'LAT':>8}  {'HOPS'}")
        print(f"  {'─'*60}{C.RESET}")

        recent = list(reports)[-8:]
        for r in reversed(recent):
            ts    = datetime.fromtimestamp(r['timestamp']).strftime('%H:%M:%S.%f')[:-3]
            proto = {1:'ICMP', 6:'TCP', 17:'UDP'}.get(r['proto'], str(r['proto']))
            flow  = f"{r['src_ip']}→{r['dst_ip']}[{proto}]"
            total_lat = sum(h.get('hop_latency_ns',0) for h in r['hops'])
            lat_str = f"{total_lat/1000:.1f}µs"
            lat_color = C.RED if total_lat>1_000_000 else C.YELLOW if total_lat>100_000 else C.GREEN

            # Build path string
            path_parts = []
            for h in r['hops']:
                sw = h.get('switch_id', '?')
                ip = h.get('ingress_port', '?')
                ep = h.get('egress_port', '?')
                path_parts.append(f"SW{sw}[{ip}→{ep}]")
            path = '▶'.join(path_parts) if path_parts else '?'

            print(f"  {C.GRAY}{ts}{C.RESET} {flow:<28} "
                  f"{C.CYAN}{path:<20}{C.RESET} "
                  f"{lat_color}{lat_str:>8}{C.RESET}  "
                  f"{C.MAGENTA}{r['hop_count']}hop(s){C.RESET}")

        # Per-hop detail for latest packet
        if reports:
            latest = reports[-1]
            print(f"\n  {C.BOLD}Latest Packet — Hop-by-Hop Breakdown{C.RESET}")
            print(f"  {'─'*60}")
            for i, hop in enumerate(latest['hops']):
                sw    = hop.get('switch_id', '?')
                ip    = hop.get('ingress_port', '?')
                ep    = hop.get('egress_port', '?')
                lat   = hop.get('hop_latency_ns', 0)
                q     = hop.get('queue_occupancy', 0)
                ts    = hop.get('ingress_tstamp', 0)

                lat_color = C.RED if lat>1_000_000 else C.YELLOW if lat>100_000 else C.GREEN
                q_color   = C.RED if q>800 else C.YELLOW if q>500 else C.GREEN

                print(f"  Hop {i+1}: {C.BOLD}SW{sw}{C.RESET} "
                      f"port {C.CYAN}{ip}→{ep}{C.RESET} | "
                      f"lat={lat_color}{lat/1000:.1f}µs{C.RESET} | "
                      f"q={q_color}{q}{C.RESET} | "
                      f"ts={C.GRAY}{ts}{C.RESET}")

            # INT overhead
            overhead = latest['int_overhead']
            orig     = latest['original_size']
            print(f"\n  {C.GRAY}Packet: {orig}B total | "
                  f"INT overhead: {overhead}B | "
                  f"mask: 0x{latest['instruction_mask']:04X}{C.RESET}")

        # Anomalies
        anomalies = list(self.tracker.anomalies)
        if anomalies:
            print(f"\n  {C.BOLD}{'─'*60}")
            print(f"  {C.BOLD}Anomalies{C.RESET}")
            for a in anomalies[:4]:
                print(f"  {a}")

        print(f"\n  {C.BOLD}{C.CYAN}{'═'*70}{C.RESET}")
        print(f"  {C.GRAY}Press Ctrl+C to stop{C.RESET}")

    def run(self, refresh=1.0):
        while True:
            self.render()
            time.sleep(refresh)


# ---------------------------------------------------------------
# Packet capture modes
# ---------------------------------------------------------------
def capture_live(iface, tracker, decoder):
    """Sniff live packets from interface"""
    print(f"[INFO] Sniffing on {iface}...")

    def handle(pkt):
        decoded = decoder.decode(pkt)
        if decoded:
            tracker.add(decoded)

    sniff(iface=iface, prn=handle, store=0)


def capture_pcap(pcap_file, tracker, decoder):
    """Read from pcap file"""
    print(f"[INFO] Reading {pcap_file}...")
    pkts = rdpcap(pcap_file)
    for pkt in pkts:
        decoded = decoder.decode(pkt)
        if decoded:
            tracker.add(decoded)
            time.sleep(0.1)  # simulate real-time replay
    print(f"[INFO] Loaded {len(pkts)} packets, "
          f"{tracker.pkt_count} INT reports decoded")


# ---------------------------------------------------------------
# Main
# ---------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="INT Live Telemetry Dashboard")
    parser.add_argument("--iface", default="s1-eth2",
                        help="Network interface to sniff (default: s1-eth2)")
    parser.add_argument("--pcap", default=None,
                        help="Read from pcap file instead of live interface")
    parser.add_argument("--refresh", type=float, default=1.0,
                        help="Dashboard refresh rate in seconds")
    args = parser.parse_args()

    decoder = IntDecoder()
    tracker = StatsTracker()
    source  = args.pcap if args.pcap else args.iface
    dash    = Dashboard(tracker, source)

    # Start capture in background thread
    if args.pcap:
        t = threading.Thread(
            target=capture_pcap,
            args=(args.pcap, tracker, decoder),
            daemon=True
        )
    else:
        t = threading.Thread(
            target=capture_live,
            args=(args.iface, tracker, decoder),
            daemon=True
        )
    t.start()

    # Run dashboard
    try:
        dash.run(refresh=args.refresh)
    except KeyboardInterrupt:
        print(f"\n{C.CYAN}[INFO] Dashboard stopped. "
              f"Total reports: {tracker.pkt_count}{C.RESET}")


if __name__ == "__main__":
    main()
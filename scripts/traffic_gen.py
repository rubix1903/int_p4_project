"""
INT Traffic Generator
Uses Scapy to generate test traffic for the INT demo.
Simulates:
  - Steady UDP flows (baseline latency measurement)
  - Burst traffic (triggers queue congestion events)
  - Multiple concurrent flows (tests ECMP path diversity)
  - TCP flows with SYN/ACK (tests TCP INT instrumentation)

Usage cmnds:
  sudo python3 scripts/traffic_gen.py --mode steady --src 10.0.1.1 --dst 10.0.3.2
  sudo python3 scripts/traffic_gen.py --mode burst  --pps 10000
  sudo python3 scripts/traffic_gen.py --mode multi  --flows 5
"""

import argparse
import random
import time
import sys
import threading

try:
    from scapy.all import (
        Ether, IP, TCP, UDP, Raw,
        sendp, send, srp1,
        get_if_hwaddr, get_if_list,
        conf
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("[ERROR] Scapy not installed: pip install scapy")
    sys.exit(1)



# Constants
# ----------------
DEFAULT_IFACE   = "eth0"
DEFAULT_SRC_IP  = "10.0.1.1"
DEFAULT_DST_IP  = "10.0.3.2"
DEFAULT_SRC_PORT = 12345
DEFAULT_DST_PORT = 5001

# DSCP 0x17 = INT-enabled flow marker
INT_DSCP = 0x17



# Packet Builders
# --------------------
def build_udp_pkt(src_ip, dst_ip, src_port, dst_port,
                  payload_size=64, iface=DEFAULT_IFACE):
    # Built a UDP packet marked for INT instrumentation
    payload = bytes(random.randint(0, 255) for _ in range(payload_size))
    pkt = (
        Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") /
        IP(src=src_ip, dst=dst_ip, tos=INT_DSCP << 2) /
        UDP(sport=src_port, dport=dst_port) /
        Raw(load=payload)
    )
    return pkt


def build_tcp_pkt(src_ip, dst_ip, src_port, dst_port,
                  flags="S", iface=DEFAULT_IFACE):
    # Built a TCP SYN packet marked for INT
    pkt = (
        Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") /
        IP(src=src_ip, dst=dst_ip, tos=INT_DSCP << 2) /
        TCP(sport=src_port, dport=dst_port, flags=flags,
            seq=random.randint(0, 2**32)) /
        Raw(load=b"\x00" * 20)
    )
    return pkt



# Traffic Modes
# -------------------
class TrafficGen:
    def __init__(self, args):
        self.src_ip   = args.src
        self.dst_ip   = args.dst
        self.iface    = args.iface
        self.pps      = args.pps
        self.duration = args.duration
        self.running  = False

    def _send_rate_limited(self, pkts, pps):
        # Sends packets at a given packets-per-second rate
        interval = 1.0 / pps if pps > 0 else 0
        sent = 0
        start = time.time()

        for pkt in pkts:
            sendp(pkt, iface=self.iface, verbose=False)
            sent += 1
            elapsed = time.time() - start
            expected = sent / pps if pps > 0 else elapsed
            if expected > elapsed:
                time.sleep(expected - elapsed)
        return sent

    def mode_steady(self):
        """
        Steady single-flow UDP traffic.
        Perfect for measuring baseline hop latency.
        """
        print(f"[STEADY] Sending {self.pps}pps UDP for {self.duration}s")
        print(f"         {self.src_ip}:{DEFAULT_SRC_PORT} → {self.dst_ip}:{DEFAULT_DST_PORT}")
        self.running = True
        sent = 0
        interval = 1.0 / self.pps
        end_time = time.time() + self.duration

        while self.running and time.time() < end_time:
            pkt = build_udp_pkt(
                self.src_ip, self.dst_ip,
                DEFAULT_SRC_PORT, DEFAULT_DST_PORT,
                payload_size=64, iface=self.iface
            )
            sendp(pkt, iface=self.iface, verbose=False)
            sent += 1
            time.sleep(interval)

        print(f"[STEADY] Sent {sent} packets")

    def mode_burst(self):
        """
        Bursts traffic to trigger queue congestion events.
        INT shows queue_occupancy spikes in real-time.
        """
        print(f"[BURST] Alternating: 5s quiet → 2s burst at {self.pps}pps")
        self.running = True
        end_time = time.time() + self.duration

        while self.running and time.time() < end_time:
            # Quiet period
            print("  [BURST] Quiet phase (5s)...")
            quiet_pkt = build_udp_pkt(
                self.src_ip, self.dst_ip,
                DEFAULT_SRC_PORT, DEFAULT_DST_PORT,
                iface=self.iface
            )
            for _ in range(int(5 * 100)):   # 100pps during quiet
                sendp(quiet_pkt, iface=self.iface, verbose=False)
                time.sleep(0.01)

            # Burst period
            print(f"  [BURST] BURST phase (2s at {self.pps}pps) ← watch queue metrics!")
            burst_end = time.time() + 2
            while time.time() < burst_end:
                for _ in range(10):  # mini-burst of 10
                    pkt = build_udp_pkt(
                        self.src_ip, self.dst_ip,
                        random.randint(10000, 60000),
                        DEFAULT_DST_PORT,
                        payload_size=1400,  # Large frames
                        iface=self.iface
                    )
                    sendp(pkt, iface=self.iface, verbose=False)
                time.sleep(10 / self.pps)

    def mode_multi(self, num_flows=5):
        """
        Multiple concurrent flows - tests ECMP path's diversity.
        Different flows may take S2 or S4 path; INT reveals which path is taken.
        """
        print(f"[MULTI] {num_flows} concurrent flows for {self.duration}s")
        print("        Watch INT reports for path diversity (S2 vs S4 hops)")

        threads = []
        for i in range(num_flows):
            src_port = DEFAULT_SRC_PORT + i
            dst_port = DEFAULT_DST_PORT + (i % 10)

            def flow_worker(sp=src_port, dp=dst_port, fid=i):
                end = time.time() + self.duration
                while time.time() < end:
                    pkt = build_udp_pkt(
                        self.src_ip, self.dst_ip,
                        sp, dp, payload_size=128, iface=self.iface
                    )
                    sendp(pkt, iface=self.iface, verbose=False)
                    time.sleep(0.05 + random.uniform(0, 0.05))

            t = threading.Thread(target=flow_worker, daemon=True)
            threads.append(t)

        for t in threads:
            t.start()

        print(f"  {num_flows} flow threads started. Press Ctrl+C to stop.")
        try:
            time.sleep(self.duration)
        except KeyboardInterrupt:
            pass
        print(f"[MULTI] Done.")

    def mode_tcp(self):
        # TCP flow generation
        print(f"[TCP] TCP SYN flood for latency measurement")
        end_time = time.time() + self.duration
        sent = 0

        while time.time() < end_time:
            pkt = build_tcp_pkt(
                self.src_ip, self.dst_ip,
                random.randint(49152, 65535), 80,
                iface=self.iface
            )
            sendp(pkt, iface=self.iface, verbose=False)
            sent += 1
            time.sleep(1.0 / self.pps)

        print(f"[TCP] Sent {sent} TCP packets")



# Main
# -------
def main():
    parser = argparse.ArgumentParser(
        description="INT Traffic Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=
        """
        Examples:
        sudo python3 scripts/traffic_gen.py --mode steady
        sudo python3 scripts/traffic_gen.py --mode burst  --pps 5000
        sudo python3 scripts/traffic_gen.py --mode multi  --flows 8
        sudo python3 scripts/traffic_gen.py --mode tcp
        """
        )

    parser.add_argument("--mode",     default="steady",
                        choices=["steady", "burst", "multi", "tcp"],
                        help="Traffic generation mode")
    parser.add_argument("--src",      default=DEFAULT_SRC_IP,
                        help="Source IP address")
    parser.add_argument("--dst",      default=DEFAULT_DST_IP,
                        help="Destination IP address")
    parser.add_argument("--iface",    default=DEFAULT_IFACE,
                        help="Network interface to send on")
    parser.add_argument("--pps",      type=int, default=1000,
                        help="Packets per second")
    parser.add_argument("--duration", type=int, default=60,
                        help="Duration in seconds")
    parser.add_argument("--flows",    type=int, default=5,
                        help="Number of parallel flows (multi mode)")
    args = parser.parse_args()

    gen = TrafficGen(args)
    print(f"INT Traffic Generator - Mode: {args.mode.upper()}")
    print(f"Interface: {args.iface} | Rate: {args.pps}pps | Duration: {args.duration}s")
    print("-" * 50)

    try:
        if args.mode == "steady":
            gen.mode_steady()
        elif args.mode == "burst":
            gen.mode_burst()
        elif args.mode == "multi":
            gen.mode_multi(num_flows=args.flows)
        elif args.mode == "tcp":
            gen.mode_tcp()
    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user")
    except PermissionError:
        print("[ERROR] Root privileges required. Run with sudo.")
        sys.exit(1)


if __name__ == "__main__":
    main()

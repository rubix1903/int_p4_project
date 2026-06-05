#!/usr/bin/env python3
"""
INT Mininet Topology
====================
Creates a 4-switch topology to demonstrate In-band Network Telemetry.

Topology:
                       ┌─────┐
            ┌──────────┤ S2  ├──────────┐
            │          │(transit)│      │
            │          └─────┘          │
  h1 ── [S1:source] ──────────────── [S3:sink] ── h2
            │          ┌─────┐          │
            └──────────┤ S4  ├──────────┘
                       │(transit)│
                       └─────┘

Hosts:
  h1: 10.0.1.1 (traffic generator)
  h2: 10.0.3.2 (traffic receiver / INT collector runs here)

Switches:
  S1: INT Source - stamps INT headers on h1→h2 flows
  S2: INT Transit - appends hop metadata (primary path)
  S4: INT Transit - appends hop metadata (alternate path)
  S3: INT Sink - strips INT, sends report to collector

Usage:
  sudo python3 topology/int_topology.py

Requirements:
  - Mininet installed
  - BMv2 (behavioral-model) installed
  - P4C compiler available
"""

import os
import sys
import subprocess
import time
import argparse

# Ensure p4utils is importable if present
try:
    pass  # p4utils disabled
    HAS_P4UTILS = False
except ImportError:
    HAS_P4UTILS = False
    print("[WARN] p4utils not found. Using raw Mininet + BMv2 mode.")

try:
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSKernelSwitch
    from mininet.cli import CLI
    from mininet.log import setLogLevel, info
    from mininet.link import TCLink
    HAS_MININET = True
except ImportError:
    HAS_MININET = False
    print("[ERROR] Mininet not installed. Please install mininet.")


# ---------------------------------------------------------------
# P4 Switch configuration
# ---------------------------------------------------------------
P4_PROG      = os.path.join(os.path.dirname(__file__), "../p4src/int.p4")
BMV2_EXE     = "simple_switch"
THRIFT_PORT_BASE = 9090

SWITCH_CONFIG = {
    "s1": {"thrift_port": 9091, "role": "source",  "sw_id": 1},
    "s2": {"thrift_port": 9092, "role": "transit", "sw_id": 2},
    "s3": {"thrift_port": 9093, "role": "sink",    "sw_id": 3},
    "s4": {"thrift_port": 9094, "role": "transit", "sw_id": 4},
}


def compile_p4():
    """Compile the P4 program to BMv2 JSON"""
    output_dir = os.path.join(os.path.dirname(__file__), "../build")
    os.makedirs(output_dir, exist_ok=True)
    json_out = os.path.join(output_dir, "int.json")
    p4info_out = os.path.join(output_dir, "int.p4info.txt")

    cmd = [
        "p4c-bm2-ss",
        "--p4v", "16",
        "--p4runtime-files", p4info_out,
        "-o", json_out,
        P4_PROG
    ]
    print(f"[INFO] Compiling: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[ERROR] Compilation failed:\n{result.stderr}")
        sys.exit(1)
    print(f"[INFO] Compiled to {json_out}")
    return json_out


def run_p4utils_topology(json_path: str):
    """
    Use p4utils NetworkAPI to create and manage the topology.
    p4utils handles BMv2 instance lifecycle automatically.
    """
    net = NetworkAPI()

    # Add hosts
    net.addHost("h1")
    net.addHost("h2")
    net.addHost("collector")  # INT collector host

    # Add P4 switches
    for sw_name in ["s1", "s2", "s3", "s4"]:
        cfg = SWITCH_CONFIG[sw_name]
        net.addP4Switch(
            sw_name,
            cli_input=f"topology/{sw_name}_commands.txt",
            log_enabled=True,
            log_dir=f"logs/{sw_name}"
        )

    # Set P4 program for all switches
    net.setP4Source("s1", P4_PROG)
    net.setP4Source("s2", P4_PROG)
    net.setP4Source("s3", P4_PROG)
    net.setP4Source("s4", P4_PROG)

    # Connect hosts
    net.addLink("h1",        "s1", delay="1ms",   bw=100)
    net.addLink("h2",        "s3", delay="1ms",   bw=100)
    net.addLink("collector", "s3", delay="0.1ms", bw=1000)

    # Primary path: S1 → S2 → S3
    net.addLink("s1", "s2", delay="5ms",  bw=100)
    net.addLink("s2", "s3", delay="5ms",  bw=100)

    # Alternate path: S1 → S4 → S3
    net.addLink("s1", "s4", delay="10ms", bw=100)
    net.addLink("s4", "s3", delay="10ms", bw=100)

    # Configure IP addresses
    net.addNodeIntfData("h1",        "h1-eth0",  ip="10.0.1.1/24", mac="00:00:0a:00:01:01")
    net.addNodeIntfData("h2",        "h2-eth0",  ip="10.0.3.2/24", mac="00:00:0a:00:03:02")
    net.addNodeIntfData("collector", "col-eth0", ip="10.0.3.3/24", mac="00:00:0a:00:03:03")

    net.enablePcapDumpAll("pcaps")
    net.enableLogAll("logs")
    net.enableCli()
    net.startNetwork()


def run_mininet_topology(json_path: str):
    """
    Fallback: raw Mininet + manual BMv2 process management.
    """
    if not HAS_MININET:
        print("[ERROR] Neither p4utils nor mininet available.")
        sys.exit(1)

    setLogLevel("info")
    net = Mininet(link=TCLink)

    info("*** Adding hosts\n")
    h1  = net.addHost("h1",        ip="10.0.1.1/24", mac="00:00:0a:00:01:01")
    h2  = net.addHost("h2",        ip="10.0.3.2/24", mac="00:00:0a:00:03:02")
    col = net.addHost("collector", ip="10.0.3.3/24", mac="00:00:0a:00:03:03")

    info("*** Adding switches (BMv2)\n")
    switches = {}
    for sw_name in ["s1", "s2", "s3", "s4"]:
        sw = net.addSwitch(sw_name, cls=OVSKernelSwitch)
        switches[sw_name] = sw

    info("*** Adding links\n")
    net.addLink(h1,  switches["s1"], delay="1ms",   bw=100)
    net.addLink(h2,  switches["s3"], delay="1ms",   bw=100)
    net.addLink(col, switches["s3"], delay="0.1ms", bw=1000)
    net.addLink(switches["s1"], switches["s2"], delay="5ms",  bw=100)
    net.addLink(switches["s2"], switches["s3"], delay="5ms",  bw=100)
    net.addLink(switches["s1"], switches["s4"], delay="10ms", bw=100)
    net.addLink(switches["s4"], switches["s3"], delay="10ms", bw=100)

    info("*** Starting network\n")
    net.start()

    info("*** Network is up. Type 'exit' to quit.\n")
    info("*** Run on h1: ping h2 to generate traffic\n")
    info("*** Run on collector: python3 controller/int_controller.py\n")

    CLI(net)
    net.stop()


def generate_switch_commands():
    """Generate simple_switch_CLI command files for each switch"""
    os.makedirs("topology", exist_ok=True)

    # S1 - Source commands
    s1_cmds = """
# S1 - INT Source Switch Commands
# Forwarding table
table_add IntIngress.ipv4_lpm IntIngress.ipv4_forward 10.0.3.0/24 => 00:00:0a:00:03:02 2
table_add IntIngress.ipv4_lpm IntIngress.ipv4_forward 10.0.2.0/24 => 00:00:0a:00:02:02 2

# INT Source - enable for all flows from h1 to h2
table_add IntIngress.int_source_table IntIngress.int_set_source 10.0.1.0&&&255.255.255.0 10.0.3.0&&&255.255.255.0 0&&&0 0&&&0 =>

# INT Transit role (also transit when INT packets pass through)
table_add IntIngress.int_transit_table IntIngress.int_set_transit 1 => 1
"""

    # S2 - Transit commands
    s2_cmds = """
# S2 - INT Transit Switch Commands
table_add IntIngress.ipv4_lpm IntIngress.ipv4_forward 10.0.3.0/24 => 00:00:0a:00:03:02 2
table_add IntIngress.ipv4_lpm IntIngress.ipv4_forward 10.0.1.0/24 => 00:00:0a:00:01:01 1

# INT Transit role
table_add IntIngress.int_transit_table IntIngress.int_set_transit 1 => 2
"""

    # S3 - Sink commands
    s3_cmds = """
# S3 - INT Sink Switch Commands
table_add IntIngress.ipv4_lpm IntIngress.ipv4_forward 10.0.3.2/32 => 00:00:0a:00:03:02 2
table_add IntIngress.ipv4_lpm IntIngress.ipv4_forward 10.0.3.3/32 => 00:00:0a:00:03:03 3
table_add IntIngress.ipv4_lpm IntIngress.ipv4_forward 10.0.1.0/24 => 00:00:0a:00:01:01 1

# INT Transit role (adds its own metadata before sinking)
table_add IntIngress.int_transit_table IntIngress.int_set_transit 1 => 3

# INT Sink - port 2 exits INT domain (to h2)
table_add IntIngress.int_sink_table IntIngress.int_set_sink 2 => 3

# Mirror session for reports (send to collector at 10.0.3.3:54321)
mirroring_add 500 3
"""

    # S4 - Alternate transit commands
    s4_cmds = """
# S4 - INT Transit Switch Commands (Alternate Path)
table_add IntIngress.ipv4_lpm IntIngress.ipv4_forward 10.0.3.0/24 => 00:00:0a:00:03:02 2
table_add IntIngress.ipv4_lpm IntIngress.ipv4_forward 10.0.1.0/24 => 00:00:0a:00:01:01 1

# INT Transit role
table_add IntIngress.int_transit_table IntIngress.int_set_transit 1 => 4
"""

    cmd_map = {"s1": s1_cmds, "s2": s2_cmds, "s3": s3_cmds, "s4": s4_cmds}
    for sw, cmds in cmd_map.items():
        with open(f"topology/{sw}_commands.txt", "w") as f:
            f.write(cmds.strip())
    print("[INFO] Switch command files written to topology/")


# ---------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="INT Mininet Topology")
    parser.add_argument("--compile", action="store_true",
                        help="Compile P4 program before starting")
    parser.add_argument("--gen-cmds", action="store_true",
                        help="Generate switch command files only")
    args = parser.parse_args()

    generate_switch_commands()

    if args.gen_cmds:
        print("[INFO] Command files generated. Exiting.")
        sys.exit(0)

    json_path = None
    if args.compile:
        json_path = compile_p4()

    if HAS_P4UTILS:
        print("[INFO] Using p4utils mode")
        run_p4utils_topology(json_path or "build/int.json")
    else:
        print("[INFO] Using raw Mininet mode")
        run_mininet_topology(json_path or "build/int.json")

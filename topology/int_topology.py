import os
from mininet.net import Mininet
from mininet.node import Host, Switch
from mininet.link import TCLink
from mininet.cli import CLI

# This class replaces the broken p4_mininet helpers
class ReadiedSwitch(Switch):
    def __init__(self, name, json=None, thrift_port=None, **kwargs):
        Switch.__init__(self, name, **kwargs)
        self.json = json
        self.thrift_port = thrift_port

    def start(self, controllers):
        args = [ 'simple_switch' ]
        args.extend( [ '--thrift-port', str(self.thrift_port) ] )
        for p, intf in self.intfs.items():
            if not intf.IP():
                args.extend( [ '-i', f'{p}@{intf.name}' ] )
        args.append(self.json)
        print(f"Starting BMv2: {' '.join(args)}")
        self.cmd( ' '.join(args) + ' > /dev/null 2>&1 &' )

def run():
    # Fix OVS Conflict
    os.system("mn -c")
    os.system("systemctl stop openvswitch")
    os.system("modprobe -r openvswitch")

    net = Mininet(link=TCLink, controller=None)

    # Hosts
    h1 = net.addHost('h1', ip='10.0.1.1/24', mac='00:00:00:00:01:01')
    h2 = net.addHost('h2', ip='10.0.3.2/24', mac='00:00:00:00:03:02')
    col = net.addHost('col', ip='10.0.3.3/24', mac='00:00:00:00:03:03')

    # Switches (Pointing to your compiled JSON)
    json_path = 'build/int.json'
    s1 = net.addSwitch('s1', cls=ReadiedSwitch, json=json_path, thrift_port=9091)
    s2 = net.addSwitch('s2', cls=ReadiedSwitch, json=json_path, thrift_port=9092)
    s3 = net.addSwitch('s3', cls=ReadiedSwitch, json=json_path, thrift_port=9093)

    # Links
    net.addLink(h1, s1) # port 1
    net.addLink(s1, s2) # port 2
    net.addLink(s2, s3) # s2 port 2, s3 port 1
    net.addLink(h2, s3) # port 2
    net.addLink(col, s3) # port 3

    net.start()

    # Apply Forwarding Rules with correct MACs
    os.system("simple_switch_CLI --thrift-port 9091 <<< 'table_add IntIngress.ipv4_lpm IntIngress.ipv4_forward 10.0.3.2/32 => 00:00:00:00:03:02 2; table_add IntIngress.int_source_table IntIngress.int_set_source 10.0.1.1/32 =>'")
    os.system("simple_switch_CLI --thrift-port 9092 <<< 'table_add IntIngress.ipv4_lpm IntIngress.ipv4_forward 10.0.3.2/32 => 00:00:00:00:03:02 2'")
    os.system("simple_switch_CLI --thrift-port 9093 <<< 'table_add IntIngress.ipv4_lpm IntIngress.ipv4_forward 10.0.3.2/32 => 00:00:00:00:03:02 2; table_add IntIngress.int_sink_table IntIngress.int_set_sink 2 =>; mirroring_add 500 3'")

    print("Network ready. Type 'h1 ping h2' in CLI to test.")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
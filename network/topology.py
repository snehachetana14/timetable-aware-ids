#!/usr/bin/env python3
"""topology.py - Mininet topology for Timetable-Aware IDS."""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info

# room_name -> {id, hosts}; subnet is 10.0.<id>.0/24
ROOMS = {
    'room204': {'id': 2, 'hosts': 6},   # lecture hall (active)
    'lab3':    {'id': 3, 'hosts': 4},   # computer lab (empty this slot)
    'extnet':  {'id': 9, 'hosts': 1},   # external network
}


def build_topology():
    net = Mininet(controller=RemoteController, switch=OVSSwitch,
                  link=TCLink, autoSetMacs=True)

    info('*** Adding controller\n')
    net.addController('c0', controller=RemoteController,
                      ip='127.0.0.1', port=6653)

    info('*** Adding core switch\n')
    core = net.addSwitch('s1', protocols='OpenFlow13')

    host_map = {}
    switch_num = 2

    info('*** Adding room switches and hosts\n')
    for room_name, cfg in ROOMS.items():
        room_id = cfg['id']
        sw = net.addSwitch('s%d' % switch_num, protocols='OpenFlow13')
        switch_num += 1
        net.addLink(sw, core)

        hosts = []
        for h in range(1, cfg['hosts'] + 1):
            ip = '10.0.%d.%d/24' % (room_id, h)
            host = net.addHost('%s_h%d' % (room_name, h), ip=ip)
            net.addLink(host, sw)
            hosts.append(host)
        host_map[room_name] = hosts
        info('    %s: %d hosts on 10.0.%d.0/24\n' % (room_name, cfg['hosts'], room_id))

    return net, host_map


def main():
    setLogLevel('info')
    net, host_map = build_topology()
    info('*** Starting network\n')
    net.start()
    info('*** Network ready. Run attacks from the CLI below.\n')
    CLI(net)
    net.stop()


if __name__ == '__main__':
    main()
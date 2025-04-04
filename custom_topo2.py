#!/usr/bin/env python3
from mininet.log import setLogLevel, info
from mn_wifi.net import Mininet_wifi
from mn_wifi.cli import CLI
from mn_wifi.link import wmediumd
from mn_wifi.wmediumdConnector import interference
from mininet.node import RemoteController
from containernet.node import Docker as DockerContainer  # or from containernet.mininet.node import Docker

def run_topology():
    net = Mininet_wifi(
        controller=RemoteController,
        link=wmediumd,
        wmediumd_mode=interference
    )

    info("*** Creating 9 OVS switches for a 3×3 torus ***\n")
    # 3×3 = 9 normal OVS switches
    switches = []
    for r in range(3):
        row = []
        for c in range(3):
            idx = r*3 + c + 1  # 1..9
            sw_name = f"s{idx}"
            # Each switch uses OpenFlow13
            sw = net.addSwitch(sw_name, protocols='OpenFlow13')
            row.append(sw)
        switches.append(row)

    info("*** Linking switches in a torus pattern ***\n")
    for r in range(3):
        for c in range(3):
            sw_curr = switches[r][c]
            sw_right = switches[r][(c+1) % 3]
            sw_down  = switches[(r+1) % 3][c]

            if c < 2:
                net.addLink(sw_curr, sw_right)
            elif c == 2:
                net.addLink(sw_curr, switches[r][0])

            if r < 2:
                net.addLink(sw_curr, sw_down)
            elif r == 2:
                net.addLink(sw_curr, switches[0][c])

    info("*** Creating two Wi-Fi APs ***\n")
    # We’ll attach these APs to, say, s5 (center) and s9 (bottom-right corner)
    ap1 = net.addAccessPoint('ap1', ssid='ssid-foo', mode='g', channel='1',
                             position='10,10,0')
    ap2 = net.addAccessPoint('ap2', ssid='ssid-bar', mode='g', channel='6',
                             position='20,10,0')

    info("*** Creating stations ***\n")
    sta1 = net.addStation('sta1', position='12,15,0')
    sta2 = net.addStation('sta2', position='18,15,0')
    sta3 = net.addStation('sta3', position='25,12,0')

    info("*** Creating a Remote Controller ***\n")
    c0 = net.addController('c0', controller=RemoteController,
                           ip='127.0.0.1', port=6653)

    info("*** Configuring Wi-Fi ***\n")
    net.configureWifiNodes()

    info("*** Linking the APs to the torus ***\n")
    # Connect ap1 to s5 (center, row=1 col=1)
    s5 = switches[1][1]
    net.addLink(ap1, s5)

    # Connect ap2 to s9 (row=2 col=2)
    s9 = switches[2][2]
    net.addLink(ap2, s9)

    info("*** Creating a Docker-based host ***\n")
    d1 = net.addHost(
        'd1',
        dimage='ubuntu:trusty',
        docker_args={'cpus': '0.5'}
    )
    # Link that Docker host to s1 (top-left corner)
    net.addLink(d1, switches[0][0])

    info("*** Starting network ***\n")
    net.start()

    # ** Print out DPIDs (decimal or hex) for ap1 and ap2:
    info(f"ap1 name={ap1.name}, dpid={ap1.dpid}\n")
    info(f"ap2 name={ap2.name}, dpid={ap2.dpid}\n")

    info("*** Testing connectivity ***\n")
    net.pingAll()

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_topology()

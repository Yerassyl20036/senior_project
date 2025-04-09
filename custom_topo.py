#!/usr/bin/env python3
from mininet.log import setLogLevel, info
from mn_wifi.net import Mininet_wifi
from mn_wifi.cli import CLI
from mn_wifi.link import wmediumd
from mn_wifi.wmediumdConnector import interference
from mininet.node import RemoteController
from containernet.node import Docker as DockerContainer  # or from containernet.mininet.node import Docker

def run_topology():
    """
     - 3x3 torus of OVS switches (9 switches)
     - 3 Wi-Fi access points
     - 6 or more stations (regular hosts)
     - 2 Docker hosts
    """
    net = Mininet_wifi(controller=RemoteController,
                       link=wmediumd,
                       wmediumd_mode=interference)

    info("\n*** Creating 9 OVS switches for a 3x3 torus ***\n")
    switches = []
    for r in range(3):
        row = []
        for c in range(3):
            idx = r*3 + c + 1
            sw_name = f"s{idx}"
            sw = net.addSwitch(sw_name, protocols='OpenFlow13')
            row.append(sw)
        switches.append(row)

    info("*** Linking switches in a torus pattern ***\n")
    for r in range(3):
        for c in range(3):
            sw_curr = switches[r][c]
            sw_right = switches[r][(c+1)%3]
            sw_down = switches[(r+1)%3][c]

            if c < 2:
                net.addLink(sw_curr, sw_right)
            elif c == 2:
                net.addLink(sw_curr, switches[r][0])

            if r < 2:
                net.addLink(sw_curr, sw_down)
            elif r == 2:
                net.addLink(sw_curr, switches[0][c])

    info("\n*** Creating 3 Wi-Fi Access Points ***\n")
    ap1 = net.addAccessPoint('ap1', ssid='ssid-ap1', mode='g', channel='1',
                             position='10,10,0')
    ap2 = net.addAccessPoint('ap2', ssid='ssid-ap2', mode='g', channel='6',
                             position='20,10,0')
    ap3 = net.addAccessPoint('ap3', ssid='ssid-ap3', mode='g', channel='11',
                             position='30,10,0')

    info("\n*** Creating 6 stations (regular hosts) ***\n")
    sta_list = []
    for i in range(1, 7):
        sta = net.addStation(f'sta{i}', position=f'{10+2*i},15,0')
        sta_list.append(sta)

    info("\n*** Creating 2 Docker-based hosts ***\n")
    # Make sure you have a valid Docker image (dimage='ubuntu:trusty' or custom)
    d1 = net.addHost('d1',
                       dimage='ubuntu:trusty',
                       docker_args={'cpus': '0.5'})
    d2 = net.addHost('d2',
                       dimage='ubuntu:trusty',
                       docker_args={'cpus': '0.5'})

    info("\n*** Adding a Remote Controller ***\n")
    c0 = net.addController('c0', controller=RemoteController,
                           ip='127.0.0.1', port=6653)

    info("\n*** Configuring Wi-Fi ***\n")
    net.configureWifiNodes()

    info("*** Linking APs to some switches ***\n")
    # e.g., link ap1-> s5, ap2-> s6, ap3-> s9
    s5 = switches[1][1]  # middle
    s6 = switches[1][2]
    s9 = switches[2][2]
    net.addLink(ap1, s5)
    net.addLink(ap2, s6)
    net.addLink(ap3, s9)

    info("*** Linking Docker hosts to top-left corner (s1) and top-center (s2) ***\n")
    s1 = switches[0][0]
    s2 = switches[0][1]
    net.addLink(d1, s1)
    net.addLink(d2, s2)

    info("\n*** Starting network ***\n")
    net.start()
    info("*** Testing connectivity ***\n")
    net.pingAll()

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_topology()

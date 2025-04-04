#!/usr/bin/env python3
from containernet.mininet.net import Containernet
from containernet.mininet.node import Docker
from mininet.node import Controller

def test_containernet():
    net = Containernet(controller=Controller)
    net.addController('c0')
    d1 = net.addDockerHost('d1', dimage='ubuntu:latest')
    s1 = net.addSwitch('s1')
    net.addLink(d1, s1)
    net.start()
    net.pingAll()
    net.stop()

if __name__ == "__main__":
    test_containernet()

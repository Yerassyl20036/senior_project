from mininet.net import Mininet
from containernet.mininet.node import Docker
from mininet.node import Controller

def test_mininet_with_docker():
    # No remote or local controllers needed for a simple L2 test:
    net = Mininet(controller=None)

    # Add one switch in 'standalone' (learning) mode
    s1 = net.addSwitch('s1', failMode='standalone')

    # Docker-based host (d1)
    d1 = net.addHost(
        'd1',
        dimage='ubuntu:trusty',
        ip='10.0.0.10/24'
    )
    net.addLink(d1, s1)

    # Plain Mininet host (h2)
    h2 = net.addHost('h2', ip='10.0.0.11/24')
    net.addLink(h2, s1)

    net.start()
    net.pingAll()
    net.stop()

if __name__ == "__main__":
    test_mininet_with_docker()

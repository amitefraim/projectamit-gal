#!/usr/bin/env python3

import sys
sys.path.append('/home/ron/Desktop/tmp/mininet')

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.util import irange
from mininet.node import Controller, RemoteController
from mininet.node import OVSController
from sys import argv


class CustomTopo(Topo):
    def build(self, numSwitches=4, numHostsPerSwitch=4, numClients=5):

        s0 = self.addSwitch('s0')
        for i in irange(1, numSwitches):
            s = self.buildSwitch(i, numHostsPerSwitch=numHostsPerSwitch)
            self.addLink(s0, s)

        for i in irange(1,numClients):
            h = self.addHost('h%s' % i, mac='00:00:00:00:00:%s'%i)
            self.addLink(s0, h)



    def buildSwitch(self, loc, numHostsPerSwitch):

        dpid = (loc * numHostsPerSwitch) + 1
        s = self.addSwitch('s%s' % loc, dpid='%x' % dpid)
        h0 = self.addHost('h0_%s' % loc, mac='00:%s:00:00:00:00' % loc, ip='10.%s.0.0' % loc)
        self.addLink(s, h0)

        for n in irange(1, numHostsPerSwitch):
            h = self.addHost('h%s_%s' % (n, loc),ip='10.%s.0.%s'%(loc,n),mac='00:%s:00:00:00:%s'%(loc,n))
            self.addLink(s, h)

        return s


topos = {
    'topo1': CustomTopo
}

if __name__ == '__main__':
    fileAddr = "block.list"
    fh = open(fileAddr, "w")
    fh.seek(0)
    fh.write("")
    fh.truncate()
    fh.close()

    if len(argv) == 1:
        numSwitches = 2
        numHostsPerSwitch = 2
        numClients = 5
    else:
        numSwitches = int(argv[1])
        numHostsPerSwitch = int(argv[2])
        numClients = int(argv[3])

    net = Mininet(topo=CustomTopo(numSwitches, numHostsPerSwitch, numClients), build=False)
    c0 = net.addController(name='c0',
                           controller=RemoteController,
                           ip='127.0.0.1',
                           port=6633)

    c1 = net.addController(name='c1', port=6634,controller=OVSController)

    net.start()

    net.get('s0').start([c1])
    for i in range(1, numSwitches + 1):
        net.get('s%s' % i).start([c0])

    for i in range(1, numSwitches + 1):
        net.get('h0_%s' % i).cmd('python3 /home/mininet/projectamit-gal/virusNotifier.py 8080 %s %s &' % (numSwitches, i))
        for j in range(1, numHostsPerSwitch + 1):
            net.get('h%s_%s' % (j,i)).cmd('python3 /home/mininet/projectamit-gal/server.py 8080 10.%s.0.0 &' % i)

    #net.get('h1').cmd('python3 /home/mininet/projectamit-gal/attacker.py 10.1.0.1:8080 0.2')
    #net.get('h2').cmd('curl -X POST -d installFlow 10.1.0.1:8080')
    CLI(net)
    net.stop()

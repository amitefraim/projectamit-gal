from mininet.topo import Topo
from mininet.util import irange
 
class CustomTopo( Topo ):
 
    def build(self, numSwitches=4, numHostsPerSwitch=4):
        rootSwitch = self.addSwitch('s0')
        for i in irange( 1, numSwitches ):
            s = self.buildSwitch(i, numHostsPerSwitch=numHostsPerSwitch)
            self.addLink(rootSwitch, s)
 
    def buildSwitch(self, loc, numHostsPerSwitch):
 
        dpid = (loc * numHostsPerSwitch) + 1
        s = self.addSwitch('s%s' % loc, dpid='%x' % dpid)
        
        h0 = self.addHost('h0_%s' % loc, mac='00:%s:00:00:00:00' % loc, ip='10.%s.0.0' % loc)
        self.addLink(s,h0)

        for n in irange(1, numHostsPerSwitch):
            h = self.addHost('h%s_%s' % (n, loc))
            self.addLink(s, h)
 
        return s
 
topos = {
    'topo1': CustomTopo
}
#Final Project - Moving Target Defense
#Created by: Gal Aharon & Amit Efraim 

"""
Moving Target Defense Implementation:

If the packet is real:
1) Keep a table that maps IP addresses to MAC addresses and switch ports.
   Stock this table using information from ARP and IP packets.
2) When you see an ARP query, try to answer it using information in the table
   from step 1.  If the info in the table is old, just flood the query.
3) Flood all other ARPs.
4) When you see an IP packet, if you know the destination port (because it's
   in the table from step 1), install a flow for it.
   
Initialization: pingall command to update arpTable.
If the packet is Virtual:
1) Changing SRC VIRTUAL IP ---> REAL SRC IP 
2) Update necessary packet information from the arpTable (source port, destination port, mac address ...)
3) Send the packet.
"""

from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer

import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time

# Timeout for flows
FLOW_IDLE_TIMEOUT = 10

# Timeout for ARP entries
ARP_TIMEOUT = 60 * 2

# Maximum number of packet to buffer on a switch for an unknown IP
MAX_BUFFERED_PER_IP = 5

# Maximum time to hang on to a buffer for an unknown IP in seconds
MAX_BUFFER_TIME = 5
import threading
import random
# The number of Vip variable to construct the Vip address
N_IP = 100
#We use the Entry class from l3_learning file
class Entry (object):
  """
  Not strictly an ARP entry.
  We use the port to determine which port to forward traffic out of.
  We use the MAC to answer ARP replies.
  We use the timeout so that if an entry is older than ARP_TIMEOUT, we
   flood the ARP request rather than try to answer it ourselves.
  """
  def __init__ (self, port, mac):
    self.timeout = time.time() + ARP_TIMEOUT
    self.port = port
    self.mac = mac
    
  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)
  def __ne__ (self, other):
    return not self.__eq__(other)

  def isExpired (self):
    if self.port == of.OFPP_NONE: return False
    return time.time() > self.timeout

# Changes dpid to mac address
def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))

# Main Algorithm class
class l3_switch (EventMixin):
  #Both maps help us convert Virtual to Real IP
  R2V_Map = {"10.0.0.1": "","10.0.0.2": "","10.0.0.3": "","10.0.0.4": "","10.0.0.5": "","10.0.0.6": "","10.0.0.7": "","10.0.0.8": "","10.0.0.9": "","10.0.0.10": "","10.0.0.11": "","10.0.0.12": "","10.0.0.13": "","10.0.0.14": "","10.0.0.15": "","10.0.0.16": "","10.0.0.17": "","10.0.0.18": "","10.0.0.19": "","10.0.0.20": ""}
  V2R_Map = {}

  def __init__ (self, fakeways = [], arp_for_unknowns = False):
  # "t1" thread performs TimerEventGen function. It contains a while loop that every 4 seconds 
  # changes the virtual IP of the hosts by calling the sub-function "_move_the_target"
    def TimerEventGen():
        self._move_the_target()       
	while 1:
	    time.sleep(15)
	    self._move_the_target()
	    #print "After Timer"
    
  	
    # These are "fake gateways" -- we'll answer ARPs for them with MAC
    # of the switch they're connected to.
    self.fakeways = set(fakeways)
	
    # If this is true and we see a packet for an unknown
    # host, we'll ARP for it.
    self.arp_for_unknowns = arp_for_unknowns

    
    # (dpid,IP) -> expire_time
    # We use this to keep from spamming ARPs
    self.outstanding_arps = {}

    # (dpid,IP) -> [(expire_time,buffer_id,in_port), ...]
    # These are buffers we've gotten at this datapath for this IP which
    # we can't deliver because we don't know where they go.
    self.lost_buffers = {}

    # For each switch, we map IP addresses to Entries
    self.arpTable = {}

    # This timer handles expiring stuff
    self._expire_timer = Timer(2, self._handle_expiration, recurring=True)
    self.listenTo(core)
	#Here we call TimeEventGen that performs bt t1 thread
    t1 = threading.Thread(target = TimerEventGen) 
    t1.start()
	# self.HostMem is another dictionary that links host's IP address to datapath id (dpid) parameter
    self.HostMem = {}
    self.IP_Packets_Table = {}
    self.count = 0
    self.packetin = 0
   
  def _move_the_target (self):
        #log.debug("timer success")
        #random.seed(time())
        pseudo_ranum = random.randint(21, N_IP - 1)
	print("Random Number:", pseudo_ranum)
	for keys in self.R2V_Map.keys():
            #self.R2V_Map[keys] = "10.0."+ str(random.randint(0, 9)) +"." + str(pseudo_ranum)  #space: 5*80
            self.R2V_Map[keys] = "10." + "0" +"."+ "0" +"." + str(pseudo_ranum)
	    #print self.R2V_Map[keys]
            # pseudo_ranum is updated to point to next index (cyclic)
            pseudo_ranum = (pseudo_ranum + 1) % N_IP
        self.V2R_Map = {v: k for k, v in self.R2V_Map.items()}
        print "**********", self.R2V_Map, "***********"
        print "**********", self.V2R_Map, "***********"
	
	# create ofp_flow_mod message to delete all flows
	# (note that flow_mods match all flows by default)
	#msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
 
	# iterate over all connected switches and delete all their flows
#	for connection in core.openflow.connections: # _connections.values() before betta
 # 		connection.send(msg)
  		#log.debug("Clearing all flows from %s." % (dpidToStr(connection.dpid),))

  def isRealIPAddress(self, ipAddr):
        '''Returns True id IP address is real'''
	#print ipAddr
        if ipAddr in self.R2V_Map.keys():
            return True


  def isVirtualIPAddress(self, ipAddr):
        ''' Returns True if the IP address is virtual'''
	#print ipAddr
        if ipAddr in self.R2V_Map.values():
            return True

  def ReturnRealIP (self, ipAddr):
	ip2 = '10.0.0.3'
  	if ipAddr in self.R2V_Map.keys(): 
  		ip2 = ipAddr
  	elif ipAddr in self.R2V_Map.values():
  		#print("Changing DST Virtual IP " + ipAddr + "---> Real DST IP " + V2R_Map[ipAddr])
  		ip2 = V2R_Map[ipAddr]
	#print ipAddr 	
	return ip2
  
  ########################################################

  def _handle_expiration (self):
    # Called by a timer so that we can remove old items.
    empty = []
    for k,v in self.lost_buffers.iteritems():
      dpid,ip = k

      for item in list(v):
        expires_at,buffer_id,in_port = item
        if expires_at < time.time():
          # This packet is old.  Tell this switch to drop it.
          v.remove(item)
          po = of.ofp_packet_out(buffer_id = buffer_id, in_port = in_port)
          core.openflow.sendToDPID(dpid, po)
      if len(v) == 0: empty.append(k)

    # Remove empty buffer bins
    for k in empty:
      del self.lost_buffers[k]

  def _send_lost_buffers (self, dpid, ipaddr, macaddr, port):
    """
    We may have "lost" buffers -- packets we got but didn't know
    where to send at the time.  We may know now.  Try and see.
    """
    if (dpid,ipaddr) in self.lost_buffers:
      # Yup!
      bucket = self.lost_buffers[(dpid,ipaddr)]
      del self.lost_buffers[(dpid,ipaddr)]
      #log.debug("Sending %i buffered packets to %s from %s"
       #         % (len(bucket),ipaddr,dpid_to_str(dpid)))
      for _,buffer_id,in_port in bucket:
        po = of.ofp_packet_out(buffer_id=buffer_id,in_port=in_port)
        po.actions.append(of.ofp_action_dl_addr.set_dst(macaddr))
        po.actions.append(of.ofp_action_output(port = port))
        core.openflow.sendToDPID(dpid, po)

  def _handle_GoingUpEvent (self, event):
    self.listenTo(core.openflow)
    log.debug("Up...")
  def handle_timer_elapse (message):
    print "I was told to tell you:", message
  Timer(10, handle_timer_elapse, args = ["Hello"])
  
  def _handle_PacketIn (self, event):
    self.packetin = self.packetin + 1
    dpid = event.connection.dpid
    inport = event.port
    
    packet = event.parsed
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return

    if dpid not in self.arpTable:
      # New switch -- create an empty table
      print "new switch"
      self.arpTable[dpid] = {}
     
      for fake in self.fakeways:
        self.arpTable[dpid][IPAddr(fake)] = Entry(of.OFPP_NONE,
         dpid_to_mac(dpid))

    if packet.type == ethernet.LLDP_TYPE:
      # Ignore LLDP packets
      return

    flag = 0 
	# This part of code handles packet in and write to file.py count variable that informs 
	# us how many malicious packets Arrived to Virtual IPs
	###################################################################################################  
    if isinstance(packet.next, ipv4)  :
	if (self.isVirtualIPAddress(str(packet.next.dstip))) : 
                flag =1
        elif (self.isRealIPAddress(str(packet.next.dstip))) :
                flag = 1    		
        if (flag == 0) : 
                print "Unknown IP: %s,Dropping packet" % str(packet.next.dstip)

    if isinstance(packet.next, arp):
        print "after if arp: %s " % str(packet.next.protodst)

        if (self.isVirtualIPAddress(str(packet.next.protodst))) :	
                flag = 1
	        self.count = self.count + 1
		print "$$$$$$$$$$ count = %i $$$$$$$$$$" % self.count
        if (flag == 0) : 
                print "Unknown IP: %s,Dropping packet" % str(packet.next.protodst)
    f = open( 'file.py', 'w' )
    f.write( 'count = ' + str(self.count) + '   '+ 'num of packts in:'+ ' ' + str(self.packetin) +  '\n' )
    f.close()
    ########################################################################################

    
    # handling IPV4 packets
    if isinstance(packet.next, ipv4):
      log.debug("%i %i IP %s => %s", dpid,inport, packet.next.srcip,packet.next.dstip)
      srcaddr = packet.next.srcip
      srcaddr_old = packet.next.srcip
      dstaddr = packet.next.dstip 
      dstaddr_old = packet.next.dstip
      # if source is virtual we change it to real      
      if self.isVirtualIPAddress(str(srcaddr)):
        srcaddr = IPAddr(self.V2R_Map[str(srcaddr)])
        print("Changing SRC VIRTUAL IP " + self.R2V_Map[str(srcaddr)] + "---> REAL SRC IP " + str(srcaddr))
     
	  # if destination is virtual we change it to real
      if self.isVirtualIPAddress(str(dstaddr)):
        dstaddr = IPAddr(self.V2R_Map[str(dstaddr)])
        print("Changing DST VIRTUAL IP " + self.R2V_Map[str(dstaddr)] + "---> REAL SRC IP " + str(dstaddr))
	  # if the IP was real we update HostMem (ip---dpid) mapping	
      if self.isRealIPAddress(str(srcaddr_old)) and srcaddr not in self.HostMem.keys():
                self.HostMem[srcaddr] = dpid
      dpid = self.HostMem[srcaddr]
      if self.isRealIPAddress(str(dstaddr_old)) and dstaddr not in self.HostMem.keys():
                self.HostMem[dstaddr] = dpid
      dpid = self.HostMem[dstaddr]
	  
	  #update the correct macaddr
      if self.isVirtualIPAddress(str(srcaddr_old)):
            macaddr = dpid_to_mac(dpid)
      else:
            macaddr = packet.src
      self._send_lost_buffers(dpid, srcaddr, macaddr, inport)
      # Learn or update the correct port/MAC fron arpTable
      if srcaddr in self.arpTable[dpid]:
        if self.arpTable[dpid][srcaddr] != (inport, macaddr):
          log.info("%i %i RE-learned %s", dpid,inport,srcaddr)
      else: log.debug("%i %i learned %s", dpid,inport,str(srcaddr))
	  # if source was real update arpTable
      if (self.isRealIPAddress(str(srcaddr_old))) :
           self.arpTable[dpid][srcaddr] = Entry(inport, macaddr)
      # if source was virtual take the correct values from arpTable
	  # mininet give us wrong values when we use virtual IP
      if self.isVirtualIPAddress(str(srcaddr_old)) :		
      	inport = self.arpTable[dpid][srcaddr].port
        macaddr = self.arpTable[dpid][srcaddr].mac
      
      
      # if we have a destination forward the packet
      if dstaddr in self.arpTable[dpid]:
        
        prt = self.arpTable[dpid][dstaddr].port
        mac = self.arpTable[dpid][dstaddr].mac
        if prt == inport:
          log.warning("%i %i not sending packet for %s back out of the " +
                      "input port" % (dpid, inport, str(dstaddr)))
        else:
          log.debug("%i %i installing flow for %s => %s out port %i"
                    % (dpid, inport, srcaddr, dstaddr, prt))
	  

          actions = []
          actions.append(of.ofp_action_dl_addr.set_dst(mac))
          actions.append(of.ofp_action_output(port = prt))
          match = of.ofp_match.from_packet(packet, inport)
          match.dl_src = None # Wildcard source MAC

          msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=FLOW_IDLE_TIMEOUT,
                                hard_timeout=of.OFP_FLOW_PERMANENT,
                                buffer_id=event.ofp.buffer_id,
                                actions=actions,
                                match=of.ofp_match.from_packet(packet,
                                                               inport))
          event.connection.send(msg.pack())
	  # if we don't have a destination drop the packet. 	  
      elif not (self.isRealIPAddress(str(dstaddr))) or not (self.isRealIPAddress(str(srcaddr)))  : 
          po = of.ofp_packet_out(buffer_id = buffer_id, in_port = in_port)
          core.openflow.sendToDPID(dpid, po)
          log.warning( "Moving Targed Defense has blocked a packet from unknown source" )
      
      
	# handles arp packet
    elif isinstance(packet.next, arp):
      a = packet.next

      log.debug("%i %i ARP %s %s => %s", dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))
      dstaddr2 = a.protodst
      dstaddr2_old = a.protodst
      srcaddr2 = a.protosrc
      srcaddr2_old = srcaddr2
      
      if self.isVirtualIPAddress(str(srcaddr2)):
              srcaddr2 = IPAddr(self.V2R_Map[str(srcaddr2)])
              print("arp: Changing SRC VIRTUAL IP " + self.R2V_Map[str(srcaddr2)] + "---> REAL SRC IP " + str(srcaddr2))
      if self.isVirtualIPAddress(str(dstaddr2)):
        dstaddr2 = IPAddr(self.V2R_Map[str(dstaddr2)])
        print("arp: Changing DST VIRTUAL IP " + self.R2V_Map[str(dstaddr2)] + "---> REAL DST IP " + str(dstaddr2))
      if self.isRealIPAddress(str(srcaddr2_old)) and srcaddr2 not in self.HostMem.keys():
                self.HostMem[srcaddr2] = dpid
      if self.isRealIPAddress(str(dstaddr2_old)) and dstaddr2 not in self.HostMem.keys():
                self.HostMem[dstaddr2] = dpid
      dpid = self.HostMem[srcaddr2]
      if self.isVirtualIPAddress(str(srcaddr2_old)):
            macaddr = dpid_to_mac(dpid)
      else: macaddr = packet.src
      #macaddr = self.arpTable[dpid][srcaddr2].mac
      a.prototype = arp.PROTO_TYPE_IP
      a.hwtype = arp.HW_TYPE_ETHERNET

      if srcaddr2 != 0:

            # Learn or update port/MAC info
            if srcaddr2 in self.arpTable[dpid]:
              if self.arpTable[dpid][srcaddr2] != (inport, macaddr):
                log.info("%i %i RE-learned %s", dpid,inport,str(srcaddr2))
            else:
	      	log.debug("%i %i learned %s", dpid,inport,str(srcaddr2))
            if (self.isRealIPAddress(str(srcaddr2_old))) :
                 self.arpTable[dpid][srcaddr2] = Entry(inport, macaddr)
   	    if self.isVirtualIPAddress(str(srcaddr2_old)) :
        	 #for keys,values in self.HostMem :
           	  # print (keys)
                   #print (values)
                 inport = self.arpTable[dpid][srcaddr2].port
            # Send any waiting packets...
            self._send_lost_buffers(dpid, str(srcaddr2), macaddr, inport)
	    
            if a.opcode == arp.REQUEST:
              # Check if we can answer
	      dstaddr2 = a.protodst
              
              if dstaddr2 in self.arpTable[dpid]:
                # destination exists

                if not self.arpTable[dpid][dstaddr2].isExpired():

                  # We will reply ourselves
                  
                  r = arp()
                  r.hwtype = a.hwtype
                  r.prototype = a.prototype
                  r.hwlen = a.hwlen
                  r.protolen = a.protolen
                  r.opcode = arp.REPLY
                  r.hwdst = a.hwsrc
                  r.protodst = IPAddr(self.ReturnRealIP(srcaddr2))
                  r.protosrc = IPAddr(self.ReturnRealIP(dstaddr2))
                  r.hwsrc = self.arpTable[dpid][dstaddr2].mac
                  e = ethernet(type=packet.type, src=dpid_to_mac(dpid),
                               dst=a.hwsrc)
                  e.set_payload(r)
                  log.debug("%i %i answering ARP for %s" % (dpid, inport,
                   str(r.protosrc)))
                  msg = of.ofp_packet_out()
                  msg.data = e.pack()
                  msg.actions.append(of.ofp_action_output(port =
                                                          of.OFPP_IN_PORT))
                  msg.in_port = inport    
                  event.connection.send(msg)
                  return
				  
			  # if source and dest were not virtual or real we dropp the packet
              elif not (self.isRealIPAddress(str(dstaddr2))) or not (self.isRealIPAddress(str(srcaddr2)))  : 
                  po = of.ofp_packet_out(buffer_id = buffer_id, in_port = in_port)
                  core.openflow.sendToDPID(dpid, po)
                  log.warning( "Moving Targed Defense has blocked a packet from unknown source" )       
     
      srcaddr2_old = srcaddr2
      
	  # unrecognized arp: if source is recognized av Virtual or Real than
	  # we flood the packet throgh the network
	  
      if self.isVirtualIPAddress(str(srcaddr2)):
              srcaddr2 = IPAddr(self.V2R_Map[str(srcaddr2)])
              print("arp flood: Changing SRC VIRTUAL IP " + self.R2V_Map[str(srcaddr2)] + "---> REAL SRC IP " + str(srcaddr2))
      if self.isVirtualIPAddress(str(dstaddr2)):
        dstaddr2 = IPAddr(self.V2R_Map[str(dstaddr2)])
        print("arp flood: Changing DST VIRTUAL IP " + self.R2V_Map[str(dstaddr2)] + "---> REAL DST IP " + str(dstaddr2))
      if self.isRealIPAddress(str(srcaddr2_old)) and srcaddr2 not in self.HostMem.keys():
                self.HostMem[srcaddr2] = dpid
      dpid = self.HostMem[srcaddr2]
      macaddr = self.arpTable[dpid][srcaddr2].mac
      macaddr = dpid_to_mac(dpid)
      if self.isVirtualIPAddress(str(srcaddr2_old)) :	
      	 inport = self.arpTable[dpid][srcaddr2].port
      # just flood it
      log.debug("%i %i flooding ARP %s %s => %s" % (dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), str(srcaddr2), str(dstaddr2)))
      msg = of.ofp_packet_out(in_port = inport, data = event.ofp,
          action = of.ofp_action_output(port = of.OFPP_FLOOD))
      event.connection.send(msg)


# running MTD
def launch (fakeways="", arp_for_unknowns=None):
  fakeways = fakeways.replace(","," ").split()
  fakeways = [IPAddr(x) for x in fakeways]
  if arp_for_unknowns is None:
    arp_for_unknowns = len(fakeways) > 0
  else:
    arp_for_unknowns = str_to_bool(arp_for_unknowns)
  core.registerNew(l3_switch, fakeways, arp_for_unknowns)


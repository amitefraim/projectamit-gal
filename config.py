#!/usr/bin/python

#Final Project - Our script for testing Moving Target Defense
#Created by: Gal Aharon & Amit Efraim 

"""
test.py: We ping to random addresses to test MTD

"""

from mininet.net import Mininet
from mininet.node import Node,RemoteController
from mininet.topo import SingleSwitchTopo
from mininet.log import setLogLevel
from mininet.cli import CLI
from select import poll, POLLIN
from time import time
from functools import partial
import random
import time


def randpings( host, targetips ):
    "host should try to ping targetips (chosen ip)"
    cmd = ( 'while true; do '
            ' for ip in %s; do ' % targetips +
            '  echo -n %s "->" $ip ' % host.IP() +
            '   `ping -c1 -w 1 $ip | grep packets` ;'
            '  sleep 1;'
            ' done; '
            'done &' )

    print ( '*** Host %s (%s) will be pinging ips: %s' %
            ( host.name, host.IP(), targetips ) )

    host.cmd( cmd )

def multiping( netsize, seconds):
    "Ping randomly"
	#create single switch topology
    topo = SingleSwitchTopo( netsize ) 
    #create mininet object with remote controller
    net = Mininet( topo=topo, controller=partial( RemoteController, ip='127.0.0.1', port=6633 ) ) 
    net.start()
    net.pingAll()
    #ping between all hosts to update the tables
    print 'pingAll finished!'
    hosts = net.hosts
    i=0
    j=0
    while (j<100)  :
       while (i<5) :
           pseudo_ranum = random.randint(21, 99)
           i=i+1
           randpings( hosts[0],"10." + "0" +"."+ "0" +"." + str(pseudo_ranum)) 
		   #ping from chosen host (malicious) to random address (Vip = 80 addresses)
		   #here we assume that the attacker knows the Virtual address space 
       time.sleep( 1 )
       print j
       j=j+1
       i=0
    #Our random worm tries to send packets to our hosts    

    # Stop pings
    for host in hosts:
        host.cmd( 'kill %while' )

    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    multiping( netsize=20, seconds=10 ) #call multiping with 20 hosts

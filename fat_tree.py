#!/usr/bin/python

"""
This setup the topology in lab3-part3
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.util import dumpNodeConnections
from mininet.link import Link, Intf, TCLink
import os 
from time import sleep
import sys
N = 4 

class Topology(Topo):
    
    
    def __init__(self):
        "Create Topology." 
        Topo.__init__(self)

        core_switches = []
        for i in range(N // 2):
            core_switch = self.addSwitch(f's{i+1}')
            core_switches.append(core_switch)

        edge_switches = []
        for i in range(N):
            edge_switch = self.addSwitch(f's{len(core_switches) + i + 1}')
            edge_switches.append(edge_switch)

        for i in range(N // 2):
            for j in range(N):
                self.addLink(core_switches[i], edge_switches[j])

        for i in range(N):
            for j in range(N // 2):
                host = self.addHost(f'h{i*N//2+j+1}')
                self.addLink(host, edge_switches[i])

# This is for "mn --custom"
topos = { 'mytopo': ( lambda: Topology() ) }

# This is for "python *.py"
if __name__ == '__main__':
    setLogLevel( 'info' )
            
    topo = Topology()
    net = Mininet(topo=topo, link=TCLink)       # The TCLink is a special setting for setting the bandwidth in the future.
    
    # 1. Start mininet
    net.start()
    
    
    # Wait for links setup (sometimes, it takes some time to setup, so wait for a while before mininet starts)
    print "\nWaiting for links to setup . . . .",
    sys.stdout.flush()
    for time_idx in range(3):
        print ".",
        sys.stdout.flush()
        sleep(1)
    
        
    # 2. Start the CLI commands
    info( '\n*** Running CLI\n' )
    CLI( net )
    
    
    # 3. Stop mininet properly
    net.stop()


    ### If you did not close the mininet, please run "mn -c" to clean up and re-run the mininet 

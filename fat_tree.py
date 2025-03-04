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
import argparse  # 引入 argparse 模块

# 定义拓扑类
class Topology(Topo):
    def __init__(self, N):
        "Create Topology."
        Topo.__init__(self)

        core_switches = []
        for i in range(N // 2):
            name = "s" + str(i + 1)
            core_switch = self.addSwitch(name)
            core_switches.append(core_switch)

        edge_switches = []
        for i in range(N):
            name = "s" + str(len(core_switches) + i + 1)
            edge_switch = self.addSwitch(name)
            edge_switches.append(edge_switch)

        for i in range(N // 2):  # For layer 1
            for j in range(N):  # For layer 2
                self.addLink(core_switches[i], edge_switches[j])

        for i in range(N):  # For each switch in layer 2
            for j in range(N // 2):  # For each host in current subnet
                name = "h" + str(i * N // 2 + j + 1)
                host = self.addHost(name)
                self.addLink(host, edge_switches[i])

# 定义 topos 字典，用于 "mn --custom"
topos = {'mytopo': (lambda N=4: Topology(N))}  # 默认 N=4

# 主程序
if __name__ == '__main__':
    setLogLevel('info')

    # 使用 argparse 解析命令行参数
    parser = argparse.ArgumentParser(description='Fat Tree Topology')
    parser.add_argument('--N', type=int, default=4, help='Number of edge switches and core switches (default: 4)')
    args = parser.parse_args()

    # 创建拓扑
    topo = Topology(args.N)
    net = Mininet(topo=topo, link=TCLink)  # The TCLink is a special setting for setting the bandwidth in the future.

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
    info('\n*** Running CLI\n')
    CLI(net)

    # 3. Stop mininet properly
    net.stop()

    ### If you did not close the mininet, please run "mn -c" to clean up and re-run the mininet

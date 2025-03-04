from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.node import RemoteController

N = 4 

class FatTreeTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        core_switches = []
        for i in range(N // 2):
            core_switch = self.addSwitch(f'cs{i+1}')
            core_switches.append(core_switch)

        edge_switches = []
        for i in range(N):
            edge_switch = self.addSwitch(f'es{i+1}')
            edge_switches.append(edge_switch)

        for i in range(N // 2):
            for j in range(N):
                self.addLink(core_switches[i], edge_switches[j])

        for i in range(N):
            for j in range(N // 2):
                host = self.addHost(f'h{i*N//2+j+1}')
                self.addLink(host, edge_switches[i])

def run_experiment():
    topo = FatTreeTopo()
    ctrl = RemoteController('ryu', ip='127.0.0.1', port=6633)
    net = Mininet(topo=topo, controller=ctrl)
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_experiment()
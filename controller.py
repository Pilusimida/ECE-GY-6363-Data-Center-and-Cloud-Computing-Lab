from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, icmp
from ryu.lib.packet import tcp as tcp_pkt
from ryu.lib.packet import udp as udp_pkt
from ryu.lib.packet import icmp as icmp_pkt
from ryu.lib.packet import ipv4 as ipv4_pkt
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
import networkx as nx
from ryu.topology.api import get_switch
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link

class PolicySDN(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PolicySDN, self).__init__(*args, **kwargs)
        self.net = nx.DiGraph()
        self.topology_api_app = self
        self.network = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath, buffer_id=buffer_id,
                priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches=[switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        self.net.clear()
        self.net.add_nodes_from(switches)
        self.net.add_edges_from(links)
        self.logger.info("Topology updated: %s nodes, %s edges", 
                        len(self.net.nodes), len(self.net.edges))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        src = eth.src
        dst = eth.dst

        ip = pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)

        if src not in self.net.nodes:
            self.AddHost(src, dpid, in_port)

        # ARP
        pk_arp = pkt.get_protocol(arp.arp)
        if pk_arp:
            self.arp(src, dst, in_port, datapath, msg)
            return


        if pkt_icmp or pkt_tcp:
            self.icmp_tcp(datapath, msg, pkt_icmp, pkt_tcp)
            return
        
        if pkt_udp:
            self.udp(datapath, msg, pkt_udp)



    def udp(self, datapath, msg, pkt_udp):

        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        src = eth.src
        dst = eth.dst
        ip = pkt.get_protocol(ipv4.ipv4)

        # Get switch MAC
        switch_macs = [self.net.nodes[n]['switch'] for n in self.net.nodes if 'switch' in self.net.nodes[n]]
        if src in switch_macs:
            self.logger.info("Ignore ICMP from switch: %s", src)
            return

        self.logger.info("[ICMP] Packet from %s to %s", src, dst)
        if dst in self.net.nodes:
            # ICMP -- clockwise path
            paths = list(nx.all_shortest_paths(self.net, dpid, self.net.nodes[dst]['switch']))
            if len(paths) == 2:
                closewise = self.find_clockwise_path(paths)
                counterclosewise = 1 - closewise
                path = paths[counterclosewise]
            else:
                path = paths[0]

            if len(path) == 1:
                out_port = self.net.nodes[dst]['port']
                actions = [parser.OFPActionOutput(out_port)]

                match = parser.OFPMatch(
                    eth_type=0x0800, 
                    ipv4_src=ip.src, 
                    ipv4_dst=ip.dst, 
                    ip_proto=1  # ICMP
                )

                self.add_flow(datapath, priority=100, match=match, actions=actions)
                data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id,
                    in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)

                return


            next_hop = path[1]
            out_port = self.net[dpid][next_hop]['port']
            
            actions = [parser.OFPActionOutput(out_port)]

            if pkt_udp:
                if ip.src == '10.0.0.4' or ip.src == '10.0.0.1':
                    match = parser.OFPMatch(
                        eth_type=0x0800,  # IPv4
                        ipv4_src=ip.src,
                        ipv4_dst=ip.dst,
                        ip_proto=17,       # UDP
                    )
                    actions = []
                    self.add_flow(datapath, priority=100, match=match, actions=actions)
                else:
                    match = parser.OFPMatch(
                        eth_type=0x0800,  # IPv4
                        ipv4_src=ip.src,
                        ipv4_dst=ip.dst,
                        ip_proto=17,       # UDP
                    )
                    self.add_flow(datapath, priority=100, match=match, actions=actions)



            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

    def arp(self, src, dst, in_port, datapath, msg):
        # add the host to the network graph to calculate the shortest path
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if src not in self.net.nodes:
            self.AddHost(src, dpid, in_port)
            actions = [parser.OFPActionOutput(in_port)]
            match = parser.OFPMatch(eth_type=0x0806, eth_dst=src)
            self.add_flow(datapath, priority=100, match=match, actions=actions)
   
        if dst in self.net.nodes:
            # to find the shortest path
            path = nx.shortest_path(self.net, dpid, self.net.nodes[dst]['switch'])
            
            if len(path) == 1:
                out_port = self.net.nodes[dst]['port']
                actions = [parser.OFPActionOutput(out_port)]

                match = parser.OFPMatch(
                    eth_type=0x0806, 
                    eth_dst = dst,
                )

                self.add_flow(datapath, priority=100, match=match, actions=actions)
                data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id,
                    in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                return
            
            next_hop = path[1]
            out_port = self.net[dpid][next_hop]['port']
            # print("find path: ", src, dst, next_hop, self.net[dpid])

        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(eth_type=0x0806, eth_dst = dst)
            self.add_flow(datapath, priority=100, match=match, actions=actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    def find_clockwise_path(self, paths):
        for i in range(len(paths)):
            path = paths[i]
            curr = path[0]
            next_val = path[1]
            if next_val == (curr % 4) + 1:
                return i
            else:
                continue

    def icmp_tcp(self, datapath, msg, pkt_icmp, pkt_tcp):

        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        src = eth.src
        dst = eth.dst
        ip = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)

        # 获取交换机的 MAC 地址列表
        switch_macs = [self.net.nodes[n]['switch'] for n in self.net.nodes if 'switch' in self.net.nodes[n]]
        if src in switch_macs:
            return

        if dst in self.net.nodes:
            # define the block hosts
            blocked_hosts = {'10.0.0.2', '10.0.0.4'}

            if pkt_tcp:
                tcp_info = pkt.get_protocol(tcp.tcp) 
                # block and send tcp rst
                if ip.src in blocked_hosts and tcp_info.dst_port == 80:
                    identification = ip.identification

                    seq = tcp_info.ack
                    ack = tcp_info.seq + 1

                    self.send_tcp_rst(
                        datapath=datapath, 
                        src_ip=ip.dst, 
                        dst_ip=ip.src, 
                        src_eth=dst,
                        dst_eth=src, 
                        src_port=tcp_info.dst_port, 
                        dst_port=tcp_info.src_port, 
                        identification_number=identification,
                        seq=seq,
                        ack=ack,
                        in_port=in_port
                    )
                    return

            # ICMP -- closewise
            paths = list(nx.all_shortest_paths(self.net, dpid, self.net.nodes[dst]['switch']))
            if len(paths) == 2:
                closewise = self.find_clockwise_path(paths)
                path = paths[closewise]
            else:
                path = paths[0]
            
            if len(path) == 1:
                out_port = self.net.nodes[dst]['port']
                actions = [parser.OFPActionOutput(out_port)]

                match = parser.OFPMatch(
                    eth_type=0x0800, 
                    ipv4_src=ip.src, 
                    ipv4_dst=ip.dst, 
                    ip_proto=1
                )

                self.add_flow(datapath, priority=100, match=match, actions=actions)
                data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id,
                    in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                return

            next_hop = path[1]
            out_port = self.net[dpid][next_hop]['port']
            
            actions = [parser.OFPActionOutput(out_port)]

            if pkt_icmp:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip.src, ipv4_dst=ip.dst, ip_proto=1)
                self.add_flow(datapath, priority=100, match=match, actions=actions)

            if pkt_tcp:
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=ip.src,
                    ipv4_dst=ip.dst,
                    ip_proto=6
                )
                self.add_flow(datapath, priority=100, match=match, actions=actions)

            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

    #TCP RST
    def send_tcp_rst(self, datapath, src_ip, dst_ip, src_eth, dst_eth, src_port, dst_port, identification_number, seq, ack, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        eth = ethernet.ethernet(dst = dst_eth, src = src_eth, ethertype = 0x0800)
        ip = ipv4.ipv4(src = src_ip, dst = dst_ip, proto = 6, identification = identification_number)
    
        # ip = ipv4.ipv4(dst=src_ip, src=dst_ip, identification = identification_number, proto=6)
        tcp_rst = tcp.tcp(src_port=src_port, dst_port=dst_port, seq=seq, ack=ack, bits=(tcp.TCP_RST | tcp.TCP_ACK))

        pkt = packet.Packet()
        pkt.add_protocol(eth)
        pkt.add_protocol(ip)
        pkt.add_protocol(tcp_rst)
        pkt.serialize()


        actions = [parser.OFPActionOutput(in_port)]

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data)

        datapath.send_msg(out)


    def AddHost(self, mac, dpid, in_port):
            self.net.add_node(mac)
            self.net.add_edge(dpid, mac, port=in_port)
            self.net.add_edge(mac, dpid)

            self.net.nodes[mac]['switch'] = dpid
            self.net.nodes[mac]['port'] = in_port
            self.logger.info("Added host %s to switch %s at port %s", mac, dpid, in_port)
        
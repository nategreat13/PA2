'''
    Author: Nathan Gygi
    u0773016
    March 22, 2019
'''

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types
from ryu import cfg

'''
    A simple controller that intercepts ARP and PING
    messages and prints out valuable information.
'''
class monitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(monitor, self).__init__(*args, **kwargs)
        CONF = cfg.CONF
        CONF.register_opts([
            cfg.IntOpt('front_end_testers', default=0, help = ('Number of Front End Machines')),
            cfg.IntOpt('back_end_servers', default=0, help = ('Number of Back End Machines')),
            cfg.StrOpt('virtual_ip', default='default', help = ('Virtual IP'))])

        self.num_front_end = CONF.front_end_testers
        self.num_back_end = CONF.back_end_servers
        self.virtual_ip = CONF.virtual_ip
        
        self.back_end_connection_counts = []
        self.back_end_physical_addresses = []
        self.back_end_mac_addresses = []
        self.back_end_ports = []
        for i in range(self.num_back_end):
            self.back_end_connection_counts.append(0)
            server_number = i + self.num_front_end + 1
            self.back_end_physical_addresses.append('10.0.0.' + str(server_number))
            if server_number < 16:
                self.back_end_mac_addresses.append('00:00:00:00:00:0' + hex(server_number)[2:])
            else:
                self.back_end_mac_addresses.append('00:00:00:00:00:' + hex(server_number)[2:])
            self.back_end_ports.append(server_number)

        self.next_server_address_index = 0 # Keep track of which back end server to assign the host to
        self.packet_count = 1 # Counter for the packet number

    '''
        Handles packet in events
    '''
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # Get message
        msg = ev.msg

        # Get packet out of message
        pkt = packet.Packet(data=msg.data)

        # Get the arp packet and parse it if it exists
        pkt_arp = pkt.get_protocol(arp.arp)
        
        if pkt_arp:
            self.parse_arp(pkt_arp, msg, pkt)
            self.packet_count += 1
            return

    '''
        Parses an arp packet and prints important information
    '''
    def parse_arp(self, pkt_arp, msg, pkt):
        eth = pkt.get_protocol(ethernet.ethernet) # Get the ethernet packet
        
        # Get important information from the msg and eth packet
        in_port = msg.match['in_port']
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dst = eth.dst
        src = eth.src
        
        for i in range(self.num_back_end):
            if src == self.back_end_mac_addresses[i]:
                return
        if pkt_arp.dst_ip != self.virtual_ip:
            return

        # Get index of next server to use and increment its count
        index = self.next_server_address_index
        self.back_end_connection_counts[index] += 1
        
        # Update the next server index to know which back end to use next
        self.next_server_address_index += 1
        
        # If we get to the end of the list of back ends, start again at the beginning
        if self.next_server_address_index == self.num_back_end:
            self.next_server_address_index = 0
        
        # Get the actual mac and ip of the backend that will be assigned to the host
        dst_mac = self.back_end_mac_addresses[index]
        dst_ip = self.back_end_physical_addresses[index]
        back_end_port = self.back_end_ports[index]

        # Create the eth and arp packets to send to the requesting
        # host and combine them into one packet
        eth_pkt = ethernet.ethernet(dst=pkt_arp.src_mac, src=dst_mac, ethertype=ether.ETH_TYPE_ARP)
        arp_pkt = arp.arp(hwtype=pkt_arp.hwtype,proto=pkt_arp.proto,hlen=pkt_arp.hlen,plen=pkt_arp.plen,opcode=pkt_arp.opcode,src_mac=dst_mac,src_ip=self.virtual_ip,
                    dst_mac=pkt_arp.src_mac, dst_ip=pkt_arp.src_ip)
        p = packet.Packet()
        p.add_protocol(eth_pkt)
        p.add_protocol(arp_pkt)
        p.serialize()

        # Send the packet to the requesting host to update their arp table
        # to point to the assigned backend
        data = p.data
        actions = [parser.OFPActionOutput(port=in_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)

        datapath.send_msg(out)

        # Create the eth and arp packets to send to the back_end
        # host and combine them into one packet
#        eth_pkt = ethernet.ethernet(dst=dst_mac, src=pkt_arp.src_mac, ethertype=ether.ETH_TYPE_ARP)
#        arp_pkt = arp.arp(hwtype=pkt_arp.hwtype,proto=pkt_arp.proto,hlen=pkt_arp.hlen,plen=pkt_arp.plen,opcode=pkt_arp.opcode,src_mac=pkt_arp.src_mac,src_ip=pkt_arp.src_ip,
#                              dst_mac=dst_mac, dst_ip=dst_ip    )
#        p = packet.Packet()
#        p.add_protocol(eth_pkt)
#        p.add_protocol(arp_pkt)
#        p.serialize()
#
#        # Send the packet to the back_end server to update their
#        # arp table to point to the requesting host
#        data = p.data
#        actions = [parser.OFPActionOutput(port=back_end_port)]
#        out = parser.OFPPacketOut(datapath=datapath,
#                              buffer_id=ofproto.OFP_NO_BUFFER,
#                              in_port=ofproto.OFPP_CONTROLLER,
#                              actions=actions,
#                              data=data)
#
#        datapath.send_msg(out)

#        match = parser.OFPMatch(in_port=in_port, ipv4_dst=self.virtual_ip)
#        actions = [parser.OFPActionSetField(ipv4_dst=dst_ip), parser.OFPActionOutput(back_end_port)]
#        self.add_flow(datapath, 1, match, actions)
#
#        match = parser.OFPMatch(in_port=back_end_port, ipv4_src=dst_ip, ipv4_dst=src_ip)
#        actions = [parser.OFPActionSetField(ipv4_src=self.virtual_ip) parser.OFPActionOutput(in_port)]
#        self.add_flow(datapath, 1, match, actions)

                
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        self.logger.info("--------------------")
        self.logger.info("Adding Flow: %s",mod)
        self.logger.info("--------------------")
        datapath.send_msg(mod)


        

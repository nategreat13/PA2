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
        for i in range(self.num_back_end):
            self.back_end_connection_counts.append(0)
            server_number = i + self.num_front_end + 1
            self.back_end_physical_addresses.append('10.0.0.' + str(server_number))
            if server_number < 16:
                self.back_end_mac_addresses.append('00:00:00:00:00:0' + hex(server_number)[2:])
            else:
                self.back_end_mac_addresses.append('00:00:00:00:00:' + hex(server_number)[2:])

        print(self.back_end_physical_addresses)
        print(self.back_end_mac_addresses)
        
        self.next_server_address_index = 0
        
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
        pkt_eth = pkt.get_protocol(ethernet.ethernet) # Get the ethernet packet
        
        in_port = msg.match['in_port']

        datapath = msg.datapath
        address, port = msg.datapath.address # Get the switch address and port

        # Print out important information
        self.logger.info("--------------------------------------------")
        self.logger.info("Packet ( %s) Received on Port(%s) Eth ARP", self.packet_count, msg.match['in_port'])
        self.logger.info("\tARP")
        self.logger.info("\t\tSrc  IP: %s", pkt_arp.src_ip)
        self.logger.info("\t\tDest IP: %s", pkt_arp.dst_ip)
        self.logger.info("\t\tSrc  MAC: %s", pkt_arp.src_mac)
        self.logger.info("\t\tDest MAC: %s", pkt_arp.dst_mac)
        self.logger.info("\tNOT IPV4")
        self.logger.info("\tNOT IPV6")
        self.logger.info("\tETH")
        self.logger.info("\t\tFrom MAC: %s", pkt_eth.src)
        self.logger.info("\t\tTo   MAC: %s", pkt_eth.dst)
        self.logger.info("\tController Switch (OF)")
        self.logger.info("\t\tAddress, Port: ('%s', %s)", address, port)
        
        # Get index of next server to use
        index = self.next_server_address_index
        self.back_end_connection_counts[dst_mac] += 1

        self.next_server_address_index += 1
        if self.next_server_address_index == self.num_back_end:
            self.next_server_address_index = 0

        dst_mac = self.back_end_mac_addresses[index]
        dst_ip = self.back_end_physical_addresses[index]

        eth_pkt = ethernet.ethernet(dst=dst_mac, src=pkt_arp.src_mac, ethertype=ether.ETH_TYPE_ARP)
        arp_pkt = arp.arp(hwtype=pkt_arp.hwtype,proto=pkt_arp.proto,hlen=pkt_arp.hlen,plen=pkt_arp.plen,opcode=pkt_arp.opcode,src_mac=pkt_arp.src_mac,src_ip=pkt_arp.src_ip,
                    dst_mac=dst_mac, dst_ip=dst_ip)
        packet = packet.Packet()
        packet.add_protocol(eth_pkt)
        packet.add_protocol(arp_pkt)
        packet.serialize()

        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info("packet-out %s" % (packet,))
        data = packet.data
        actions = [parser.OFPActionOutput(port=in_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

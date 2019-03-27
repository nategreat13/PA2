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
            cfg.IntOpt('back_end_testers', default=0, help = ('Number of Back End Machines')),
            cfg.StrOpt('virtual_ip', default='default', help = ('Virtual IP'))])

        num_front_end = CONF.front_end_testers
        num_back_end = CONF.back_end_testers
        virtual_ip = CONF.virtual_ip
        
        print(num_front_end)
        print(num_back_end)
        
        back_end_physical_addresses = []
        back_end_connection_counts = []
        for i in range(num_back_end):
            back_end_connection_counts.append(0)
            back_end_physical_addresses.append('10.0.0.' + str(i + num_front_end + 1))
        print(back_end_physical_addresses)
        
        
        
        self.packet_count = 1 # Counter for the packet number
        
        self.h5count = 0
        self.h6count = 0

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
        
        dst_mac = ''
        
        if self.h5count > self.h6count:
            print("Send to h6")
            dst_mac = '00:00:00:00:00:06'
            self.h6count += 1
        else:
            print("Send to h5")
            dst_mac = '00:00:00:00:00:05'
            self.h5count += 1

        e = ethernet.ethernet(dst=dst_mac, src=pkt_arp.src_mac, ethertype=ether.ETH_TYPE_ARP)
        a = arp.arp(hwtype=pkt_arp.hwtype,proto=pkt_arp.proto,hlen=pkt_arp.hlen,plen=pkt_arp.plen,opcode=pkt_arp.opcode,src_mac=pkt_arp.src_mac,src_ip=pkt_arp.src_ip,
                    dst_mac=dst_mac, dst_ip=pkt_arp.dst_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        print("%s", p)

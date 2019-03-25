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
        self.packet_count = 1 # Counter for the packet number
        CONF = cfg.CONF
#        CONF.register_opts([ cfg.IntOpt('front_end_testers', default=0, help = ('Number of Front End Machines')), cfg.IntOpt('back_end_testers', default=0, help = ('Number of Back End Machines')), cfg.StrOpt('virtual_ip', default='default', help = ('Virtual IP'))
#
#        print 'front_end_testers = {}'.format(CONF.front_end_testers))
#        print 'back_end_testers = {}'.format(CONF.back_end_testers))
#        print 'virtual_ip = {}'.format(CONF.virtual_ip))
    
#    '''
#        Handles packet in events
#    '''
#    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
#    def packet_in_handler(self, ev):
#        # Get message
#        msg = ev.msg
#
#        # Get packet out of message
#        pkt = packet.Packet(data=msg.data)
#
#        # Get the arp packet and parse it if it exists
#        pkt_arp = pkt.get_protocol(arp.arp)
#        if pkt_arp:
#            self.parse_arp(pkt_arp, msg, pkt)
#            self.packet_count += 1
#            return
#
#        # Get the ICMP packet and parse it if it exists
#        pkt_icmp = pkt.get_protocol(icmp.icmp)
#        if pkt_icmp:
#            self.parse_icmp(pkt_icmp, msg, pkt)
#            self.packet_count += 1
#            return
#
#    '''
#        Parses an arp packet and prints important information
#    '''
#    def parse_arp(self, pkt_arp, msg, pkt):
#        pkt_eth = pkt.get_protocol(ethernet.ethernet) # Get the ethernet packet
#
#        datapath = msg.datapath
#        address, port = msg.datapath.address # Get the switch address and port
#
#        # Print out important information
#        self.logger.info("--------------------------------------------")
#        self.logger.info("Packet ( %s) Received on Port(%s) Eth ARP", self.packet_count, msg.match['in_port'])
#        self.logger.info("\tARP")
#        self.logger.info("\t\tSrc  IP: %s", pkt_arp.src_ip)
#        self.logger.info("\t\tDest IP: %s", pkt_arp.dst_ip)
#        self.logger.info("\t\tSrc  MAC: %s", pkt_arp.src_mac)
#        self.logger.info("\t\tDest MAC: %s", pkt_arp.dst_mac)
#        self.logger.info("\tNOT IPV4")
#        self.logger.info("\tNOT IPV6")
#        self.logger.info("\tETH")
#        self.logger.info("\t\tFrom MAC: %s", pkt_eth.src)
#        self.logger.info("\t\tTo   MAC: %s", pkt_eth.dst)
#        self.logger.info("\tController Switch (OF)")
#        self.logger.info("\t\tAddress, Port: ('%s', %s)", address, port)
#
#    '''
#        Parses an ICMP packet and prints important information
#    '''
#    def parse_icmp(self, pkt_icmp, msg, pkt):
#        pkt_eth = pkt.get_protocol(ethernet.ethernet) # Get the ethernet packet
#
#        datapath = msg.datapath
#        address, port = msg.datapath.address # Get the switch address and port
#
#        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4) # Get the ipv4 packet if it exists
#
#        # Print out important information
#        self.logger.info("--------------------------------------------")
#        self.logger.info("Packet ( %s) Received on Port(%s) Eth PING", self.packet_count, msg.match['in_port'])
#        self.logger.info("\tPING")
#        self.logger.info("\tIPV4")
#        self.logger.info("\t\tCheck Sum: %s", pkt_ipv4.csum)
#        self.logger.info("\t\tFrom IP: %s", pkt_ipv4.src)
#        self.logger.info("\t\tTo   IP: %s", pkt_ipv4.dst)
#        self.logger.info("\t\tLength: %s", pkt_ipv4.total_length)
#        self.logger.info("\tNot IPV6")
#        self.logger.info("\tETH")
#        self.logger.info("\t\tFrom MAC: %s", pkt_eth.src)
#        self.logger.info("\t\tTo   MAC: %s", pkt_eth.dst)
#        self.logger.info("\tController Switch (OF)")
#        self.logger.info("\t\tAddress, Port: ('%s', %s)", address, port)
#

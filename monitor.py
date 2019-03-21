from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types

class monitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(monitor, self).__init__(*args, **kwargs)
        self.packet_count = 1
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # Get message
        msg = ev.msg
        
        # Get packet out of message
        pkt = packet.Packet(data=msg.data)
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self.parse_arp(pkt_arp, msg, pkt)
            return
        
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src
        
    def parse_arp(self, pkt_arp, msg, pkt):
        src_ip = pkt_arp.src_ip
        dst_ip = pkt_arp.dst_ip
        src_mac = pkt_arp.src_mac
        dst_mac = pkt_arp.dst_mac
        
        datapath = msg.datapath
        port = msg.match['in_port']
        self.logger.info("----------------------")
        self.logger.info("Packet ( %s) Received on Port(%s) Eth ARP", self.packet_count, port)
        self.logger.info("\tARP")
        self.logger.info("\t\tSrc  IP: %s", src_ip)
        self.logger.info("\t\tDest IP: %s", dst_ip)
        self.logger.info("\t\tSrc  MAC: %s", src_mac)
        self.logger.info("\t\tDest MAC: %s", dst_mac)
        
        self.packet_count += 1

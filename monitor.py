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
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # Get message
        msg = ev.msg
        
        # Get packet out of message
        pkt = packet.Packet(data=msg.data)
        
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src
        
        pkt_arp = pkt.get_protocol(arp.arp)
        src_ip = pkt_arp.src_ip
        dst_ip = pkt_arp.dst_ip

        datapath = msg.datapath
        port = msg.match['in_port']

        self.logger.info("In port %s", port)
        self.logger.info("src, dst %s %s", src, dst)
        self.logger.info("src_ip, dst_ip %s %s", src_ip, dst_ip)

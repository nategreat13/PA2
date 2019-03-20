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
        msg = ev.msg
        datapath = msg.datapath
        port = msg.match['in_port']
        pkt = packet.Packet(data=msg.data)
        self.logger.info("packet-in %s" % (pkt,))
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return
        pkt_arp = pkt.get_protocol(arp.arp)


#
#        msg = ev.msg
#        pkt = packet.Packet(msg.data)
#        eth = pkt.get_protocol(ethernet.ethernet)
#        arp = pkt.get_protocol(arp.arp)
#
#        dst = eth.dst
#        src = eth.src
#
#        src_ip = arp.src_ip
#        dst_ip = arp.dst_ip
#
#        self.logger.info("packet in %s %s", src, dst)
#        self.logger.info("packet in %s %s", src_ip, dst_ip)

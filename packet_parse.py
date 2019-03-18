from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
import array

class packet_parse(app_manager.RyuApp):
    
    def __init__(self, *args, **kwargs):
        super(packet_parse, self).__init__(*args, **kwargs)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        pkt = packet.Packet(array.array('B', ev.msg.data))
        for p in pkt.protocols:
            print p



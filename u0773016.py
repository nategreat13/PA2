'''
    Author: Nathan Gygi
    u0773016
    University of Utah
    CS 4480
    April 8, 2019
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
    This is a load balancing RYU controller that only handles ARP requests. 
    Given a number of front end machines, a number of back end servers, and
    a virtual IP address, the controller assigns each inquiring host to a
    back end server in a round robin fashion, alternating which server is
    assigned, in order to ensure a balance. An optional config file can
    be provided to specify the number of front end and back end machines, 
    as well as a specific virtual IP address.
'''


class monitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    '''
        This function initializes the environment and helper variables and functions.
    '''
    def __init__(self, *args, **kwargs):
        super(monitor, self).__init__(*args, **kwargs)

        # Read the config file if it is provided
        CONF = cfg.CONF
        CONF.register_opts([
            cfg.IntOpt('front_end_testers', default=0, help=('Number of Front End Machines')),
            cfg.IntOpt('back_end_servers', default=0, help=('Number of Back End Machines')),
            cfg.StrOpt('virtual_ip', default='default', help=('Virtual IP'))])

        # Get the values from the config file
        self.num_front_end = CONF.front_end_testers
        self.num_back_end = CONF.back_end_servers
        self.virtual_ip = CONF.virtual_ip

        # If num_front_end == 0, assume there was no config file,
        # and set values to the default topology
        if (self.num_front_end == 0):
            self.num_front_end = 4
            self.num_back_end = 2
            self.virtual_ip = '10.0.0.10'

        # Initiate lists to hold the back end IP addresses, MAC addresses, and ports
        self.back_end_physical_addresses = []
        self.back_end_mac_addresses = []
        self.back_end_ports = []

        # Fill the lists with the appropriate information for the back ends
        for i in range(self.num_back_end):
            server_number = i + self.num_front_end + 1
            self.back_end_physical_addresses.append('10.0.0.' + str(server_number))
            if server_number < 16:
                self.back_end_mac_addresses.append('00:00:00:00:00:0' + hex(server_number)[2:])
            else:
                self.back_end_mac_addresses.append('00:00:00:00:00:' + hex(server_number)[2:])
            self.back_end_ports.append(server_number)

        # Initiate dictionary to hold front end IP to MAC mappings
        self.front_end_ip_to_mac = {}
        for i in range(self.num_front_end):
            front_end_number = i + 1
            front_end_mac = ''
            if front_end_number < 16:
                front_end_mac = '00:00:00:00:00:0' + hex(front_end_number)[2:]
            else:
                front_end_mac = '00:00:00:00:00:' + hex(front_end_number)[2:]
            self.front_end_ip_to_mac['10.0.0.' + str(front_end_number)] = front_end_mac

        # Initiate a list to keep track of Host Mac Addresses
        # that have already been assigned to back end servers
        self.front_end_macs_served = []
        self.front_end_ips_served = []

        # Keep track of which back end server to assign the host to
        self.next_server_address_index = 0


    '''
        Handles packet in events
    '''
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # Get message
        msg = ev.msg

        # Get packet out of message
        pkt = packet.Packet(data=msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)

        #        if eth.ethertype != ether_types.ETH_TYPE_ARP:
        #            return

        # Get the arp packet and parse it if it exists
        pkt_arp = pkt.get_protocol(arp.arp)

        # Only do something if we receive an ARP message
        if pkt_arp:
            self.parse_arp(pkt_arp, msg, pkt)
            return

    '''
        Parses an arp packet and sends appropriate ARP replies and Flow Mod messages
    '''
    def parse_arp(self, pkt_arp, msg, pkt):

        # Get the ethernet part of the packet
        eth = pkt.get_protocol(ethernet.ethernet)  # Get the ethernet packet

        # Get important information from the msg and eth packet
        in_port = msg.match['in_port']
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dst = eth.dst
        src = eth.src

        self.logger.info("--------------------")
        self.logger.info("ARP Request from %s to %s on Port %s", src, pkt_arp.dst_ip, in_port)

        # If the packet destination is a MAC we have handled, send
        # an arp request back to the back end to update it's ARP table
        for i in range(len(self.front_end_ips_served)):
            if pkt_arp.dst_ip == self.front_end_ips_served[i]:
                # Create the eth and arp packets to send to the requesting
                # front end and combine them into one packet
                front_end_mac = self.front_end_ip_to_mac[pkt_arp.dst_ip]
                dst_mac = "" + pkt_arp.src_mac
                src_ip = "" + pkt_arp.dst_ip
                dst_ip = "" + pkt_arp.src_ip
                eth_pkt = ethernet.ethernet(dst=dst_mac, src=front_end_mac, ethertype=ether.ETH_TYPE_ARP)
                arp_pkt = arp.arp(opcode=arp.ARP_REPLY, src_mac=front_end_mac, src_ip=src_ip,
                                  dst_mac=dst_mac, dst_ip=dst_ip)
                p = packet.Packet()
                p.add_protocol(eth_pkt)
                p.add_protocol(arp_pkt)
                p.serialize()

                self.logger.info("Sending ARP Reply to %s to send packets for %s to %s", src, src_ip, dst_mac)
                self.logger.info("--------------------")

                # Send the packet to the server to update their arp table
                # to point to the front end
                data = p.data
                actions = [parser.OFPActionOutput(port=ofproto.OFPP_IN_PORT)]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                return

        # If the destination is not the virtual IP address, then don't do anything
        if pkt_arp.dst_ip != self.virtual_ip:
            return

        # Add the front end to the list of front ends served
        self.front_end_macs_served.append(src)
        self.front_end_ips_served.append(pkt_arp.src_ip)

        # Get index of next server to use
        index = self.next_server_address_index

        # Update the next server index to know which back end to use next
        self.next_server_address_index += 1

        # If we get to the end of the list of back ends, start again at the beginning
        if self.next_server_address_index == self.num_back_end:
            self.next_server_address_index = 0

        # Get the actual mac, ip, and port of the backend that will be assigned to the host
        dst_mac = self.back_end_mac_addresses[index]
        dst_ip = self.back_end_physical_addresses[index]
        back_end_port = self.back_end_ports[index]

        self.logger.info("Assigning Host to Server at %s", dst_mac)

        self.logger.info("Adding Flow From %s to %s on Port %s", src, self.virtual_ip, back_end_port)

        # Add the flow from the front end to the back end
        match = parser.OFPMatch(in_port=in_port,eth_type=0x0800,ipv4_dst=self.virtual_ip)
        actions = [parser.OFPActionSetField(ipv4_dst=dst_ip), parser.OFPActionOutput(back_end_port)]
        self.add_flow(datapath, 1, match, actions)

        self.logger.info("Adding Flow From %s to %s on Port %s", dst_mac, pkt_arp.src_ip, in_port)

        # Add the flow from the back end to the front end
        match = parser.OFPMatch(in_port=back_end_port,eth_type=0x0800,ipv4_src=dst_ip,ipv4_dst=pkt_arp.src_ip)
        actions = [parser.OFPActionSetField(ipv4_src=self.virtual_ip),parser.OFPActionOutput(in_port)]
        self.add_flow(datapath, 1, match, actions)

        # Create the eth and arp packets to send to the requesting
        # front end and combine them into one packet
        eth_pkt = ethernet.ethernet(dst=pkt_arp.src_mac, src=dst_mac, ethertype=ether.ETH_TYPE_ARP)
        arp_pkt = arp.arp(opcode=arp.ARP_REPLY, src_mac=dst_mac, src_ip=self.virtual_ip,
                          dst_mac=pkt_arp.src_mac, dst_ip=pkt_arp.src_ip)
        p = packet.Packet()
        p.add_protocol(eth_pkt)
        p.add_protocol(arp_pkt)
        p.serialize()

        self.logger.info("Sending ARP Reply to %s to send packets for %s to %s", src, self.virtual_ip, dst_mac)

        # Send the packet to the requesting host to update their arp table
        # to point to the assigned backend
        data = p.data
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_IN_PORT)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    '''
        This function adds a flow to the switch in route future traffic
        through the switch without going through the controller.
        Much of this logic was found by looking at the simple_switch_13.py file.
    '''
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)
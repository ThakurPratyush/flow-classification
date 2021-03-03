from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib import hub

import json
import sys
import argparse
import time

# link bandwidth in kbps
LINK_BANDWIDTH = 10000 #10 Mbps


#Monitor Interval
INTERVAL = 10


# Elephant flow parameters
EF_DURATION = 30
EF_PERCENTAGE = 25

EF_BANDWIDTH = LINK_BANDWIDTH * EF_PERCENTAGE / 100
EF_MEDIUM_BANDWIDTH = LINK_BANDWIDTH * 10 / 100


keystore = {}


def calculate_value(key, val):
    '''
    This function we are calculating packets per second.
    - store the previous key and value  in keystore.
    - when we get the key with the new value, 
       1. check the key exists in keystore
       2. Then takes the old value
       3. calculate the paketes per secon =  (new value - oldvalue) / INTERVAL
       4. assing the new value in the keystone.
    '''
    key = str(key).replace(".", "_")
    if key in keystore:
        oldval = keystore[key]
        cval = (val - oldval) / INTERVAL
        # storing the val
        keystore[key] = val
        return cval
    else:
        keystore[key] = val
        return 0





class EFlowApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(EFlowApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.agg_fat_flows = []

        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info("Link Bandwidth %d mbps", LINK_BANDWIDTH)
        self.logger.info(" Elephant Flow Detection duration  %d ", EF_DURATION)
        self.logger.info("Big Elephant Flow Bandwidth %d Kbps",EF_BANDWIDTH)
        self.logger.info("Medium Elephant Flow Bandwidth %d Kbps",EF_MEDIUM_BANDWIDTH)

    def _monitor(self):
        self.logger.info("start flow monitoring thread")
        while True:
            hub.sleep(INTERVAL)
            self.logger.info(self.datapaths)
            for dp in self.datapaths.values():
                self.request_flow_metrics(dp)


    def request_flow_metrics(self, datapath):
        ofp_parser = datapath.ofproto_parser
        self.logger.info("Generating flow stats requests")
        req = ofp_parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)


    @set_ev_cls([ofp_event.EventOFPFlowStatsReply,
                 ], MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        MICE_FLOWS = []
        ELEPHANT_FLOWS = []
        MEDIUM_ELEPHANT_FLOWS = []
        SMALL_ELEPHANT_FLOWS = []
        self.logger.info("Checking elephant flows ....")

        for stat in ev.msg.body:
            m = {}
            srcip = "*"
            dstip = "*"
            srcport = "*"
            dstport = "*"
            protocol = "*"
            for i in stat.match.items():
                key = list(i)[0]  # match key 
                val = list(i)[1]  # match value 
                if key == "ipv4_src":
                    srcip = val
                if key == "ipv4_dst":
                    dstip = val
                if key == "ip_proto":
                    if val == 1:
                        protocol = "icmp"
                    elif val == 6:
                        protocol = "tcp"
                    elif val == 17:
                        protocol = "udp"
                if key == "tcp_src" or key == "udp_src":
                    srcport = val
                if key == "tcp_dst" or key == "udp_dst":
                    dstport = val

            if srcip=="*":
                continue
            # identify the total utilization by flows
            #self.logger.info(stat)
                            #convert in to kbps                
            kilobits = stat.byte_count  * 8  / 1000
            rate_kbps = kilobits / stat.duration_sec   

            flow = {"src_ip":srcip , "dst_ip": dstip, "protocol":protocol}
            if protocol == "udp" or protocol =="tcp":
                flow["src_port"] = srcport
                flow["dst_port"] = dstport
            print(flow,rate_kbps)
            #MICE Flow detection
            if stat.duration_sec < EF_DURATION:
                MICE_FLOWS.append(flow)

            #ELEPHANT Flow detection
            if stat.duration_sec >= EF_DURATION:        
                if rate_kbps > EF_BANDWIDTH :
                    ELEPHANT_FLOWS.append(flow)
                elif rate_kbps > EF_MEDIUM_BANDWIDTH:
                    MEDIUM_ELEPHANT_FLOWS.append(flow)
                else:
                    SMALL_ELEPHANT_FLOWS.append(flow)

        self.logger.info('*********************************************')
        self.logger.info("MICE Flows")    
        self.logger.info(MICE_FLOWS)
        self.logger.info('*********************************************')
        self.logger.info("BIG ELEPHANT Flows")
        self.logger.info(ELEPHANT_FLOWS)
        self.logger.info('*********************************************')
        self.logger.info("MEDIUM ELEPHANT Flows")
        self.logger.info(MEDIUM_ELEPHANT_FLOWS)
        self.logger.info('*********************************************')
        self.logger.info("SMALL ELEPHANT Flows")
        self.logger.info(SMALL_ELEPHANT_FLOWS)
        self.logger.info('*********************************************')



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=0, hard=0,):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=idle, hard_timeout=hard,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match,
                                    idle_timeout=idle, hard_timeout=hard,
                                    instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:

            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto

                # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)

                #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=srcip, ipv4_dst=dstip,
                                            ip_proto=protocol,
                                            tcp_src=t.src_port, tcp_dst=t.dst_port,)

                #  If UDP Protocol 
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=srcip, ipv4_dst=dstip, 
                                            ip_proto=protocol,
                                            udp_src=u.src_port, udp_dst=u.dst_port,)       

                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle=20)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions, idle=20)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

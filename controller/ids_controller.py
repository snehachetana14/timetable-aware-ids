from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib import hub
import os
import csv
from datetime import datetime


class TimetableIDS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TimetableIDS, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}

        # ---- detection state ----
        # which hosts (by IP) we've already blocked, so we don't repeat
        self.blocked = set()
        # how many distinct destination ports each source IP has contacted
        # (used to detect port scanning)
        self.scan_tracker = {}
        # load the timetable from the CSV file
        self.timetable = self._load_timetable()

        # thresholds (tunable)
        self.SCAN_THRESHOLD = 15      # contacting 15+ ports = port scan
        self.FLOOD_PKT_THRESHOLD = 500  # 500+ pkts between polls = flood

        # remember last poll's packet counts, to measure the rate of change
        self.prev_port_pkts = {}

        self.monitor_thread = hub.spawn(self._monitor)

    # ================= TIMETABLE ENGINE =================
    def _load_timetable(self):
        # read schedule.csv sitting next to this script
        path = os.path.join(os.path.dirname(__file__), '..',
                            'timetable', 'schedule.csv')
        table = {}
        try:
            with open(path) as f:
                for row in csv.DictReader(f):
                    table[int(row['room'])] = row
            self.logger.info("TIMETABLE loaded: %s", table)
        except Exception as e:
            self.logger.info("TIMETABLE load failed (%s) - using defaults", e)
        return table

    def _room_of_ip(self, ip):
        # IP scheme: 10.0.<room>.<device>  -> the room is the 3rd number
        try:
            return int(ip.split('.')[2])
        except Exception:
            return None

    def _room_should_be_active(self, room):
        # returns True if the timetable says this room is in use now
        row = self.timetable.get(room)
        if row is None:
            return True  # unknown room -> don't flag
        return row['expected_active'].strip().lower() == 'yes'

    # ================= MONITORING =================
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0,
                                         datapath.ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        # FLOOD DETECTION: compare each port's packet count to last poll.
        # A huge jump between two polls = flooding.
        dpid = ev.msg.datapath.id
        for stat in ev.msg.body:
            key = (dpid, stat.port_no)
            prev = self.prev_port_pkts.get(key, stat.rx_packets)
            delta = stat.rx_packets - prev
            self.prev_port_pkts[key] = stat.rx_packets

            self.logger.info("STATS switch=%s port=%s rx_pkts=%s delta=%s",
                             dpid, stat.port_no, stat.rx_packets, delta)

            if delta > self.FLOOD_PKT_THRESHOLD:
                self.logger.info("!!! ALERT: FLOOD detected on switch=%s "
                                 "port=%s (%s pkts in 5s)",
                                 dpid, stat.port_no, delta)

    # ================= SWITCH SETUP =================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def _block_host(self, datapath, ip):
        # RESPONSE: install a high-priority rule that drops everything
        # from this IP. Empty action list = drop.
        if ip in self.blocked:
            return
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        mod = parser.OFPFlowMod(datapath=datapath, priority=100,
                                match=match, instructions=[])
        datapath.send_msg(mod)
        self.blocked.add(ip)
        self.logger.info("### BLOCKED host %s - isolated from network", ip)

    # ================= PACKET HANDLING + DETECTION =================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = datapath.id
        dst = eth.dst
        src = eth.src

        # ---- DETECTION runs here, before normal forwarding ----
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            room = self._room_of_ip(src_ip)

            # CHECK 1: timetable violation - traffic from a room
            # that the schedule says should be silent
            if room is not None and not self._room_should_be_active(room):
                self.logger.info("!!! ALERT: TIMETABLE VIOLATION - traffic "
                                 "from %s in Room %s (should be empty)",
                                 src_ip, room)
                self._block_host(datapath, src_ip)

            # CHECK 2: port scan - one source hitting many different ports
            tp = pkt.get_protocol(__import__('ryu.lib.packet.tcp',
                                   fromlist=['tcp']).tcp)
            if tp:
                ports = self.scan_tracker.setdefault(src_ip, set())
                ports.add(tp.dst_port)
                if len(ports) > self.SCAN_THRESHOLD:
                    self.logger.info("!!! ALERT: PORT SCAN from %s "
                                     "(%s ports)", src_ip, len(ports))
                    self._block_host(datapath, src_ip)

        # ---- normal learning-switch forwarding ----
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
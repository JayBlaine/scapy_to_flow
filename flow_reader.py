import scapy
import pandas as pd
from scapy.layers.inet import TCP, IP
from scapy.packet import Packet
from scapy.sendrecv import sniff, AsyncSniffer
from scapy.sessions import TCPSession, IPSession

from flow import Flow
from flow_handler import create_flow_entry, update_flow_entry, flow_cleanup


def prn_scapy(flows: dict, flow_buf: list):
    def read_pkt(pkt: Packet):
        if pkt.haslayer(TCP):
            if 'N' in pkt[TCP].flags:
                print('HIT')
                print(pkt.show())
        #print(pkt.show())


    return read_pkt

# TODO: CONVERT FROM DF TO SCAPY INPUT
def read_pkts(interface: str, tag: int = 0):

    flow_ret_buf = []
    flows = {}
    # dict of flows
    sniff(iface=interface, session=IPSession, prn=prn_scapy(flows=flows, flow_buf=flow_ret_buf), filter='ip and (tcp or udp)')
    #t = AsyncSniffer(iface=interface, session=IPSession, prn=prn_scapy(flows=flows, flow_buf=flow_ret_buf), filter='tcp or udp')


    #print(list(Flow.__dict__.keys())[3:88])
    for i in df.index:  # todo: one in a million chance of same ip/port:ip/port id matching (SCAPY: pkt.port, pkt.ip (IP, TCP/UDP) (IN SNIFF CALLBACK)
        flowid = "{}:{}--{}:{}".format(df["ip_src"][i], df["ip_src_port"][i], df["ip_dst"][i], df["ip_dst_port"][i])
        flowid_rev = "{}:{}--{}:{}".format(df["ip_dst"][i], df["ip_dst_port"][i], df["ip_src"][i], df["ip_src_port"][i])

        if flowid in flows.keys():  # fwd
            flows[flowid] = update_flow_entry(i, df=df, flow=flows[flowid], dir=1)

        elif flowid_rev in flows.keys():  # bwd
            flows[flowid_rev] = update_flow_entry(i, df=df, flow=flows[flowid_rev], dir=2)

        else:
            flows[flowid] = create_flow_entry(i, df=df)

        cur_time = float(df["time"][i]) # TODO: USE DT FOR CUR TIME AND STORED TIME
        for j in flows.copy().keys():
            if cur_time - 60 > flows[j].flow_cur_time:
                """
                flow over, write to returning df, remove from dict
                """
                flows[j].ip_all_flow_duration = flows[j].flow_cur_time - flows[j].flow_start
                flows[j].label = tag
                flows[j] = flow_cleanup(j, df=df, flow=flows[j])
                flow_ret_buf.append(flows[j]._get_all()[:-1])
                flows.pop(j)
                # TODO: Maybe final cleanup function where calculate stats
                # TODO: Maybe write to file or df and remove dict entry to avoid duplicate keys

    #print(list(Flow.__dict__.keys())[3:88])
    flow_ret = pd.DataFrame(flow_ret_buf, columns=list(Flow.__dict__.keys())[3:88])  # Python 3.6+

    return flow_ret

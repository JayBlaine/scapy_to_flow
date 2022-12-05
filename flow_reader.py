from dataprep.clean import clean_ip
import scapy
import pandas as pd

from flow import Flow
from flow_handler import create_flow_entry, update_flow_entry, flow_cleanup


# TODO: CONVERT FROM DF TO SCAPY INPUT
def read_pkts(df: pd.DataFrame, tag: int = 0):

    flow_ret_buf = []
    flows = {}

    ICMPClass = df[(df['ip_proto'] == 'ICMP')].index  # TODO: FIX, CURRENTLY DROPPING (SCAPY FILTER TCP OR UDP)
    df.drop(ICMPClass, inplace=True)
    df.fillna(0, inplace=True)

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

    #print(flow_ret_buf)
    #print(list(Flow.__dict__.keys())[3:88])
    flow_ret = pd.DataFrame(flow_ret_buf, columns=list(Flow.__dict__.keys())[3:88])  # Python 3.6+
    #print(flow_ret.head())
    #print(flow_ret.columns)
    flow_ret = clean_ip(flow_ret, "ip_addr_src", output_format="integer", inplace=True, report=False, progress=False)  # ip_src_clean
    flow_ret = clean_ip(flow_ret, "ip_addr_dst", output_format="integer", inplace=True, report=False, progress=False)  # ip_dst_clean

    #le = LabelEncoder()
    #flow_ret['wlan_rcv_addr'] = le.fit_transform(flow_ret['wlan_rcv_addr'])
    #flow_ret['wlan_trn_addr'] = le.fit_transform(flow_ret['wlan_trn_addr'])
    #flow_ret['wlan_dst_addr'] = le.fit_transform(flow_ret['wlan_dst_addr'])
    #flow_ret['wlan_src_addr'] = le.fit_transform(flow_ret['wlan_src_addr'])

    return flow_ret

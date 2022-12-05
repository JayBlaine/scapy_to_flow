import pandas as pd
from flow import Flow
import re


def create_flow_entry(i: int, df: pd.DataFrame):  # TODO: CONVERT FROM DF TO SCAPY FIELDS
    new_flow = Flow()

    new_flow.flow_start = float(df["time"][i])
    new_flow.flow_cur_time = float(df["time"][i])

    new_flow.ip_addr_src = str(df["ip_src"][i])
    new_flow.ip_addr_dst = str(df["ip_dst"][i])
    new_flow.ip_port_src = int(df["ip_src_port"][i])
    new_flow.ip_port_dst = int(df["ip_dst_port"][i])
    if str(df["ip_tr_proto"][i]) == "TCP":
        new_flow.ip_proto = 0
    elif str(df["ip_tr_proto"][i]) == "UDP":
        new_flow.ip_proto = 1
    elif str(df["ip_tr_proto"][i]) == "ICMP":
        new_flow.ip_proto = 2

    new_flow.ip_fwd_pkt_tot_num = 1
    new_flow.ip_fwd_pkt_tot_len = int(df["ip_total_len"][i])
    new_flow.ip_fwd_pkt_len_max = int(df["ip_total_len"][i])
    new_flow.ip_fwd_pkt_len_min = int(df["ip_total_len"][i])
    new_flow.ip_fwd_pkt_len_mean = float(df["ip_total_len"][i])
    new_flow.ip_fwd_pkt_len_std = 0.0

    new_flow.ip_pkt_tot_num = 1
    new_flow.ip_pkt_tot_len = int(df["ip_total_len"][i])
    new_flow.ip_pkt_len_max = int(df["ip_total_len"][i])
    new_flow.ip_pkt_len_min = int(df["ip_total_len"][i])
    new_flow.ip_pkt_len_mean = float(df["ip_total_len"][i])
    new_flow.ip_pkt_len_std = 0.0

    """
    TCP/IP FLAGS
    """

    if df["ip_dont_fragment"][i] == "Set":
        new_flow.ip_dont_frag_count += 1

    if df["tcp_push"][i] == "Set":
        new_flow.tcp_fwd_psh_flags += 1
        new_flow.tcp_psh_flag_count += 1
    if df["tcp_urgent"][i] == "Set":
        new_flow.tcp_fwd_urg_flags += 1
        new_flow.tcp_urg_flag_count += 1
    if df["tcp_fin"][i] == "Set":
        new_flow.tcp_fin_flag_count += 1
    if df["tcp_syn"][i] == "Set":
        new_flow.tcp_syn_flag_count += 1
    if df["tcp_reset"][i] == "Set":
        new_flow.tcp_rst_flag_count += 1
    if df["tcp_ack"][i] == "Set":
        new_flow.tcp_ack_flag_count += 1
    if df["tcp_cwr"][i] == "Set":
        new_flow.tcp_cwr_flag_count += 1
    if df["tcp_ecn_echo"][i] == "Set":
        new_flow.tcp_ece_flag_count += 1

    """
    TCP/IP MISC
    """
    if int(df["ip_ttl"][i]) > 0:
        new_flow.ip_ttl_max = int(df["ip_ttl"][i])
        new_flow.ip_ttl_min = int(df["ip_ttl"][i])
        new_flow.ip_ttl_mean = float(df["ip_ttl"][i])
        new_flow.ip_ttl_std = 0.0

        new_flow.ip_fwd_ttl_max = int(df["ip_ttl"][i])
        new_flow.ip_fwd_ttl_min = int(df["ip_ttl"][i])
        new_flow.ip_fwd_ttl_mean = float(df["ip_ttl"][i])
        new_flow.ip_fwd_ttl_std = 0.0


    return new_flow


def update_flow_entry(i: int, flow: Flow, df: pd.DataFrame, dir: int):  # dir 1 = fwd, 2 = bwd
    # TODO: CONVERT FROM DF TO SCAPY FIELDS
    updated_flow = flow
    updated_flow.flow_cur_time = float(df["time"][i])

    updated_flow.ip_pkt_tot_num += 1
    updated_flow.ip_pkt_tot_len += int(df["ip_total_len"][i])
    if int(df["ip_total_len"][i]) > updated_flow.ip_pkt_len_max:
        updated_flow.ip_pkt_len_max = int(df["ip_total_len"][i])
    if int(df["ip_total_len"][i]) < updated_flow.ip_pkt_len_min:
        updated_flow.ip_pkt_len_min = int(df["ip_total_len"][i])

    # Rolling avg update
    oldavg = updated_flow.ip_pkt_len_mean
    updated_flow.ip_pkt_len_mean = oldavg + (int(df["ip_total_len"][i]) - oldavg) / updated_flow.ip_pkt_tot_num

    oldstd = updated_flow.ip_pkt_len_std
    updated_flow.ip_pkt_len_std = oldstd + (
                abs(int(df["ip_total_len"][i]) - oldavg) - oldstd) / updated_flow.ip_pkt_tot_num
    # curAvg = curAvg + (newNum - curAvg)/n;
    # calculate new std avg using ^ with old std, new dev, n

    """
    FWD FLOW FEATURES
    """
    if dir == 1:
        updated_flow.ip_fwd_pkt_tot_num += 1
        updated_flow.ip_fwd_pkt_tot_len += int(df["ip_total_len"][i])
        if int(df["ip_total_len"][i]) > updated_flow.ip_fwd_pkt_len_max:
            updated_flow.ip_fwd_pkt_len_max = int(df["ip_total_len"][i])
        if int(df["ip_total_len"][i]) < updated_flow.ip_fwd_pkt_len_min:
            updated_flow.ip_fwd_pkt_len_min = int(df["ip_total_len"][i])

        # Rolling avg update
        oldavg = updated_flow.ip_fwd_pkt_len_mean
        updated_flow.ip_fwd_pkt_len_mean = oldavg + (
                    int(df["ip_total_len"][i]) - oldavg) / updated_flow.ip_fwd_pkt_tot_num

        oldstd = updated_flow.ip_fwd_pkt_len_std
        updated_flow.ip_fwd_pkt_len_std = oldstd + (
                    abs(int(df["ip_total_len"][i]) - oldavg) - oldstd) / updated_flow.ip_fwd_pkt_tot_num
        # curAvg = curAvg + (newNum - curAvg)/n;
        # calculate new std avg using ^ with old std, new dev, n

    """
    BWD FLOW FEATURES
    """

    if dir == 2:
        if updated_flow.ip_bwd_pkt_tot_num == 0:  # first backward packet
            updated_flow.ip_bwd_pkt_tot_num = 1
            updated_flow.ip_bwd_pkt_tot_len = int(df["ip_total_len"][i])
            updated_flow.ip_bwd_pkt_len_max = int(df["ip_total_len"][i])
            updated_flow.ip_bwd_pkt_len_min = int(df["ip_total_len"][i])
            updated_flow.ip_bwd_pkt_len_mean = float(df["ip_total_len"][i])
            updated_flow.ip_bwd_pkt_len_std = 0.0
        else:
            updated_flow.ip_bwd_pkt_tot_num += 1
            updated_flow.ip_bwd_pkt_tot_len += int(df["ip_total_len"][i])
            if int(df["ip_total_len"][i]) > updated_flow.ip_bwd_pkt_len_max:
                updated_flow.ip_bwd_pkt_len_max = int(df["ip_total_len"][i])
            if int(df["ip_total_len"][i]) < updated_flow.ip_bwd_pkt_len_min:
                updated_flow.ip_bwd_pkt_len_min = int(df["ip_total_len"][i])

            # Rolling avg update
            oldavg = updated_flow.ip_bwd_pkt_len_mean
            updated_flow.ip_bwd_pkt_len_mean = oldavg + (
                        int(df["ip_total_len"][i]) - oldavg) / updated_flow.ip_bwd_pkt_tot_num

            oldstd = updated_flow.ip_bwd_pkt_len_std
            updated_flow.ip_bwd_pkt_len_std = oldstd + (
                        abs(int(df["ip_total_len"][i]) - oldavg) - oldstd) / updated_flow.ip_bwd_pkt_tot_num
            # curAvg = curAvg + (newNum - curAvg)/n;
            # calculate new std avg using ^ with old std, new dev, n

    """
    TCP/IP FLAGS
    """

    if df["ip_dont_fragment"][i] == "Set":
        updated_flow.ip_dont_frag_count += 1

    if df["tcp_push"][i] == "Set":
        if dir == 1:
            updated_flow.tcp_fwd_psh_flags += 1
        else:
            updated_flow.tcp_bwd_psh_flags += 1
        updated_flow.tcp_psh_flag_count += 1
    if df["tcp_urgent"][i] == "Set":
        if dir == 1:
            updated_flow.tcp_fwd_urg_flags += 1
        else:
            updated_flow.tcp_bwd_urg_flags += 1
        updated_flow.tcp_urg_flag_count += 1
    if df["tcp_fin"][i] == "Set":
        updated_flow.tcp_fin_flag_count += 1
    if df["tcp_syn"][i] == "Set":
        updated_flow.tcp_syn_flag_count += 1
    if df["tcp_reset"][i] == "Set":
        updated_flow.tcp_rst_flag_count += 1
    if df["tcp_ack"][i] == "Set":
        updated_flow.tcp_ack_flag_count += 1
    if df["tcp_cwr"][i] == "Set":
        updated_flow.tcp_cwr_flag_count += 1
    if df["tcp_ecn_echo"][i] == "Set":
        updated_flow.tcp_ece_flag_count += 1

    """
    TCP/IP MISC
    """
    if int(df["ip_ttl"][i]) > updated_flow.ip_ttl_max:
        updated_flow.ip_ttl_max = int(df["ip_ttl"][i])
    if int(df["ip_ttl"][i]) < updated_flow.ip_ttl_min:
        updated_flow.ip_ttl_min = int(df["ip_ttl"][i])
    oldavg = updated_flow.ip_ttl_mean
    updated_flow.ip_ttl_mean = oldavg + (int(df["ip_ttl"][i]) - oldavg) / updated_flow.ip_pkt_tot_num
    oldstd = updated_flow.ip_ttl_std
    updated_flow.ip_ttl_std = oldstd + (abs(int(df["ip_ttl"][i]) - oldavg) - oldstd) / updated_flow.ip_pkt_tot_num

    """
    TCP/IP FWD MISC
    """

    if dir == 1:
        if int(df["ip_ttl"][i]) > updated_flow.ip_fwd_ttl_max:
            updated_flow.ip_fwd_ttl_max = int(df["ip_ttl"][i])
        if int(df["ip_ttl"][i]) < updated_flow.ip_fwd_ttl_min:
            updated_flow.ip_fwd_ttl_min = int(df["ip_ttl"][i])
        oldavg = updated_flow.ip_fwd_ttl_mean
        updated_flow.ip_fwd_ttl_mean = oldavg + (int(df["ip_ttl"][i]) - oldavg) / updated_flow.ip_fwd_pkt_tot_num
        oldstd = updated_flow.ip_fwd_ttl_std
        updated_flow.ip_fwd_ttl_std = oldstd + (
                abs(int(df["ip_ttl"][i]) - oldavg) - oldstd) / updated_flow.ip_fwd_pkt_tot_num

        if updated_flow.ip_fwd_pkt_tot_num == 3 and updated_flow.ip_proto == 0:  # s -> s/a -> data
            updated_flow.tcp_fwd_init_win = int(df["tcp_window_size_value"][i])

    """
    TCP/IP BWD MISC
    """
    if dir == 2:
        if updated_flow.ip_bwd_pkt_tot_num == 1:  # first backward packet
            if int(df["ip_ttl"][i]) > 0:
                updated_flow.ip_bwd_ttl_max = int(df["ip_ttl"][i])
                updated_flow.ip_bwd_ttl_min = int(df["ip_ttl"][i])
                updated_flow.ip_bwd_ttl_mean = float(df["ip_ttl"][i])
                updated_flow.ip_bwd_ttl_std = 0.0

        else:
            if int(df["ip_ttl"][i]) > updated_flow.ip_bwd_ttl_max:
                updated_flow.ip_bwd_ttl_max = int(df["ip_ttl"][i])
            if int(df["ip_ttl"][i]) < updated_flow.ip_bwd_ttl_min:
                updated_flow.ip_bwd_ttl_min = int(df["ip_ttl"][i])
            oldavg = updated_flow.ip_bwd_ttl_mean
            updated_flow.ip_bwd_ttl_mean = oldavg + (int(df["ip_ttl"][i]) - oldavg) / updated_flow.ip_bwd_pkt_tot_num
            oldstd = updated_flow.ip_bwd_ttl_std
            updated_flow.ip_bwd_ttl_std = oldstd + (
                        abs(int(df["ip_ttl"][i]) - oldavg) - oldstd) / updated_flow.ip_bwd_pkt_tot_num

        if updated_flow.ip_bwd_pkt_tot_num == 2 and updated_flow.ip_proto == 0:  # s/a -> data
            updated_flow.tcp_bwd_init_win = int(df["tcp_window_size_value"][i])

    return updated_flow


def flow_cleanup(i: int, df: pd.DataFrame, flow: Flow):
    final_flow = flow

    if final_flow.ip_all_flow_duration < 1.0:
        final_flow.ip_flow_bytes_sec = final_flow.ip_pkt_tot_len
        final_flow.ip_flow_pkts_sec = final_flow.ip_pkt_tot_num

        final_flow.ip_fwd_pkts_sec = final_flow.ip_fwd_pkt_tot_num
        final_flow.ip_fwd_bytes_sec = final_flow.ip_fwd_pkt_tot_len
    else:
        final_flow.ip_flow_bytes_sec = final_flow.ip_pkt_tot_len / final_flow.ip_all_flow_duration
        final_flow.ip_flow_pkts_sec = final_flow.ip_pkt_tot_num / final_flow.ip_all_flow_duration

        final_flow.ip_fwd_pkts_sec = final_flow.ip_fwd_pkt_tot_num / final_flow.ip_all_flow_duration
        final_flow.ip_fwd_bytes_sec = final_flow.ip_fwd_pkt_tot_len / final_flow.ip_all_flow_duration

    if final_flow.ip_bwd_pkt_tot_num > 0:
        if final_flow.ip_all_flow_duration < 1.0:
            final_flow.ip_bwd_pkts_sec = final_flow.ip_bwd_pkt_tot_num
            final_flow.ip_bwd_bytes_sec = final_flow.ip_bwd_pkt_tot_len
        else:
            final_flow.ip_bwd_pkts_sec = final_flow.ip_bwd_pkt_tot_num / final_flow.ip_all_flow_duration
            final_flow.ip_bwd_bytes_sec = final_flow.ip_bwd_pkt_tot_len / final_flow.ip_all_flow_duration

    return final_flow

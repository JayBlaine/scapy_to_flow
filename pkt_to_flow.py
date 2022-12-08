from flow_tracker import FlowTracker
import time

# TODO: argparse for hcyte usage


def main():
    t = FlowTracker(iface="eno1")

    t.sniffer.start()
    i = 0
    while i < 75:
        print(t.flows)
        print()
        i += 1
        time.sleep(1)
    # TODO: IF ALERT, LABEL MALICIOUS
    t.sniffer.stop()
    t.final_cleanup()
    """
    args = parse_args()
    alert_file = open(args.read, "r")
    alert_lines = follow(alert_file)
    for line in alert_lines:
        # GET IP SRC IP DST FROM LINE, ----> t.flows[src:sport dst:dport].label=1
    
    """


if __name__ == "__main__":
    main()

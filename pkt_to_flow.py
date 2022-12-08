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


if __name__ == "__main__":
    main()

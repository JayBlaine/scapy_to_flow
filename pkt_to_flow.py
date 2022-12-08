from flow_reader import read_pkts, flows
import time

# TODO: argparse for hcyte usage


def main():
    t = read_pkts(interface='eno1', filename='test.csv')

    t.start()
    i = 0
    while i < 75:
        print(flows)
        i += 1
        time.sleep(1)
    # TODO: IF ALERT, LABEL MALICIOUS
    t.stop()


if __name__ == "__main__":
    main()

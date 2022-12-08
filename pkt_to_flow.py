from flow_reader import read_pkts, flows
import time


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

    # df = pd.read_csv("/home/jragsdale/802_train/pkt_csv/pkt_ben_09-27.csv", encoding='ISO-8859-1', dtype=str)
    # tag = 1 if "pkt_ben_09-27.csv".split('_')[1] == 'mal' else 0
    # df['label'] = 1 if tag else 0
    # print('Converting {} to flow'.format("pkt_ben_09-27.csv"))
    # df1 = read_pkts(df=df, tag=tag)



if __name__ == "__main__":
    main()

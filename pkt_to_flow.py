from flow_reader import read_pkts
import os
import sys
import pandas as pd


def main():
    if len(sys.argv) < 3:
        print('USAGE: python3 pkt_to_flow <input directory> <output directory>')
        exit(1)

    # df = pd.read_csv("/home/jragsdale/802_train/pkt_csv/pkt_ben_09-27.csv", encoding='ISO-8859-1', dtype=str)
    # tag = 1 if "pkt_ben_09-27.csv".split('_')[1] == 'mal' else 0
    # df['label'] = 1 if tag else 0
    # print('Converting {} to flow'.format("pkt_ben_09-27.csv"))
    # df1 = read_pkts(df=df, tag=tag)

    dir_in = sys.argv[1]
    dir_out = sys.argv[2]
    for filename in os.listdir(dir_in):
        f = os.path.join(dir_in, filename)
        if os.path.isfile(f):
            print('Reading {} to dataframe'.format(filename))
            df = pd.read_csv(f, encoding='ISO-8859-1', dtype=str)
            # file pattern: pkt_[ben, mal]_mon-day
            tag = 1 if str(filename).split('_')[1] == 'mal' else 0
            df['label'] = 1 if tag else 0

            print('Converting {} to flow'.format(filename))
            df1 = read_pkts(df=df, tag=tag)
            # trimming off pkt_
            newname = '{}flow_{}_{}'.format(dir_out, str(filename).split('_')[1], str(filename).split('_')[2])
            print('Saving {} to csv\n'.format(newname))
            df1.to_csv(newname)


if __name__ == "__main__":
    main()

# follow.py
#
# Follow a file like tail -f.
import sys
import time


def follow(file):
    """
    Behaves like tail -f: follows file and returns new lines as they're appended

    :param file: followed file
    :return: yields lines as they're appended, continues execution.
    """
    try:
        file.seek(0, 2)
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line
    except KeyboardInterrupt:
        sys.exit(1)

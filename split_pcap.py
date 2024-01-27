#!/usr/bin/env python3

import sys

from hashlib import sha256
from scapy.utils import rdpcap


def main():
    for pcap in sys.argv[1:]:
        packets = rdpcap(pcap)
        for packet in packets:
            m = sha256()
            m.update(packet.load)
            fname = m.hexdigest()
            with open(fname, "wb") as f:
                f.write(packet.load)


if __name__ == "__main__":
    main()

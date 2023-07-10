#Imports
from scapy.all import *
from scapy.utils import PcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet
from collections import Counter

import os, psutil, statistics, multiprocessing
import pandas as pd
import numpy as np
from multiprocessing import Pool

def get_ioc_counts0(chunk):
    dns_counts = Counter(packet[IP].dst for packet in chunk if packet.haslayer(DNS) and (packet[DNS].qr == 1) and (packet[DNS].ancount == 0))
    ip_counts = Counter(packet[IP].src for packet in chunk if packet.haslayer(IP))
    seq_counts = Counter(packet[TCP].seq for packet in chunk if packet.haslayer(TCP))
    return dns_counts, ip_counts, seq_counts

def chunk_generator(pcap_file, chunk_size):
    chunk = []
    for packet in PcapReader(pcap_file):
        chunk.append(packet)
        if len(chunk) >= chunk_size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


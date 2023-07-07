from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet
from scapy.all import *
from scapy.utils import PcapReader
from collections import Counter
import pandas as pd
import numpy as np
import pandas as pd
import statistics
import psutil

def get_ioc_counts(chunk, pcap_file = None):
    """
    Checks a chunk of packets for indicators of compromise.
    Returns a counts dictionary for each indicator (3 so far).
    """
    dns_counts = {}
    ip_counts = {}
    seq_counts = {}
    #captured_packets = PcapReader(pcap_file)
    #Looking for indicators of compromise in pcap:
    for packet in chunk:
        if packet.haslayer(IP):
            #DNS replies that contain no answer (NXDOMAIN errors):
            if packet.haslayer(DNS) and (packet[DNS].qr == 1) and (packet[DNS].ancount == 0):
                dns = packet[IP].dst
                dns_counts[IP] = dns_counts.get(dns, 0) + 1
    
        #IP addresses that send a lot of packets:
            ip = packet[IP].src
            ip_counts[IP] = ip_counts.get(ip, 0) + 1
    
        #Repeated TCP sequence numbers:
        if packet.haslayer(TCP):
            seq = packet[TCP].seq
            seq_counts[seq] = seq_counts.get(seq, 0) + 1
    #Doing some checks        
    print(f"DNS counts: {len(dns_counts)}")
    print(f"IP counts: {len(ip_counts)}")
    print(f"SEQ counts: {len(seq_counts)}")
    print(f"Available memory: {psutil.virtual_memory()[1]/1_000_000_000:.3f} GB")
    return dns_counts, ip_counts, seq_counts


def get_ioc_counts0(chunk, pcap_file = None):
    """
    Checks a chunk of packets for indicators of compromise.
    Returns a counts dictionary for each indicator (3 so far).
    """
    dns_counts = Counter()
    ip_counts = Counter()
    seq_counts = Counter()

    for packet in chunk:
        if packet.haslayer(IP):
            if packet.haslayer(DNS) and (packet[DNS].qr == 1) and (packet[DNS].ancount == 0):
                dns = packet[IP].dst
                dns_counts[dns] += 1

            ip = packet[IP].src
            ip_counts[ip] += 1

        if packet.haslayer(TCP):
            seq = packet[TCP].seq
            seq_counts[seq] += 1

    print(f"DNS counts: {len(dns_counts)}")
    print(f"IP counts: {len(ip_counts)}")
    print(f"SEQ counts: {len(seq_counts)}")
    print(f"Available memory: {psutil.virtual_memory()[1]/1_000_000_000:.3f} GB")
    return dns_counts, ip_counts, seq_counts

def set_threshold(packet_counts, sigma_value = 3, default_threshold = 25, print_stats = False):
    """
    Looks at the quantities associated with packets in a capture and establishes a threshold to flag packets at.
    Sigma_value:
    - 0.5 = 38.29%
    - 1.0 = 68.27%
    - 2.0 = 95.45%
    - 3.0 = 99.73%
    - 4.0 = 99.99%
    """
    #Setting the threshold to identify packets:
    if len(packet_counts) < 2:
        threshold = default_threshold
    else:
        mean = statistics.mean(packet_counts.values())
        stdev = statistics.stdev(packet_counts.values())
        threshold = mean + sigma_value * stdev
    if print_stats == True:
        print(f"The threshold is: {threshold}")
        
    return threshold


def eval_packets(threshold, packet_counts, print_stats = False):
    """
    Evaluates packet contents against threshold, creates and returns a set. The set should be used to identify and extract suspect packets from the capture.
    """
    #Checking packets against thresholds:
    suspicious = []
    #DNS
    for sus_item, occurrences in packet_counts.items():
        if occurrences < threshold:
            continue
        suspicious.append(sus_item)
    if print_stats == True:
        print(len(suspicious))
    return set(suspicious)

def packets_to_dataframe(packets: list[Packet]):
    """
    Extracts MAC IDs, IPs, ports and ICMP information from captured packets and returns a Pandas DataFrame.
    """
    packet_info = []
    for packet in packets:
        try:
            info = {}
            if packet.haslayer(Ether):
                info['Src_MAC'] = packet[Ether].src
                info['Dst_MAC'] = packet[Ether].dst

            if packet.haslayer(IP):
                info['Src_IP'] = packet[IP].src
                info['Dst_IP'] = packet[IP].dst

            if packet.haslayer(TCP):
                info['Src_Port'] = packet[TCP].sport
                info['Dst_Port'] = packet[TCP].dport

            if packet.haslayer(UDP):
                info['Src_Port'] = packet[UDP].sport
                info['Dst_Port'] = packet[UDP].dport

            if packet.haslayer(ICMP):
                info['Type'] = packet[ICMP].type
                info['Code'] = packet[ICMP].code

            packet_info.append(info)

        except Exception as e:
            print(f"Error when processing packet: {e}")

    return pd.DataFrame(packet_info)

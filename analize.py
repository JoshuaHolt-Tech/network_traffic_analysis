from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet
import pandas as pd

def print_packet_info(packets: list[Packet]):
    for packet in packets:
        try:
            # Print Ethernet layer (MAC addresses)
            if packet.haslayer(Ether):
                print(f"Source MAC: {packet[Ether].src}, Destination MAC: {packet[Ether].dst}")

            # Print IP layer (IP addresses)
            if packet.haslayer(IP):
                print(f"Source IP: {packet[IP].src}, Destination IP: {packet[IP].dst}")

            # Print TCP layer (port numbers)
            if packet.haslayer(TCP):
                print(f"Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")

            # Print UDP layer (port numbers)
            if packet.haslayer(UDP):
                print(f"Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")

            # Print ICMP layer (type and code)
            if packet.haslayer(ICMP):
                print(f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}")

            print("\n---\n")

        except Exception as e:
            print(f"Error when processing packet: {e}")

def get_ioc_counts(chunk):
    """
    Checks a chunk of packets for indicators of compromise.
    Returns a counts dictionary for each indicator (3 so far).
    """
    dns_counts = {}
    ip_counts = {}
    seq_counts = {}
    
    #Looking for indicators of compromise in pcap:
    for packet in captured_packets:
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
    
    return dns_counts, ip_counts, seq_counts


def set_threshold(packet_counts, sigma_value = 3, default_threshold = 25, print_stats = False):
    """

    """
    #Setting the threshold at 99.7% to identify packets:
    if len(packet_counts) < 2:
        threshold = default_threshold
    else:
        mean = statistics.mean(packet_counts.values())
        stddev = statistics.stdev(packet_counts.values())
        threshold = mean + sigma_value * stdev
    if print_stats == True:
        print(f"The threshold is: {threshold}")
        
    return threshold


def eval_packets(threshold, packet_counts, print_stats = False):
    """

    """
    #Checking packets against thresholds:
    suspicious = []
    #DNS
    for sus_item, occurrences in dns_counts.items():
        if occurrences < dns_threshold:
            continue
        suspicious.append(sus_item)
    if print_stats == True:
        print(len(suspicious))
    return set(suspicious)

def packets_to_dataframe(packets: list[Packet]):
    """

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

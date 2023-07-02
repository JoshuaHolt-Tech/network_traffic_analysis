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



def packets_to_dataframe(packets: list[Packet]):
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

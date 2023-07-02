![Network Traffic Analysis] (network_analysis_cover.jpg)
Network Traffic Analysis :satellite:

# Abstract :book:

This dataset was created to provide realistic traffic for cybersecurity research. It used a system which profiles the abstract behavior of human interactions and generates naturalistic benign background traffic in a controlled environment. It represents the behavior of 25 users over a five-day period, from Monday, July 3, 2017, to Friday, July 7, 2017. The data includes normal user activities as well as a variety of cyber-attacks with specific machines acting as the attackers and others as the victims. The data includes activities based on HTTP, HTTPS, FTP, SSH, and email protocols.

On Monday, only normal user activities were recorded. From Tuesday to Friday, both normal activities and cyber-attacks were recorded. The cyber-attacks include Brute Force FTP, Brute Force SSH, DoS, Heartbleed, Web Attack, Infiltration, Botnet, and DDoS.

## Network Information :globe_with_meridians:

### Outsiders (Attackers network) :no_entry:
- Kali: 205.174.165.73
- Win: 205.174.165.69
- Win: 205.174.165.70
- Win: 205.174.165.71
  |
  |
- Firewall: 205.174.165.80, 172.16.0.1
  |
  |
- DNS+ DC Server: 192.168.10.3
  |
  |------------------------|------------------------|------------------------|
  |                        |                        |
### Insiders (Victim network) :house:
- Web server 16 Public: 192.168.10.50, 205.174.165.68
- Ubuntu server 12 Public: 192.168.10.51, 205.174.165.66
- Ubuntu 14.4, 32B: 192.168.10.19
- Ubuntu 14.4, 64B: 192.168.10.17
- Ubuntu 16.4, 32B: 192.168.10.16
- Ubuntu 16.4, 64B: 192.168.10.12
- Win 7 Pro, 64B: 192.168.10.9
- Win 8.1, 64B: 192.168.10.5
- Win Vista, 64B: 192.168.10.8
- Win 10, pro 32B: 192.168.10.14
- Win 10, 64B: 192.168.10.15
- MAC: 192.168.10.25

[Research paper](https://www.scitepress.org/papers/2018/66398/66398.pdf)

# Goal :dart:
Analyze network traffic to detect any anomalies, indicators of compromise or suspicious activities.

# Acquire :inbox_tray:
[Files](https://www.unb.ca/cic/datasets/ids-2017.html):
- Monday, Normal Activity, 11.0G
- Tuesday, attacks + Normal Activity, 11G
- Wednesday, attacks + Normal Activity, 13G
- Thursday, attacks + Normal Activity, 7.8G
- Friday, attacks + Normal Activity, 8.3G

# Data Dictionary :notebook:
## Terminology:
| Terminology |	Definition |
|:--------|:-----------|
| Flow | A sequence of packets sent from a source to a destination, like a conversation or a session between two systems |
| Forward Packets | Messages going from the source to the destination, like words spoken by person A to person B |
| Backward Packets | Messages going from the destination back to the source, like words spoken by person B to person A |
| Inter-Arrival Time | The time interval between two consecutive packets, like the pause between two sentences in a conversation |
| Downlink | Data being sent from a central source (like a server or a network) to an end device (like your computer), like receiving a letter |
| Uplink | Data being sent from the end device back to the central source, like sending a reply |
| Bulk | A group or block of data being sent together, like sending a box of items instead of sending each item individually |
| Subflow | A part of a larger flow, like a sub-conversation within a larger conversation |
| Active Time | The period when data is being sent or received, like talking/listening in a conversation |
| Idle Time | The period when no data is being sent or received, like silence in a conversation |
| FIN Flag | A signal used to indicate the end of data transmission, like saying "I'm done speaking" in a conversation |
| SYN Flag | A signal used to initiate a connection, like dialing a phone number to start a call |
| RST Flag | A signal used to reset the connection, like hanging up and redialing in the middle of a phone call |
| PSH Flag | A signal used to tell the receiving system to process these packets as they are received instead of buffering them |
| ACK Flag | A signal used to acknowledge the receipt of a packet of data, like saying "I heard you" in a conversation |
| URG Flag | A signal used to indicate that the data contained in the packet should be processed immediately |
| CWE Flag | Not a standard flag in the TCP protocol, might be specific to the dataset, please check the dataset documentation for more details |
| ECE Flag | A signal used to indicate network congestion (too much data being sent) and tells the sender to reduce the amount of data it's sending |
| NS Flag | ECN-nonce - concealment protection. A mechanism that protects against accidental or malicious concealment of marked packets from the TCP sender. RFC 3540|
| CWR Flag | Congestion Window Reduced flag is used to signal that the TCP sender has received a TCP segment with the ECE flag set and had reduced its congestion window size in response. RFC 3168 |
| ECE Flag | ECN-Echo flag is used to indicate that the TCP peer is ECN capable during 3-way handshake (SYN, SYN-ACK), or to signal that a TCP segment was received with the CE flag in the IP header set. RFC 3168 |
| TCP:RA Flag | RST, ACK combined indicate that the connection does not exist or is already closed, and that the received segment was in error. |
| TCP:FA Flag | FIN, ACK combined flags indicate that the sender has finished sending data and is acknowledging the data received from the other side.|
| TCP:PA Flag | PSH, ACK combined flags indicate that the sender wants to push the data to the receiving application immediately and is acknowledging the data received from the other side.|
| TCP:S Flag | SYN flag is used to initiate a connection between hosts.|
| TCP:SEC Flag | SYN, ECE, CWR combined flags are used during the initial handshake to indicate that the sender is ECN capable and has received a TCP segment with the ECE flag set, and had reduced its congestion window size in response.|

## Data Column Descriptions:
| Feature |	Description |
|:--------|:-----------|
| Destination Port | The port number where the conversation is directed |
| Flow Duration | The length of the conversation |
| Total Fwd Packets | The total number of messages sent from the source to the destination |
| Total Backward Packets | The total number of messages sent from the destination back to the source |
| Total Length of Fwd Packets | The total size of messages sent from the source to the destination |
| Total Length of Bwd Packets | The total size of messages sent from the destination back to the source |
| Fwd Packet Length Max | The size of the largest message sent from the source to the destination |
| Fwd Packet Length Min | The size of the smallest message sent from the source to the destination |
| Fwd Packet Length Mean | The average size of messages sent from the source to the destination |
| Fwd Packet Length Std | How much the size of messages sent from the source to the destination varies |
| Bwd Packet Length Max | The size of the largest message sent from the destination back to the source |
| Bwd Packet Length Min | The size of the smallest message sent from the destination back to the source |
| Bwd Packet Length Mean | The average size of messages sent from the destination back to the source |
| Bwd Packet Length Std | How much the size of messages sent from the destination back to the source varies |
| Flow Bytes/s | The rate of data transfer in the conversation |
| Flow Packets/s | The rate of messages in the conversation |
| Flow IAT Mean | The average pause between two consecutive messages in the conversation |
| Flow IAT Std | How much the pause between two consecutive messages in the conversation varies |
| Flow IAT Max | The longest pause between two consecutive messages in the conversation |
| Flow IAT Min | The shortest pause between two consecutive messages in the conversation |
| Fwd IAT Total | The total pause time between messages sent from the source to the destination |
| Fwd IAT Mean | The average pause time between messages sent from the source to the destination |
| Fwd IAT Std | How much the pause time between messages sent from the source to the destination varies |
| Fwd IAT Max | The longest pause time between messages sent from the source to the destination |
| Fwd IAT Min | The shortest pause time between messages sent from the source to the destination |
| Bwd IAT Total | The total pause time between messages sent from the destination back to the source |
| Bwd IAT Mean | The average pause time between messages sent from the destination back to the source |
| Bwd IAT Std | How much the pause time between messages sent from the destination back to the source varies |
| Bwd IAT Max | The longest pause time between messages sent from the destination back to the source |
| Bwd IAT Min | The shortest pause time between messages sent from the destination back to the source |
| Fwd PSH Flags | The number of forward PSH flags |
| Bwd PSH Flags | The number of backward PSH flags |
| Fwd URG Flags | The number of forward URG flags |
| Bwd URG Flags | The number of backward URG flags |
| Fwd Header Length | The size of the information header for messages sent from the source to the destination |
| Bwd Header Length | The size of the information header for messages sent from the destination back to the source |
| Fwd Packets/s | The rate of messages sent from the source to the destination |
| Bwd Packets/s | The rate of messages sent from the destination back to the source |
| Min Packet Length | The size of the smallest message in the conversation |
| Max Packet Length | The size of the largest message in the conversation |
| Packet Length Mean | The average size of messages in the conversation |
| Packet Length Std | How much the size of messages in the conversation varies |
| Packet Length Variance | The variance of the size of messages in the conversation |
| FIN Flag Count | The count of FIN flags |
| SYN Flag Count | The count of SYN flags |
| RST Flag Count | The count of RST flags |
| PSH Flag Count | The count of PSH flags| ACK Flag Count | The count of ACK flags |
| URG Flag Count | The count of URG flags |
| CWE Flag Count | The count of CWE flags |
| ECE Flag Count | The count of ECE flags |
| Down/Up Ratio | The ratio of data received (downlink) to data sent (uplink) |
| Average Packet Size | The average size of the messages in the conversation |
| Avg Fwd Segment Size | The average size of a group of messages sent from the source to the destination |
| Avg Bwd Segment Size | The average size of a group of messages sent from the destination back to the source |
| Fwd Header Length.1 | The size of the information header for messages sent from the source to the destination (duplicate) |
| Fwd Avg Bytes/Bulk | The average size of a group of data sent together from the source to the destination |
| Fwd Avg Packets/Bulk | The average number of messages in a group sent together from the source to the destination |
| Fwd Avg Bulk Rate | The average rate of groups of data sent together from the source to the destination |
| Bwd Avg Bytes/Bulk | The average size of a group of data sent together from the destination back to the source |
| Bwd Avg Packets/Bulk | The average number of messages in a group sent together from the destination back to the source |
| Bwd Avg Bulk Rate | The average rate of groups of data sent together from the destination back to the source |
| Subflow Fwd Packets | The number of messages in a part of the conversation going from the source to the destination |
| Subflow Fwd Bytes | The size of the part of the conversation going from the source to the destination |
| Subflow Bwd Packets | The number of messages in a part of the conversation going from the destination back to the source |
| Subflow Bwd Bytes | The size of the part of the conversation going from the destination back to the source |
| Init_Win_bytes_forward | The size of the initial data window for the source to the destination |
| Init_Win_bytes_backward | The size of the initial data window for the destination back to the source |
| act_data_pkt_fwd | The number of data messages sent from the source to the destination |
| min_seg_size_forward | The size of the smallest group of data sent from the source to the destination |
| Active Mean | The average time when data is being sent or received |
| Active Std | How much the active time varies |
| Active Max | The longest period when data is being sent or received |
| Active Min | The shortest period when data is being sent or received |
| Idle Mean | The average time when no data is being sent or received |
| Idle Std | How much the idle time varies |
| Idle Max | The longest period when no data is being sent or received |
| Idle Min | The shortest period when no data is being sent or received |
| Label | The label indicating BENIGN or the type of attack |

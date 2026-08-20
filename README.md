Python_Sniffer 

# Network Packet Sniffer & Analyzer

A lightweight Python toolkit for capturing live network traffic and analyzing 
packet structure — built to understand how data actually moves across a network, 
one layer at a time.

## What it does

- **Live capture** (`sniffer.py`): Uses `scapy` to sniff packets off a network 
  interface in real time, parsing TCP, UDP, ICMP, and ARP traffic and printing 
  source/destination IPs, ports, protocol flags, and payload previews as they happen.
- **Offline analysis** (`analyze_pcap.py`): Reads any `.pcap` file (including 
  ones exported from Wireshark) and prints a full layer-by-layer breakdown of 
  each packet — Ethernet → IP → TCP/UDP/ICMP → payload — plus protocol counts 
  and "top talkers" statistics.

## Why

Packet capture is one of the clearest ways to see networking concepts stop 
being abstract: the TCP three-way handshake, how DNS queries look on the wire, 
what a raw HTTP request actually contains. This project applies that hands-on 
approach with clean, readable code as a base for further exploration (protocol 
filtering, custom parsers, traffic visualization, etc.).

## Tech stack

- Python 3
- [Scapy](https://scapy.net/) for packet crafting/parsing
- BPF filter support (same syntax as `tcpdump`/Wireshark)

## Quick start

\`\`\`bash
pip install -r requirements.txt
sudo python3 sniffer.py -f "tcp port 80"     # live capture (needs root/admin)
python3 analyze_pcap.py sample.pcap          # offline analysis, no privileges needed
\`\`\`

Full usage instructions in the README below.

**Note:** For educational use on networks/devices you own or are authorized to monitor.

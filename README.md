# Network Packet Sniffer & Analyzer

A small educational toolkit for capturing live traffic and studying how
packets are structured. Two scripts:

| Script            | Purpose                                                             | Needs root? |
|--------------------|----------------------------------------------------------------------|-------------|
| `sniffer.py`       | Captures **live** packets from a network interface and prints them  | Yes         |
| `analyze_pcap.py`  | Reads a saved `.pcap` file and prints a full layer-by-layer breakdown| No          |

## Setup

```bash
pip install -r requirements.txt
```

On Linux you also need `libpcap` (usually already present); on macOS, scapy
uses the built-in BPF devices; on Windows, install **Npcap** first
(https://npcap.com/).

## 1. Live capture — `sniffer.py`

Capturing raw packets means asking the OS for extra privileges, so run it
with `sudo` (Linux/macOS) or an Administrator shell (Windows):

```bash
sudo python3 sniffer.py                      # capture everything, run until Ctrl+C
sudo python3 sniffer.py -c 50                # stop after 50 packets
sudo python3 sniffer.py -i eth0              # choose a specific interface
sudo python3 sniffer.py -f "tcp port 80"     # BPF filter: only HTTP traffic
sudo python3 sniffer.py -o out.pcap          # save what you capture for later analysis
```

Each captured packet prints a line like:

```
[14:02:11.123] TCP  192.168.1.10:51234 -> 93.184.216.34:80   flags=S       | no payload
[14:02:11.456] UDP  192.168.1.10:53211 -> 8.8.8.8:53         | 30 bytes | preview: '...'
```

At the end you get a summary of how many TCP/UDP/ICMP/ARP packets were seen.

## 2. Offline analysis — `analyze_pcap.py`

Once you have a `.pcap` file (from `sniffer.py -o`, or exported from
Wireshark), inspect it without needing root:

```bash
python3 analyze_pcap.py out.pcap
```

This prints, for every packet: its layer stack (e.g. `Ethernet > IP > TCP`),
key header fields (ports, sequence numbers, TTL, ICMP type/code), and a
preview of any raw payload bytes — followed by an overall protocol-count and
"top talkers" summary.

## How it works (the short version)

- **`socket`** is the low-level Python API for network I/O. A raw socket
  (`socket.AF_PACKET` on Linux, or `socket.AF_INET` with `IPPROTO_RAW`) lets
  you read packets straight off the wire instead of going through a normal
  TCP/UDP connection — but you get raw bytes and have to parse headers
  yourself.
- **`scapy`** wraps that raw-socket plumbing and gives you Python objects
  for each protocol layer (`Ether`, `IP`, `TCP`, `UDP`, `ICMP`, `ARP`, ...),
  so `pkt[TCP].dport` just works instead of you unpacking bytes with
  `struct`.
- Every packet is a stack of layers, outer to inner, roughly mapping to the
  network stack:
  - **Ethernet** (link layer) — MAC addresses
  - **IP** (network layer) — source/destination IP, TTL, protocol number
  - **TCP / UDP / ICMP** (transport layer) — ports, flags, sequence numbers
  - **Raw payload** (application layer) — the actual data, e.g. HTTP text,
    DNS query bytes, etc.
- `sniff()` in scapy registers a callback (`prn=handle_packet`) that fires
  for every packet the OS delivers; you can narrow what you see with a
  **BPF filter** string (the same syntax `tcpdump` uses, e.g. `"tcp port
  443"`, `"udp"`, `"host 8.8.8.8"`).

## Notes on responsible use

Only capture traffic on networks and devices you own or have explicit
permission to monitor. Packet capture on networks you don't control (e.g.
public Wi-Fi, an employer's network without authorization) may be illegal
in your jurisdiction.

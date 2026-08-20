#!/usr/bin/env python3
"""
Simple Network Packet Sniffer & Analyzer
==========================================
Educational tool for capturing and inspecting live network traffic.

Requires root/admin privileges to open a raw socket:
    sudo python3 sniffer.py

Dependencies:
    pip install scapy
"""

import argparse
import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, Raw, wrpcap


# ---------------------------------------------------------------------------
# Stats tracked across the whole capture session
# ---------------------------------------------------------------------------
stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "arp": 0,
    "other": 0,
}

captured_packets = []  # kept in memory so we can optionally save to a .pcap


def protocol_name(proto_num: int) -> str:
    """Translate an IP protocol number into a human-readable name."""
    mapping = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return mapping.get(proto_num, f"OTHER({proto_num})")


def describe_payload(pkt) -> str:
    """Return a short, safe preview of the raw payload bytes, if any."""
    if pkt.haslayer(Raw):
        raw_bytes = bytes(pkt[Raw].load)
        preview = raw_bytes[:32]
        try:
            text = preview.decode("utf-8", errors="replace")
        except Exception:
            text = repr(preview)
        return f"{len(raw_bytes)} bytes | preview: {text!r}"
    return "no payload"


def handle_packet(pkt):
    """
    Callback fired by scapy for every captured packet.
    Parses the layers we care about and prints a summary line.
    """
    stats["total"] += 1
    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

    # --- ARP (link layer, no IP) ---------------------------------------
    if pkt.haslayer(ARP):
        stats["arp"] += 1
        arp = pkt[ARP]
        op = "request" if arp.op == 1 else "reply"
        print(f"[{timestamp}] ARP  {arp.psrc:<15} -> {arp.pdst:<15} ({op})")
        captured_packets.append(pkt)
        return

    # --- IPv4 / IPv6 -----------------------------------------------------
    ip_layer = None
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
    elif pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]

    if ip_layer is None:
        stats["other"] += 1
        print(f"[{timestamp}] Non-IP packet: {pkt.summary()}")
        captured_packets.append(pkt)
        return

    src = ip_layer.src
    dst = ip_layer.dst

    if pkt.haslayer(TCP):
        stats["tcp"] += 1
        tcp = pkt[TCP]
        flags = tcp.sprintf("%TCP.flags%")
        line = (
            f"[{timestamp}] TCP  {src}:{tcp.sport:<5} -> {dst}:{tcp.dport:<5} "
            f"flags={flags:<8} | {describe_payload(pkt)}"
        )
    elif pkt.haslayer(UDP):
        stats["udp"] += 1
        udp = pkt[UDP]
        line = (
            f"[{timestamp}] UDP  {src}:{udp.sport:<5} -> {dst}:{udp.dport:<5} "
            f"| {describe_payload(pkt)}"
        )
    elif pkt.haslayer(ICMP):
        stats["icmp"] += 1
        icmp = pkt[ICMP]
        line = (
            f"[{timestamp}] ICMP {src:<15} -> {dst:<15} "
            f"type={icmp.type} code={icmp.code}"
        )
    else:
        stats["other"] += 1
        proto = protocol_name(ip_layer.proto) if hasattr(ip_layer, "proto") else "?"
        line = f"[{timestamp}] {proto:<4} {src:<15} -> {dst:<15}"

    print(line)
    captured_packets.append(pkt)


def print_summary():
    print("\n" + "=" * 60)
    print("Capture summary")
    print("=" * 60)
    print(f"Total packets : {stats['total']}")
    print(f"  TCP  : {stats['tcp']}")
    print(f"  UDP  : {stats['udp']}")
    print(f"  ICMP : {stats['icmp']}")
    print(f"  ARP  : {stats['arp']}")
    print(f"  Other: {stats['other']}")


def main():
    parser = argparse.ArgumentParser(description="Simple educational packet sniffer")
    parser.add_argument(
        "-i", "--iface", default=None,
        help="Network interface to sniff on (default: scapy's default interface)"
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="Number of packets to capture (default: 0 = run until Ctrl+C)"
    )
    parser.add_argument(
        "-f", "--filter", default=None,
        help='BPF filter string, e.g. "tcp port 80" or "udp"'
    )
    parser.add_argument(
        "-o", "--outfile", default=None,
        help="Save captured packets to this .pcap file (viewable in Wireshark)"
    )
    args = parser.parse_args()

    print("Starting capture... (Ctrl+C to stop)")
    if args.filter:
        print(f"Filter: {args.filter}")
    if args.iface:
        print(f"Interface: {args.iface}")

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=handle_packet,
            count=args.count if args.count > 0 else 0,
            store=False,
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print(
            "\nPermission denied. Packet capture needs elevated privileges.\n"
            "Try: sudo python3 sniffer.py"
        )
        return
    except OSError as e:
        print(f"\nCould not open interface: {e}")
        return

    print_summary()

    if args.outfile and captured_packets:
        wrpcap(args.outfile, captured_packets)
        print(f"\nSaved {len(captured_packets)} packets to {args.outfile}")


if __name__ == "__main__":
    main()

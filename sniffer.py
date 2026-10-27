#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer

Captures live network packets with scapy and prints:
  - timestamp, source/destination IP, protocol
  - source/destination ports (TCP/UDP), TCP flags
  - ICMP type, DNS queries
  - payload preview (printable text + hex)

Run (needs admin/root rights):
  Linux/macOS : sudo python3 sniffer.py -c 30
  Windows     : run the terminal as Administrator (Npcap must be installed)

Use ONLY on networks you own or have permission to monitor.
"""
import argparse
from datetime import datetime

from scapy.all import sniff, DNS, DNSQR, ICMP, IP, IPv6, Raw, TCP, UDP, wrpcap

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}
stats = {}


def payload_preview(packet, limit):
    """Return (text, hex) preview of the raw payload."""
    if Raw not in packet:
        return None, None
    data = bytes(packet[Raw].load)[:limit]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return text, data.hex(" ")


def handle_packet(packet, args, state):
    layer = IP if IP in packet else IPv6 if IPv6 in packet else None
    if layer is None:
        return  # ignore non-IP traffic such as ARP

    ip = packet[layer]
    proto_num = ip.proto if layer is IP else ip.nh
    proto = PROTOCOLS.get(proto_num, f"Other({proto_num})")
    stats[proto] = stats.get(proto, 0) + 1
    state["count"] += 1

    now = datetime.now().strftime("%H:%M:%S")
    print(f"\n[{state['count']}] {now}  {proto}  {len(packet)} bytes")
    print(f"    {ip.src}  ->  {ip.dst}")

    if TCP in packet:
        t = packet[TCP]
        print(f"    Ports: {t.sport} -> {t.dport}   Flags: {t.sprintf('%flags%')}")
    elif UDP in packet:
        u = packet[UDP]
        print(f"    Ports: {u.sport} -> {u.dport}")
    elif ICMP in packet:
        print(f"    ICMP type: {packet[ICMP].type}  code: {packet[ICMP].code}")

    if DNS in packet and packet[DNS].qr == 0 and DNSQR in packet:
        print(f"    DNS query: {packet[DNSQR].qname.decode(errors='ignore')}")

    if not args.no_payload:
        text, hexdata = payload_preview(packet, args.payload_len)
        if text is not None:
            print(f"    Payload (text): {text}")
            print(f"    Payload (hex) : {hexdata}")


def main():
    parser = argparse.ArgumentParser(description="Basic network sniffer (scapy)")
    parser.add_argument("-i", "--iface", help="network interface (default: scapy default)")
    parser.add_argument("-c", "--count", type=int, default=20, help="packets to capture (0 = until Ctrl+C)")
    parser.add_argument("-f", "--filter", default="", help='BPF filter, e.g. "tcp port 80" or "udp port 53"')
    parser.add_argument("-p", "--payload-len", type=int, default=64, help="payload bytes to show")
    parser.add_argument("--no-payload", action="store_true", help="hide payload")
    parser.add_argument("-w", "--write", help="save captured packets to a .pcap file (open in Wireshark)")
    args = parser.parse_args()

    print("=== CodeAlpha Basic Network Sniffer ===")
    print(f"Interface: {args.iface or 'default'} | Filter: {args.filter or 'none'} | Count: {args.count or 'unlimited'}")
    print("Press Ctrl+C to stop.\n")

    state = {"count": 0}
    captured = []

    def callback(pkt):
        captured.append(pkt)
        handle_packet(pkt, args, state)

    try:
        sniff(iface=args.iface, filter=args.filter, prn=callback, count=args.count, store=False)
    except PermissionError:
        print("Permission denied. Run as administrator/root.")
        return
    except KeyboardInterrupt:
        pass

    print("\n=== Summary ===")
    for proto, n in sorted(stats.items(), key=lambda x: -x[1]):
        print(f"  {proto:<10} {n}")
    print(f"  Total IP packets: {state['count']}")

    if args.write and captured:
        wrpcap(args.write, captured)
        print(f"Saved {len(captured)} packets to {args.write}")


if __name__ == "__main__":
    main()

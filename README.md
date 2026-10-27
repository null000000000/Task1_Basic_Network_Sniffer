Task 1: Basic Network Sniffer

CodeAlpha Cyber Security Internship, Task 1. A Python network sniffer built with `scapy` that captures live packets and shows how data moves through a network.

## What it does

- Captures live IPv4/IPv6 traffic
- Shows time, source/destination IP, protocol (TCP / UDP / ICMP) and packet size
- Shows source/destination ports and TCP flags
- Shows ICMP type/code and DNS queries
- Shows a payload preview as text and hex
- Supports BPF filters, packet count, interface selection, payload length, and `.pcap` export
- Prints a protocol summary when the capture ends

## Requirements

- Python 3
- `scapy` (`pip install -r requirements.txt`)
- Root/Administrator rights (Npcap on Windows)

## Usage

bash

```bash
sudo python3 snifer.py                         # capture 20 packets
sudo python3 snifer.py -c 50 -f "tcp port 80"  # only HTTP traffic
sudo python3 snifer.py -f "udp port 53"        # only DNS
sudo python3 snifer.py -c 100 -w capture.pcap  # save to a pcap file
```

Options: `-i` interface, `-c` count (0 = until Ctrl+C), `-f` BPF filter, `-p` payload length, `--no-payload`, `-w` pcap output.

## How it works

1. `sniff()` listens on the network interface and calls `handle_packet()` for every packet.
2. The handler reads the IP layer, then the layer above it (TCP, UDP or ICMP), following the encapsulation order: Ethernet > IP > TCP/UDP > data.
3. If the packet carries a `Raw` layer, its bytes are printed as readable text and hex.
4. Counters per protocol are kept and printed as a summary at the end.

## Testing (lab environment)

Testing was done on **Kali Linux inside VirtualBox**, on a lab network I own.

1. **Host discovery** with `nmap -sn` to see which hosts were alive on the lab subnet (3 hosts up).
2. **Live capture** with `sudo ./snifer.py`. The sniffer caught a UDP packet (86 bytes, port 57621 to 57621) and printed its source/destination, ports and payload in text and hex. The payload starts with `SpotUdp`, which matches the local peer-discovery broadcast used by Spotify.

## Protocol basics learned

- **TCP**: connection-oriented (SYN, SYN-ACK, ACK), used by HTTP, HTTPS, SSH
- **UDP**: connectionless and fast, used by DNS and streaming
- **ICMP**: diagnostics such as ping
- Encrypted traffic (HTTPS) shows unreadable payloads, while plain protocols such as HTTP and DNS are readable.

## Legal note

Use only on networks you own or have written permission to monitor.

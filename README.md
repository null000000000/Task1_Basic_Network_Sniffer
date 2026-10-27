# CodeAlpha_BasicNetworkSniffer

Task 1 - Cyber Security Internship (CodeAlpha): a basic network sniffer in Python using `scapy`.

## Features
- Captures live packets (IPv4/IPv6) and shows source/destination IPs, protocol (TCP/UDP/ICMP), ports, TCP flags, and DNS queries
- Payload preview in text and hex
- BPF filters, packet count, interface selection
- Protocol summary at the end, optional `.pcap` export for Wireshark

## Install
```
pip install -r requirements.txt
```
Windows: install Npcap (https://npcap.com) and run the terminal as Administrator.
Linux/macOS: run with `sudo`.

## Usage
```
sudo python3 sniffer.py                       # 20 packets
sudo python3 sniffer.py -c 50 -f "tcp port 80"
sudo python3 sniffer.py -f "udp port 53" --no-payload
sudo python3 sniffer.py -c 100 -w capture.pcap
```

## How it works
1. `sniff()` listens on the interface and calls a handler for every packet.
2. The handler reads the IP layer, then the TCP/UDP/ICMP layer above it (encapsulation: Ethernet > IP > TCP/UDP > data).
3. If a `Raw` layer exists, its bytes are shown as the payload. Encrypted traffic (HTTPS) shows unreadable payloads, while plain HTTP/DNS are readable.

## Protocol basics learned
- **TCP**: connection-oriented (SYN, SYN-ACK, ACK handshake), used by HTTP/HTTPS/SSH
- **UDP**: connectionless and fast, used by DNS/streaming
- **ICMP**: diagnostics such as ping

## Legal note
Capture traffic only on networks you own or are authorized to test.

## Screenshots
Add your run screenshots to the `screenshots/` folder and reference them here, e.g. `![Sniffer output](screenshots/run1.png)`.

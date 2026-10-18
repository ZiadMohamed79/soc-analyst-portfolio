# Wireshark Network Traffic Analysis

**SOC Analyst portfolio project | Network traffic analysis | Training lab**

## Objective
Analyze a packet capture in Wireshark, use display filters to isolate traffic, and document DNS resolution, TCP connection setup, TLS Client Hello messages, and a plain-text HTTP request.

## Environment and dataset
- Analysis VM: Kali Linux 2026.2 in Oracle VirtualBox
- Capture name recorded in the report: `10.0.2.15_capture_newsu.pcap`
- Packet count recorded in the report: 11,058
- Client: `10.0.2.15`
- DNS resolver: `8.8.8.8`
- Browser identified in the HTTP request: Firefox 140 on Linux

> The PCAP itself was not included in the materials available for this portfolio draft. Findings below are based on the existing report and its evidence images. Re-run the analysis against the original PCAP if available before making stronger claims.

## Key observations
1. All 11,058 packets in the report involve `10.0.2.15`; excluding that host returns no packets, consistent with a single-host capture.
2. DNS queries/responses involve `8.8.8.8` and include Mozilla/Google-related names.
3. TCP connections are initiated to remote port 443, with SYN/SYN-ACK/ACK handshake traffic.
4. TLS Client Hello packets expose connection metadata such as SNI before application traffic is encrypted.
5. One plain-text HTTP request was recorded: `GET /success.txt?ipv4` to `detectportal.firefox.com`, answered with `HTTP/1.1 200 OK`. The report identifies this as Firefox's captive-portal check.
6. The HTTP POST filter returned no packets in the supplied evidence.
7. The available evidence does not establish malicious activity or ARP spoofing; ARP/Telnet checks were listed as references but were not demonstrated in the evidence.

## Display filters documented
```wireshark
ip.addr == 10.0.2.15
ip.src == 10.0.2.15
ip.dst == 10.0.2.15
!(ip.addr == 10.0.2.15)
dns
udp
tcp
tcp.flags.syn == 1
http
http.request.method == "GET"
http.request.method == "POST"
tls.handshake.type == 1
```

## Skills demonstrated
- Wireshark display filters
- DNS, TCP, TLS, and HTTP protocol inspection
- TCP three-way handshake interpretation
- Basic browser traffic analysis
- Evidence-based reporting and limitations

## Limitations
The report states that its evidence images were photographed from the VM screen and then perspective-corrected/cropped for readability; they are not native screenshots. The original PCAP was not packaged with this draft, so packet-level verification remains pending. No attack, compromise, or ARP spoofing is claimed.

## Evidence
See [`evidence/README.md`](evidence/README.md). Only publish screenshots you have permission to share. Do not label edited photographs as native screenshots.

## Author
Ziad Mohamed — IT Student | Aspiring SOC Analyst  
GitHub: https://github.com/ZiadMohamed79  
LinkedIn: https://www.linkedin.com/in/ziad-mohamed-44bb73335/

# Wireshark Network Traffic Analysis — Report

**Analyst:** Ziad Mohamed  
**Environment:** Kali Linux 2026.2 VM on Oracle VirtualBox  
**Capture:** `10.0.2.15_capture_newsu.pcap` (11,058 packets, as reported)  
**Status:** Draft based on an existing report; PCAP-level revalidation pending

## 1. Objective
Use Wireshark display filters and packet details to identify routine network activity and describe what the supplied evidence supports.

## 2. Summary
The existing report describes a single-client capture involving `10.0.2.15`, DNS resolution through `8.8.8.8`, TCP handshakes to remote port 443, TLS Client Hello messages, and one plain-text HTTP request to `detectportal.firefox.com` that returned `200 OK`. The reported request path, `/success.txt?ipv4`, is consistent with a browser captive-portal connectivity check. The supplied evidence does not establish malicious activity.

## 3. Observations

### 3.1 Single-host scope
The report states that all 11,058 packets involve `10.0.2.15`; the filter `!(ip.addr == 10.0.2.15)` displayed no packets. This suggests the capture represents traffic involving the VM rather than a broader network view.

### 3.2 DNS
The `dns` and `udp` filters isolated DNS requests and responses involving resolver `8.8.8.8`. The report records Mozilla/Google-related lookups and notes that returned addresses subsequently appear as TCP destinations.

### 3.3 TCP connection setup
The `tcp.flags.syn == 1` filter isolated connection-establishment packets. The report describes SYN, SYN-ACK, and ACK exchanges for connections to remote port 443.

### 3.4 TLS Client Hello
The filter `tls.handshake.type == 1` isolated Client Hello messages. The report records TLS parameters and server-name information in the handshake metadata. This does not expose the encrypted application payload.

### 3.5 HTTP request
The `http` and `http.request.method == "GET"` filters isolated a request for `/success.txt?ipv4` to `detectportal.firefox.com`, with an `HTTP/1.1 200 OK` response. The report identifies it as Firefox's captive-portal check. The `http.request.method == "POST"` filter returned no packets in the supplied evidence.

## 4. Filter reference

| Goal | Wireshark display filter |
|---|---|
| Traffic to/from client | `ip.addr == 10.0.2.15` |
| Client-originated traffic | `ip.src == 10.0.2.15` |
| Traffic destined for client | `ip.dst == 10.0.2.15` |
| Exclude client | `!(ip.addr == 10.0.2.15)` |
| DNS | `dns` |
| UDP | `udp` |
| TCP | `tcp` |
| SYN packets | `tcp.flags.syn == 1` |
| HTTP | `http` |
| HTTP GET | `http.request.method == "GET"` |
| HTTP POST | `http.request.method == "POST"` |
| TLS Client Hello | `tls.handshake.type == 1` |

## 5. Assessment
The evidence is consistent with normal browser activity: DNS resolution, HTTPS connection setup, TLS handshakes, and a Firefox connectivity-check request. No conclusion of compromise or attack is supported by the provided report. ARP spoofing was not demonstrated, and no ARP/Telnet evidence was included.

## 6. Limitations and next steps
- The original PCAP was not included in the current portfolio package; findings are based on the existing PDF report.
- The report describes its evidence as processed photographs of the VM display, not native screenshots.
- Obtain the original PCAP if available and rerun filters to validate frame numbers and protocol details.
- Capture native screenshots directly from Wireshark and document timestamps/time zone.
- Only investigate ARP spoofing or other attack hypotheses if packet evidence supports them.

## 7. Evidence index
See `evidence/README.md` for the evidence checklist and suggested filenames.

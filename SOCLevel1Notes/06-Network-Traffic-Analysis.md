# Module 06: Network Traffic Analysis

> **Overview:** Network logs and full packet captures (`.pcap`) don't lie—even if an attacker clears host event logs, their network packets remain on the wire. This module covers network traffic fundamentals, advanced **Wireshark** packet operations/traffic analysis, and rapid artifact extraction with **NetworkMiner**.

---

## Chapter 1: Network Traffic Basics

### Full Packet Capture (FPC) vs. Network Metadata (NetFlow / Zeek)
- **Network Flow / Metadata (`NetFlow`, `IPFIX`, `Zeek conn.log`):**
  - Records the **"Who talked to Whom, When, How Long, and How Much Bytes"** (`Src IP`, `Src Port`, `Dst IP`, `Dst Port`, `Protocol`, `Bytes In/Out`, `Duration`) *without* storing the actual packet payload.
  - Lightweight; can be retained for months in a SIEM.
- **Full Packet Capture (`PCAP`):**
  - Records the entire packet header **and** raw payload bytes.
  - Storage-intensive, but allows analysts to reconstruct transferred files, read cleartext commands, and inspect exploit payloads.

### Strategic Network Tap Locations
- **North-South Traffic:** Traffic entering or leaving the corporate network perimeter (Internet $\leftrightarrow$ Firewall/DMZ).
- **East-West Traffic:** Internal traffic moving laterally between workstations, servers, and Domain Controllers across internal VLANs.

---

## Chapter 2: Wireshark: The Basics

### Navigating Wireshark Efficiently
- **Packet Colorization:**
  - Light Purple = TCP, Light Blue = UDP, Black with Red Text = TCP Errors (`RST`, Retransmissions), Green = HTTP.
- **Time Display Format (`View -> Time Display Format`):**
  - Switch to **`UTC Date and Time of Day (1970-01-01 01:02:03.123456)`** so packet timestamps align directly with SIEM and EDR logs!

---

## Chapter 3: Wireshark: Packet Operations

### Statistical Analysis & Protocol Hierarchy
Before scrolling through 50,000 packets manually, always use the **`Statistics`** menu to profile the capture:
1. **`Statistics -> Capture File Properties`:** Shows capture start/end time, duration, total packet count, and average packets/sec.
2. **`Statistics -> Protocol Hierarchy`:** Displays the percentage breakdown of every protocol in the `.pcap` (instantly spots unusual protocols like `IRC`, `FTP`, `Telnet`, or massive `ICMP`/`DNS` volume).
3. **`Statistics -> Conversations` & `Endpoints`:**
   - Sort by **Bytes** or **Packets** across `IPv4`, `TCP`, and `UDP` tabs to identify the **Top Talkers** (scanning hosts, C2 beacons, or data exfiltration endpoints).
4. **Name Resolution (`Edit -> Preferences -> Name Resolution`):**
   - Resolve MAC addresses to hardware vendors (`ARP`), IP addresses via captured DNS responses, and GeoIP MaxMind locations.

### Advanced Filtering Operators
| Operator | Syntax | Example |
| :--- | :--- | :--- |
| `==` / `eq` | Equal | `ip.src == 192.168.1.15` |
| `!=` / `ne` | Not Equal | `tcp.port != 22` |
| `contains` | Case-sensitive substring match | `http.server contains "Apache"` |
| `matches` | Case-insensitive PCRE Regex match | `http.user_agent matches "(?i)(nmap\|nikto\|sqlmap\|curl)"` |
| `in` | Set membership | `tcp.port in {80 443 8080 8443}` |
| `lower()` / `upper()` | Case conversion functions | `lower(http.request.uri) contains "admin"` |

---

## Chapter 4: Wireshark: Traffic Analysis

### Hunting Common Attacks in Wireshark

#### 1. Port Scanning & Reconnaissance
- **ARP Scan:** High volume of broadcast `ARP Who has ...` requests from a single MAC address:
  ```text
  arp.opcode == 1 and eth.dst == ff:ff:ff:ff:ff:ff
  ```
- **TCP Connect Scan (`nmap -sT`):** `SYN` $\rightarrow$ `SYN, ACK` $\rightarrow$ `ACK` $\rightarrow$ `RST, ACK` (window size > 1024).
- **TCP SYN Stealth Scan (`nmap -sS`):** `SYN` $\rightarrow$ `SYN, ACK` $\rightarrow$ immediate `RST` (window size `<= 1024`):
  ```text
  tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.window_size <= 1024
  ```
- **UDP Scan (`nmap -sU`):** Flood of UDP packets triggering `ICMP Type 3, Code 3 (Destination Unreachable - Port Unreachable)` replies from closed ports:
  ```text
  icmp.type == 3 and icmp.code == 3
  ```

#### 2. ARP Poisoning / Man-in-the-Middle (MitM)
- **Duplicate IP / MAC Conflict:** Two different MAC addresses claiming the same IP address (typically the Default Gateway IP):
  ```text
  arp.duplicate-address-detected or arp.opcode == 2
  ```

#### 3. Cleartext Credential & Web Attack Hunting
- **FTP Login Attempts:** `ftp.request.command == "USER" or ftp.request.command == "PASS"` (`230` = Login successful, `530` = Login incorrect).
- **HTTP Basic Auth & POST Logins:** `http.authbasic or http.request.method == "POST"`
- **Log4Shell (`CVE-2021-44228`) JNDI Payloads:**
  ```text
  frame matches "(?i)jndi:(ldap|rmi|dns)"
  ```

#### 4. Decrypting HTTPS / TLS Traffic in Wireshark
- Filter TLS handshake ClientHello (`SNI` — Server Name Indication): `tls.handshake.type == 1`
- If you have the `SSLKEYLOGFILE` (`keylog.txt`) from the victim endpoint, load it via **`Edit -> Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename`** to decrypt HTTPS payloads directly inside Wireshark!

#### 5. ICMP & DNS Tunneling (Covert C2 / Exfiltration)
- **ICMP Tunneling:** Abnormally large ICMP Echo packets (`data.len > 64`) carrying non-standard ASCII/encrypted payloads:
  ```text
  icmp and data.len > 64
  ```
- **DNS Tunneling (`dnscat2` / `iodine`):** High-entropy, abnormally long subdomain queries (`a8f9d0e1b2c3.c2.evil.com`):
  ```text
  dns.qry.name.len > 40 and !mdns
  ```

---

## Chapter 5: NetworkMiner

### What is NetworkMiner?
- **NetworkMiner:** A Network Forensic Analysis Tool (**NFAT**) focused on **host-centric** passive OS fingerprinting and rapid artifact extraction from `.pcap` files (complements Wireshark's **packet-centric** view).

### Key Tabs in NetworkMiner
| Tab | What It Automatically Extracts from a `.pcap` |
| :--- | :--- |
| **Hosts** | Lists every IP on the network along with its MAC address, open ports, **Passive OS Fingerprint** (`p0f` / `Satori`), and sent/received packet counts |
| **Files** | Automatically reassembles and saves all files, images, scripts, HTML pages, and TLS certificates transferred over `HTTP`, `FTP`, `SMB`, `TFTP`, and `SMTP` |
| **Images** | Displays visual thumbnails of all images transferred in the capture |
| **Messages** | Reconstructs full emails (`SMTP`/`POP3`/`IMAP`) and chat messages |
| **Credentials** |Automatically extracts cleartext usernames, passwords, NTLM hashes, and HTTP session cookies! |
| **Sessions** | Lists established TCP/UDP sessions with client/server port mappings |
| **DNS** | Tabular view of every DNS query, answer IP, and TTL |
| **Parameters** | Extracts HTTP GET/POST parameters, headers, and DHCP options |
| **Anomalies** | Flags suspicious traffic patterns (ARP spoofing, non-standard ports) |

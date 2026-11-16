# Module 07: Network Security Monitoring

> **Overview:** Network Security Monitoring (NSM) focuses on detecting adversary tactics as they traverse the network: reconnaissance/discovery scans, lateral movement, Man-in-the-Middle (MitM) interception, covert data exfiltration, and writing/operating **Snort** IDS/IPS signatures.

---

## Chapter 1: Network Security Essentials

### Defence-in-Depth Network Architecture
- **Perimeter & DMZ (Demilitarized Zone):** Public-facing servers (Web, Mail, DNS) are placed in an isolated **DMZ** subnet separated from the internal corporate LAN by stateful firewalls. If a DMZ web server is compromised, the attacker cannot directly reach internal workstations or Domain Controllers.
- **Network Segmentation (VLANs & Zero Trust Micro-Segmentation):** Dividing internal networks by department (`Workstations VLAN`, `Servers VLAN`, `Management VLAN`) and restricting **East-West** ports (such as blocking workstation-to-workstation SMB `445` and RDP `3389`).
- **Jump Boxes / Bastion Hosts:** Hardened intermediary servers required for administrators to SSH/RDP into sensitive production servers.

---

## Chapter 2: Network Discovery Detection

### Horizontal vs. Vertical Scans
1. **Vertical Scan (Port Scan):**
   - **1 Source IP $\rightarrow$ 1 Destination IP across *many* Destination Ports** (`21, 22, 23, 80, 443, 445, 3389...`).
   - *Goal:* Discover all open services on a single target host.
2. **Horizontal Scan (Network Sweep):**
   - **1 Source IP $\rightarrow$ *Many* Destination IPs (`10.10.1.1` – `10.10.1.254`) on 1 specific Port** (e.g., Port `445` or `3389`).
   - *Goal:* Find all hosts across a subnet running a specific vulnerable service.

### Detecting Discovery in SIEM / NetFlow Logs
- **High Connection Count with `0` Bytes Returned (`S0` / `REJ` in Zeek):** When an attacker scans closed ports, thousands of connections are initiated with tiny packet sizes (`40–60 bytes`) and `0` payload bytes transferred.
- **Service Banner Grabbing & SMB/LDAP Enumeration:** Rapid spikes of failed authentication or anonymous SMB (`IPC$`) / LDAP queries originating from a non-IT workstation.

---

## Chapter 3: Data Exfiltration Detection

### Common Exfiltration Channels & How to Spot Them
Attackers must move stolen sensitive data (`DB dumps`, `source code`, `PII`) out of the network without triggering alarms:

| Exfiltration Technique | Protocol / Port | Key Detection Indicators in NSM Logs |
| :--- | :--- | :--- |
| **Standard HTTP/HTTPS POST or Cloud Upload** | `TCP 80 / 443` | Asymmetric traffic ratio (**Bytes Out $\gg$ Bytes In**); large `POST`/`PUT` requests to uncategorized IPs or personal cloud storage (`Mega.nz`, `Pastebin`, `Dropbox`, `Discord Webhooks`) |
| **FTP / SFTP / SCP Transfer** | `TCP 21 / 22` | Outbound SSH/FTP connections from a workstation or database server that normally never initiates external file transfers |
| **DNS Tunneling** | `UDP/TCP 53` | Massive spike in DNS `TXT`/`A`/`NULL` queries to a single external domain; unusually long, high-entropy hex/base64 subdomains (`4a6f686e446f65.attacker.com`) |
| **ICMP Tunneling** | `ICMP (Type 8/0)` | High frequency of ICMP Echo Requests to an external IP where payload sizes exceed standard OS ping sizes (`> 64 bytes`) or contain non-standard data |

---

## Chapter 4: Man-in-the-Middle (MitM) Detection

### Common MitM Attack Techniques
1. **ARP Spoofing / ARP Cache Poisoning (Layer 2):**
   - Attacker sends gratuitous **ARP Replies** claiming their MAC address owns the Default Gateway's IP address, intercepting all LAN traffic.
   - *Detection:* Multiple MAC addresses mapped to the same IP in ARP tables (`arp -a`), or high volumes of unsolicited `ARP Reply (opcode 2)` frames.
   - *Mitigation:* **DAI (Dynamic ARP Inspection)** on enterprise switches.
2. **DHCP Starvation & Rogue DHCP Server:**
   - Attacker floods `DHCP Discover` requests with spoofed MAC addresses to exhaust the legitimate DHCP pool, then spins up a rogue DHCP server assigning an attacker-controlled Default Gateway and DNS server.
   - *Mitigation:* **DHCP Snooping** and **Port Security** on switches.
3. **LLMNR / NBT-NS Poisoning (`Responder`):**
   - When DNS fails to resolve a mistyped internal share (`\\fileservr`), Windows broadcasts **LLMNR (`UDP 5355`)** and **NBT-NS (`UDP 137`)** queries across the subnet. An attacker running `Responder` replies *"That's me!"* and captures the victim's **NetNTLMv2 hash**.
   - *Detection:* Unexpected broadcast responses on `UDP 5355 / 137` followed by SMB `445` authentication to a workstation IP.
4. **SSL/TLS Stripping & Fake Certificates:**
   - Downgrading `HTTPS` to `HTTP` or presenting a self-signed TLS certificate (`Issuer != Expected CA`).

---

## Chapter 5: IDS Fundamentals & Snort

### Operating Modes of Snort
1. **Sniffer Mode:** Reads packets off the wire and prints them to the console (`snort -v`, `-vd`, `-vde`).
2. **Packet Logger Mode:** Logs packets to disk (`snort -l ./log -b`).
3. **NIDS / NIPS Mode:** Evaluates live traffic or a `.pcap` file against a configuration file (`snort.conf`) and rule sets (`local.rules`):
   ```bash
   # Run Snort against a PCAP file and output alerts to console
   snort -c /etc/snort/snort.conf -r capture.pcap -A console -q

   # Run Snort against a specific custom rules file and dump logs in current directory
   snort -c local.rules -r capture.pcap -A full -l .
   ```
   - **Alert Modes (`-A`):** `console` (prints fast alerts to screen), `fast` (1-line summary), `full` (full packet headers + alert details), `cmg` (headers + hex/ASCII payload).

### Writing Custom Snort Rules Cheat Sheet
```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"SQLi Attempt Detected"; flow:to_server,established; content:"UNION"; nocase; content:"SELECT"; nocase; sid:1000010; rev:1;)
```
| Rule Option | Purpose | Example |
| :--- | :--- | :--- |
| `msg` | Alert description message | `msg:"Malicious EXE Download";` |
| `content` | Match ASCII text or Hex bytes (`\|4D 5A\|` = `MZ` Windows PE header) | `content:"|4D 5A|";` |
| `nocase` | Disable case sensitivity for the preceding `content` match | `content:"cmd.exe"; nocase;` |
| `offset` / `depth` | Start searching at byte `offset` and search within `depth` bytes | `content:"GET"; offset:0; depth:3;` |
| `pcre` | Match Perl Compatible Regular Expressions | `pcre:"/union\s+select/i";` |
| `flow` | Match connection state and direction | `flow:to_server,established;` |
| `flags` | Match specific TCP flags (`S`=SYN, `A`=ACK, `F`=FIN, `R`=RST, `P`=PSH, `U`=URG) | `flags:S;` (SYN scan detection) |
| `itype` / `icode` | Match ICMP Type and Code | `itype:8; icode:0;` (ICMP Echo Request) |
| `detection_filter` | Trigger only after $N$ matches within $T$ seconds (rate-based alerting) | `detection_filter:track by_src, count 20, seconds 5;` |
| `sid` & `rev` | Unique rule ID (`>= 1000000` for custom rules) and revision number | `sid:1000001; rev:1;` |

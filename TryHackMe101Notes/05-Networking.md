# Module 05: Networking

> **Overview:** Computer networking is the foundation of cybersecurity. This module covers network models (OSI & TCP/IP), core and secure protocols, packet analysis (`Wireshark` & `tcpdump`), and network reconnaissance (`Nmap`).

---

## Chapter 1: Networking Concepts

### The OSI Model (7 Layers)
*Mnemonic (Bottom to Top): **P**lease **D**o **N**ot **T**hrow **S**ausage **P**izza **A**way*

| Layer | Name | Data Unit (PDU) | Function & Protocols / Devices |
| :--- | :--- | :--- | :--- |
| **7** | **Application** | Data | End-user application protocols (`HTTP`, `DNS`, `FTP`, `SSH`, `SMTP`) |
| **6** | **Presentation** | Data | Data formatting, character encoding (`UTF-8`, `ASCII`), encryption/compression (`TLS/SSL`) |
| **5** | **Session** | Data | Establishes, maintains, and synchronizes sessions between hosts |
| **4** | **Transport** | Segment (TCP) / Datagram (UDP) | Host-to-host communication, ports (`0-65535`), reliability (`TCP`, `UDP`) |
| **3** | **Network** | Packet | Logical addressing (`IPv4`, `IPv6`) and routing across networks (`Routers`, `ICMP`, `IPsec`) |
| **2** | **Data Link** | Frame | Physical addressing (`MAC Address` — `48-bit` hex), switching within a LAN (`Switches`, `ARP`, `Ethernet`) |
| **1** | **Physical** | Bits (`0` and `1`) | Electrical, optical, or radio signals over physical media (`Cables`, `Wi-Fi`, `Hubs`) |

### The TCP/IP Model (4 Layers)
1. **Application Layer:** Combines OSI Layers 5, 6, and 7.
2. **Transport Layer:** Maps to OSI Layer 4 (`TCP` / `UDP`).
3. **Internet Layer:** Maps to OSI Layer 3 (`IP`, `ICMP`).
4. **Network Interface (Link) Layer:** Combines OSI Layers 1 and 2 (`Ethernet`, `Wi-Fi`).

### IP Addressing, Subnetting & Ports
- **IPv4 Address:** 32-bit address written as 4 octets (`0-255`), e.g., `192.168.1.10`.
- **RFC 1918 Private IPv4 Ranges** (Non-routable on public Internet; require **NAT**):
  - Class A: `10.0.0.0/8` (`10.0.0.0` – `10.255.255.255`)
  - Class B: `172.16.0.0/12` (`172.16.0.0` – `172.31.255.255`)
  - Class C: `192.168.0.0/16` (`192.168.0.0` – `192.168.255.255`)
- **Loopback Address:** `127.0.0.1` (`localhost` — refers to the local host itself).
- **CIDR Notation:** `/24` means 24 bits are for the network prefix (`255.255.255.0`), leaving $2^{32-24} - 2 = 254$ usable host addresses (subtracting the Network ID `.0` and Broadcast Address `.255`).
- **TCP vs. UDP:**
  - **TCP (Transmission Control Protocol):** Connection-oriented, reliable, ordered delivery via the **Three-Way Handshake** (`SYN` -> `SYN/ACK` -> `ACK`).
  - **UDP (User Datagram Protocol):** Connectionless, low-overhead, "fire-and-forget" (used for DNS, DHCP, video streaming).

---

## Chapter 2: Networking Essentials

### Core Infrastructure Protocols
1. **DHCP (Dynamic Host Configuration Protocol — UDP Ports `67` / `68`):**
   Automatically assigns IP addresses, subnet masks, default gateways, and DNS servers using the **DORA** process:
   - **D**iscover (Client broadcasts `DHCP Discover` to `255.255.255.255`)
   - **O**ffer (DHCP Server replies with `DHCP Offer`)
   - **R**equest (Client replies with `DHCP Request` to claim the offered IP)
   - **A**cknowledge (Server confirms lease with `DHCP ACK`)
2. **ARP (Address Resolution Protocol — Layer 2):**
   Resolves a known **IPv4 address** to a physical **MAC address** on the local subnet:
   - **ARP Request** (Broadcast `FF:FF:FF:FF:FF:FF`): *"Who has 192.168.1.1? Tell 192.168.1.10"*
   - **ARP Reply** (Unicast): *"192.168.1.1 is at AA:BB:CC:11:22:33"*
3. **ICMP (Internet Control Message Protocol — Layer 3):**
   Used for network diagnostics and error reporting:
   - `ping`: Sends ICMP Echo Request (`Type 8`) and expects ICMP Echo Reply (`Type 0`).
   - `traceroute` / `tracert`: Maps each router hop along a path by incrementing the **TTL (Time to Live)** field from `1` upward and listening for ICMP **Time Exceeded (`Type 11`)** replies.
4. **Routing & NAT (Network Address Translation):**
   - **Routing:** Routers inspect destination IPs against their routing table (`route -n` or `ip route`) and forward packets to the next hop.
   - **NAT / PAT (Port Address Translation):** Translates multiple internal private IPs (`192.168.1.x`) into a single public IP address at the edge router, tracking connections via unique source ports.

---

## Chapter 3: Networking Core Protocols

### Common Application Protocols & Default Ports
| Protocol | Port(s) | Transport | Description |
| :--- | :--- | :--- | :--- |
| **FTP** | `20` (Data), `21` (Control) | TCP | File Transfer Protocol (cleartext authentication and file transfer) |
| **SSH** | `22` | TCP | Secure Shell (encrypted remote CLI administration) |
| **Telnet** | `23` | TCP | Legacy unencrypted remote CLI administration |
| **SMTP** | `25` | TCP | Simple Mail Transfer Protocol (sending/relaying emails between mail servers) |
| **DNS** | `53` | UDP / TCP | Domain Name System (resolving domain names to IP addresses) |
| **HTTP** | `80` | TCP | Hypertext Transfer Protocol (unencrypted web traffic) |
| **POP3** | `110` | TCP | Post Office Protocol v3 (downloading emails to a single local client) |
| **IMAP** | `143` | TCP | Internet Message Access Protocol (syncing emails across multiple devices) |
| **SMB** | `445` | TCP | Server Message Block (Windows file/printer sharing) |
| **RDP** | `3389` | TCP / UDP | Remote Desktop Protocol (GUI remote access) |

### DNS (Domain Name System) Deep Dive
- **Hierarchy:** Root Servers (`.`) -> Top-Level Domain (TLD: `.com`, `.org`) -> Authoritative Name Servers (`tryhackme.com`) -> Subdomains (`blog.tryhackme.com`).
- **Common DNS Record Types:**
  - `A`: Maps hostname to **IPv4** address.
  - `AAAA`: Maps hostname to **IPv6** address.
  - `CNAME`: Canonical Name (maps an alias domain to another domain name).
  - `MX`: Mail Exchange server responsible for accepting email for the domain.
  - `TXT`: Arbitrary text records (used for domain verification, `SPF`, `DKIM`, `DMARC` email security).
- **Query Tools:**
  ```bash
  whois tryhackme.com
  nslookup -type=TXT tryhackme.com
  dig tryhackme.com MX +short
  ```

### HTTP Overview
- **Methods:** `GET` (retrieve resource), `POST` (submit data), `PUT` (update resource), `DELETE` (remove resource), `HEAD` (fetch headers only).
- **Status Codes:**
  - `1xx`: Informational
  - `2xx`: Success (`200 OK`)
  - `3xx`: Redirection (`301 Moved Permanently`, `302 Found`)
  - `4xx`: Client Error (`400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found`)
  - `5xx`: Server Error (`500 Internal Server Error`, `503 Service Unavailable`)

---

## Chapter 4: Networking Secure Protocols

### TLS / SSL (Transport Layer Security)
TLS wraps cleartext application protocols inside an encrypted tunnel, providing **Confidentiality** (encryption), **Integrity** (MAC), and **Authentication** (Digital Certificates signed by a Certificate Authority — **CA**).

| Unencrypted Protocol (Port) | TLS/Encrypted Equivalent (Port) |
| :--- | :--- |
| **HTTP** (`80`) | **HTTPS** (`443`) |
| **FTP** (`21`) | **FTPS** (`990`) or **SFTP** (via SSH `22`) |
| **SMTP** (`25`) | **SMTPS** (`465` / `587` with `STARTTLS`) |
| **POP3** (`110`) | **POP3S** (`995`) |
| **IMAP** (`143`) | **IMAPS** (`993`) |
| **Telnet** (`23`) | **SSH** (`22`) |

### VPNs (Virtual Private Networks)
- **IPsec:** Operates at Layer 3 (Network Layer) using **IKE (Internet Key Exchange)**, **AH (Authentication Header)**, and **ESP (Encapsulating Security Payload)**.
- **OpenVPN / WireGuard:** Modern VPN protocols creating encrypted virtual network interfaces (`tun0`).

---

## Chapter 5: Wireshark: The Basics

### Core Concepts
- **Wireshark:** The industry-standard GUI network protocol analyzer used to capture live traffic or inspect saved `.pcap` / `.pcapng` packet captures.
- **Three-Pane Layout:**
  1. **Packet List Pane (Top):** Summary row for each packet (No., Time, Source, Destination, Protocol, Length, Info).
  2. **Packet Details Pane (Middle):** Inspects the protocol headers broken down by OSI layer (Frame -> Ethernet -> IP -> TCP -> HTTP).
  3. **Packet Bytes Pane (Bottom):** Raw hexadecimal and ASCII representation of the packet payload.

### Essential Wireshark Display Filters
| Filter | Description |
| :--- | :--- |
| `ip.addr == 10.10.10.10` | Show packets with source OR destination IP `10.10.10.10` |
| `ip.src == 10.10.10.10 && ip.dst == 10.10.10.20` | Filter specific source and destination IPs |
| `tcp.port == 80` or `http` | Filter by TCP port 80 or HTTP protocol |
| `dns` or `arp` or `icmp` | Show only DNS, ARP, or ICMP traffic |
| `http.request.method == "POST"` | Find HTTP POST requests (great for spotting cleartext login credentials) |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Identify TCP SYN scan packets |
| `frame contains "flag"` | Search raw packet payloads for a specific string |

### Key Analytical Features
- **Follow Stream (`Right-click packet -> Follow -> TCP/HTTP Stream`):** Reconstructs the entire conversation in plain ASCII (color-coded Red for client-to-server, Blue for server-to-client).
- **Export Objects (`File -> Export Objects -> HTTP/SMB`):** Extracts files, images, or malware binaries transmitted over the network directly from the `.pcap`.
- **Statistics Menu (`Statistics -> Protocol Hierarchy / Conversations / Endpoints`):** Gives a high-level birds-eye view of top talkers and protocols used.

---

## Chapter 6: Tcpdump: The Basics

### Core Concepts
- **`tcpdump`:** Lightweight, command-line packet analyzer pre-installed on almost all Linux distributions—ideal when investigating remote servers over SSH without a GUI.

### Essential `tcpdump` Flags & Syntax
```bash
sudo tcpdump -i eth0 -nn -v -c 100 -w capture.pcap
```
| Flag | Meaning |
| :--- | :--- |
| `-i <interface>` | Listen on a specific network interface (`eth0`, `tun0`, `any`) |
| `-D` | List all available network interfaces |
| `-r <file.pcap>` | Read and analyze packets from an existing `.pcap` file |
| `-w <file.pcap>` | Write raw captured packets to a file |
| `-n` / `-nn` | Do not resolve hostnames (`-n`) or port names (`-nn`) — much faster! |
| `-c <count>` | Stop capturing after `<count>` packets |
| `-v` / `-vv` / `-vvv` | Increase verbosity of packet header output |
| `-A` | Print packet payload in ASCII (useful for reading HTTP requests/cleartext) |
| `-X` | Print packet payload in both Hex and ASCII |

### BPF (Berkeley Packet Filter) Expressions
```bash
tcpdump -r traffic.pcap host 192.168.1.50
tcpdump -r traffic.pcap src 10.10.10.5 and dst port 443
tcpdump -r traffic.pcap 'tcp[tcpflags] & (tcp-syn) != 0'   # Capture SYN packets
```

---

## Chapter 7: Nmap: The Basics

### Core Concepts
- **Nmap (Network Mapper):** The definitive tool for host discovery, port scanning, service/version enumeration, and OS fingerprinting.
- **Nmap Port States:**
  - `open`: An application is actively accepting TCP connections or UDP packets on this port.
  - `closed`: The port is accessible (responds with `RST` or ICMP port unreachable), but no service is listening.
  - `filtered`: A firewall or packet filter is blocking Nmap probes (no response or ICMP administratively prohibited).

### Scan Types & Essential Flags
| Flag | Scan / Option Name | How It Works / Purpose |
| :--- | :--- | :--- |
| `-sn` | **Ping Scan (Host Discovery)** | Discovers live hosts on a subnet without port scanning (`nmap -sn 192.168.1.0/24`) |
| `-Pn` | **Skip Host Discovery** | Treats all targets as online (bypasses firewalls blocking ICMP ping) |
| `-sS` | **TCP SYN Scan (Stealth)** | Default with `sudo`. Sends `SYN`, receives `SYN/ACK`, then sends `RST` before completing the 3-way handshake |
| `-sT` | **TCP Connect Scan** | Default for non-root users. Completes the full `SYN -> SYN/ACK -> ACK` handshake |
| `-sU` | **UDP Scan** | Scans UDP ports (slower because open UDP ports rarely respond) |
| `-sV` | **Service & Version Detection** | Probes open ports to determine exact software name and version (`Apache 2.4.49`) |
| `-O` | **OS Detection** | Fingerprints the target Operating System based on TCP/IP stack responses |
| `-sC` | **Default NSE Scripts** | Runs Nmap Scripting Engine default safe scripts (banner grabbing, anon FTP check, HTTP title) |
| `-A` | **Aggressive Scan** | Combines `-sV`, `-O`, `-sC`, and `--traceroute` |
| `-p` | **Port Specification** | `-p 80,443` (specific ports), `-p 1-1000` (range), `-p-` (all 65,535 ports) |
| `-T0` to `-T5` | **Timing Templates** | Controls scan speed (`-T1` sneaky/IDS evasion, `-T3` normal, `-T4` fast/recommended for CTFs) |
| `-oN` / `-oA` | **Output Saving** | Save scan results in Normal (`-oN`), XML (`-oX`), Grepable (`-oG`), or All formats (`-oA`) |

### Recommended Standard CTF / Pentest Nmap Command
```bash
sudo nmap -sS -sV -sC -p- -T4 -Pn 10.10.10.10 -oN nmap_full.txt
```

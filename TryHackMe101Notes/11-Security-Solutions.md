# Module 11: Security Solutions

> **Overview:** Enterprise security relies on layered defensive technologies (Defense-in-Depth). This module covers **SIEM** platforms, **Firewalls**, **Intrusion Detection/Prevention Systems (IDS/IPS)**, and **Vulnerability Scanners**.

---

## Chapter 1: Introduction to SIEM

### What is a SIEM?
- **SIEM (Security Information and Event Management):** A centralized platform that **collects, normalizes, aggregates, and correlates** log data from across an entire network (endpoints, servers, firewalls, cloud services) to provide real-time threat detection and incident investigation.

### How a SIEM Works
1. **Log Collection (Ingestion):**
   - **Agent-based:** Lightweight forwarders installed on endpoints (e.g., *Splunk Universal Forwarder*, *Elastic Beats / Winlogbeat*).
   - **Agentless:** Syslog (`UDP/TCP 514`), WMI/WEF (Windows Event Forwarding), or API polling.
2. **Normalization / Parsing:** Extracting raw log strings into standardized searchable fields (`src_ip`, `dest_ip`, `user`, `action`, `event_id`).
3. **Correlation & Alerting:** Applying correlation rules across multiple data sources (e.g., *50 failed SSH logins (`auth.log`) followed by 1 successful login from the same IP within 2 minutes -> Trigger High-Severity Brute-Force Alert*).

### Popular SIEM Solutions & Query Examples
- **Splunk (SPL — Search Processing Language):**
  ```spl
  index=windows EventCode=4625
  | stats count by Account_Name, src_ip
  | where count > 10
  ```
- **ELK Stack (Elasticsearch, Logstash, Kibana — KQL):**
  ```kql
  event.code: "4625" AND winlog.logon.type: "3"
  ```

---

## Chapter 2: Firewall Fundamentals

### Core Concepts
- **Firewall:** A network security device or host software that monitors and filters incoming and outgoing network traffic based on predetermined security rules (**Allow / Permit** vs. **Deny / Drop / Reject**).
  - *Drop:* Silently discards the packet without notifying the sender.
  - *Reject:* Blocks the packet and sends an `ICMP Unreachable` or `TCP RST` reply back to the sender.

### Types of Firewalls
| Firewall Type | OSI Layer | How It Works |
| :--- | :--- | :--- |
| **Stateless (Packet Filtering)** | Layer 3 & 4 | Inspects individual packets in isolation (Source/Dest IP, Port, Protocol) without tracking connection state |
| **Stateful Firewall** | Layer 3 & 4 | Tracks active connections in a **State Table** (e.g., automatically allows return traffic for an outbound connection initiated from inside the LAN) |
| **Next-Generation Firewall (NGFW)** | Layer 3 to 7 | Combines stateful inspection with **Deep Packet Inspection (DPI)**, application awareness, TLS inspection, and integrated IPS |
| **WAF (Web Application Firewall)** | Layer 7 | Protects web servers specifically from HTTP/HTTPS attacks (`SQLi`, `XSS`, `LFI`, `CSRF`) |

### Host-Based Firewalls in Practice
**1. Linux `ufw` (Uncomplicated Firewall — Frontend for `iptables`/`nftables`):**
```bash
sudo ufw status numbered                 # Check firewall status and rule numbers
sudo ufw default deny incoming           # Deny all unsolicited inbound traffic by default
sudo ufw default allow outgoing          # Allow all outbound traffic by default
sudo ufw allow 22/tcp                    # Allow incoming SSH
sudo ufw deny from 203.0.113.5 to any    # Block a specific malicious IP
sudo ufw delete 3                        # Delete rule #3
sudo ufw enable                          # Turn on the firewall
```

**2. Windows Defender Firewall (`wf.msc` / `netsh`):**
```cmd
netsh advfirewall show allprofiles
netsh advfirewall firewall add rule name="Block Bad IP" dir=in action=block remoteip=203.0.113.5
```

---

## Chapter 3: IDS Fundamentals

### IDS vs. IPS
- **IDS (Intrusion Detection System):** **Passive** monitoring solution (connected via a network **TAP** or switch **SPAN/Mirror port**). It detects malicious traffic and generates alerts for analysts, but does *not* block traffic inline.
- **IPS (Intrusion Prevention System):** Deployed **Inline** directly in the traffic path. Actively blocks/drops malicious packets in real time (risk: a False Positive rule can block legitimate production traffic!).

### Deployment Models & Detection Engines
- **HIDS (Host-based IDS):** Installed on an individual endpoint to monitor local files, registry changes, and processes (e.g., `Wazuh`, `OSSEC`).
- **NIDS (Network-based IDS):** Monitors raw traffic across network segments (e.g., `Snort`, `Suricata`, `Zeek`).
- **Detection Methods:**
  1. **Signature-Based Detection:** Matches traffic against a database of known attack patterns/byte sequences (fast and low false positives, but blind to Zero-Day/unseen attacks).
  2. **Anomaly-Based (Behavioral) Detection:** Compares traffic against a learned **Baseline** of normal network behavior (can detect novel attacks, but prone to higher false positives).

### Anatomy of a Snort / Suricata Rule
```text
alert icmp any any -> 192.168.1.0/24 any (msg:"ICMP Ping Detected"; itype:8; sid:1000001; rev:1;)
\___/ \__/ \_/ \_/    \____________/ \_/ \_____________________________________________________/
Action Proto Src Port   Dest IP     Port                    Rule Options
```
- **Rule Header:**
  - `Action`: `alert`, `log`, `pass`, `drop`, `reject`.
  - `Protocol`: `tcp`, `udp`, `icmp`, `ip`.
  - `Source IP & Port`: `any`, `$HOME_NET`, `$EXTERNAL_NET`, or CIDR/port numbers.
  - `Direction`: `->` (unidirectional) or `<>` (bidirectional).
  - `Destination IP & Port`.
- **Rule Options (inside parentheses):**
  - `msg`: Human-readable alert title shown to the SOC analyst.
  - `content`: Specific payload string or hex bytes (`|90 90 90|`) to match.
  - `nocase`: Makes `content` matching case-insensitive.
  - `sid`: **Snort ID** (values `>= 1000000` are reserved for custom local rules).
  - `rev`: Rule revision number.

### Running Snort in the Terminal
```bash
snort -V                                            # Check Snort version
sudo snort -c /etc/snort/snort.conf -T              # Test configuration file syntax
sudo snort -c local.rules -r traffic.pcap -A console -q  # Run rules against a saved PCAP
```

---

## Chapter 4: Vulnerability Scanner Overview

### Core Concepts
- **Vulnerability Assessment vs. Penetration Testing:**
  - *Vulnerability Scanning:* Automated, broad scan identifying known unpatched software versions and misconfigurations across thousands of assets (`Nessus`, `OpenVAS / Greenbone`, `Qualys`, `Nexpose`).
  - *Penetration Testing:* Goal-oriented, manual + automated simulation chaining vulnerabilities together to demonstrate real-world business impact.

### Vulnerability Scoring & Frameworks
- **CVE (Common Vulnerabilities and Exposures):** Unique public identifier (`CVE-2021-44228` = Log4Shell).
- **CVSS (Common Vulnerability Scoring System):** Numerical score from `0.0` to `10.0` measuring technical severity based on exploitability (Attack Vector, Complexity, Privileges Required) and impact (CIA):
  - `0.1 - 3.9`: Low
  - `4.0 - 6.9`: Medium
  - `7.0 - 8.9`: High
  - `9.0 - 10.0`: Critical
- **VPR (Vulnerability Priority Rating) / EPSS (Exploit Prediction Scoring System):** Threat-driven metrics that prioritize vulnerabilities that are *actively being exploited in the wild* rather than relying on static CVSS scores alone.

### Types of Vulnerability Scans
- **Unauthenticated (External / Black-Box) Scan:** Probes network services from the outside without credentials (sees what an external unauthenticated attacker sees).
- **Authenticated (Credentialed) Scan:** Logs into the target via SSH or SMB/WMI to inspect installed package versions (`dpkg`/`rpm`), missing Windows KB patches, and local registry settings directly (much more accurate with far fewer False Positives).

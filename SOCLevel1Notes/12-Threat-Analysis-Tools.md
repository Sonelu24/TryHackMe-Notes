# Module 12: Threat Analysis Tools

> **Overview:** Cyber Threat Intelligence (CTI) transforms raw external data into actionable context so SOC analysts can quickly determine whether an unfamiliar file hash, IP address, or domain name belongs to a known adversary campaign.

---

## Chapter 1: Intro to Cyber Threat Intel (CTI)

### Data vs. Information vs. Intelligence
- **Data:** Raw, unorganized indicators (e.g., an IP address `185.220.101.4` in a firewall log).
- **Information:** Data aggregated with basic context (*"IP `185.220.101.4` generated 500 failed SSH logins in 3 minutes"*).
- **Threat Intelligence:** Analyzed, actionable knowledge (*"IP `185.220.101.4` is a known Tor exit node actively used by Threat Group X to brute-force exposed SSH servers; block at perimeter and audit `auth.log`"*).

### The 4 Types of Threat Intelligence
| CTI Classification | Primary Audience | Focus & Examples |
| :--- | :--- | :--- |
| **1. Strategic CTI** | Executives (`CISO`, `CIO`, Board) | High-level geopolitical trends, industry risk reports, financial impact, and long-term security investment planning |
| **2. Tactical CTI** | Security Architects, SOC Leads, Detection Engineers | Adversary **TTPs** (MITRE ATT&CK matrices, adversary playbooks) used to design detection rules and harden defenses |
| **3. Operational CTI** | Tier 2/3 Incident Responders, Threat Hunters | Specific details about an incoming or active campaign (adversary infrastructure, campaign timelines, attribution) |
| **4. Technical CTI** | Tier 1 SOC Analysts, SIEM / Firewall / EDR Feeds | Short-lived, machine-readable **IoCs** (File hashes, C2 IP addresses, phishing domains, YARA rules) |

### The Threat Intelligence Lifecycle (6 Phases)
1. **Direction (Planning & Requirements):** Define intelligence goals and priority assets to protect.
2. **Collection:** Gather raw data from OSINT feeds, commercial CTI vendors, ISACs, honeypots, and internal SIEM logs.
3. **Processing:** Parse, normalize, deduplicate, and translate collected data into structured formats (`STIX` / `TAXII`, `MISP`).
4. **Analysis:** Correlate indicators, assess source reliability, and produce intelligence reports.
5. **Dissemination:** Distribute actionable intelligence to stakeholders (SIEM blocklists, SOC analysts, executives).
6. **Feedback:** Evaluate whether the intelligence met the original requirements and refine the next cycle.

---

## Chapter 2: File and Hash Threat Intel

### Enriching Suspicious Files & Hashes
When an EDR or Sysmon log flags an unknown executable, always extract its **SHA-256** (or `MD5`/`SHA-1`) hash and query public threat repositories (**never upload proprietary company documents to public sandboxes!** Search by hash first).

### Essential File & Hash CTI Platforms
1. **VirusTotal (`virustotal.com`):**
   - Aggregates detections across 70+ Antivirus engines plus sandbox behavioral reports:
     - **Detection Tab:** Shows vendor labels (e.g., `Trojan.Win32.RedLine`).
     - **Details Tab:** Shows PE headers, `ImpHash`, compilation timestamp, legitimate digital signature verification, and **First Submission / Last Analysis** dates.
     - **Relations Tab:** Shows **Contacted Domains**, **Contacted IPs**, **Dropped Files**, and **Execution Parents** (the `.zip` or `.docm` that dropped the binary!).
     - **Behavior Tab:** Displays full sandbox execution trees, MITRE ATT&CK mappings, registry edits, and mutexes.
     - **Community Tab:** Threat researcher comments linking the hash to specific malware families or campaigns.
2. **Abuse.ch MalwareBazaar (`bazaar.abuse.ch`):**
   - Community-driven repository of live malware samples searchable by `sha256:`, `imphash:`, `tag:` (e.g., `tag:AgentTesla`, `tag:AsyncRAT`), or `signature:`.
3. **Hybrid Analysis / Any.Run / Triage (`tria.ge`):**
   - Cloud sandboxes providing downloadable `.pcap` captures, extracted configuration files (C2 URLs, encryption keys), and process memory dumps.

---

## Chapter 3: IP and Domain Threat Intel

### Enriching External IP Addresses & Domains
When investigating an outbound connection (`Sysmon ID 3` / Firewall log) or an inbound login (`Event ID 4624` / `auth.log`), enrich the remote IP/domain across multiple reputation sources:

| Platform | Primary Use Case |
| :--- | :--- |
| **AbuseIPDB (`abuseipdb.com`)** | Community-reported malicious IP database showing **Confidence of Abuse (%)**, ISP, ASN, Country, Usage Type (`Data Center/Web Hosting/Transit`), and recent attack categories (`SSH Brute-Force`, `Port Scan`) |
| **Abuse.ch URLhaus & ThreatFox** | Tracks active malware distribution URLs (`URLhaus`) and C2 Indicators of Compromise (`ThreatFox` — searchable by `ioc:ip:port` or malware family) |
| **Cisco Talos Intelligence / IBM X-Force** | Enterprise reputation lookup for IP/Domain email volume, spam blacklists, and web categorization |
| **UrlScan.io** | Inspects suspicious domains/URLs, takes safe screenshots, and reveals the **ASN**, **TLS Certificate Issuer**, **DOM source**, and **HTTP transactions** |
| **Shodan & Censys** | Inspects what open ports, service banners, TLS certificates, and C2 frameworks (`Cobalt Strike`, `Metasploit`, `Mythic`) are hosted on an external IP |
| **WHOIS & Passive DNS (`SecurityTrails` / `ViewDNS`)** | Reveals **Domain Registration Date** (newly registered domains `< 30 days old` are highly suspicious!), Registrar, and historical IP resolutions |

---

## Chapter 4: Invite Only (Challenge Walkthrough Summary)

### Pivoting Across CTI Artifacts (Diamond Model / IoC Pivoting)
In real investigations, you rarely start with all the answers. You **pivot** from one indicator to discover the full campaign:
```text
[Phishing Attachment SHA256]
       │ (Query VirusTotal / MalwareBazaar -> Check 'Relations / Behavior' Tab)
       ▼
[Contacted C2 Domain: update-service[.]net]
       │ (Query Passive DNS / UrlScan / ThreatFox)
       ▼
[Resolved C2 IP: 185.x.x.x:4443]
       │ (Query Shodan / VirusTotal Communicating Files)
       ▼
[Identify Malware Family (e.g., AsyncRAT / Lumma Stealer) & Additional Stage-2 Hashes]
```
By pivoting from a single hash to its C2 domain/IP, a SOC analyst can proactively search the SIEM for *any other internal host* talking to that C2 IP, even if those hosts ran a completely different variant of the malware!

# Module 03: Core SOC Solutions

> **Overview:** Modern SOC teams rely on three interconnected platforms: **EDR** for deep endpoint visibility and containment, **SIEM** (`Splunk` & `Elastic Stack`) for centralized log aggregation and search, and **SOAR** for automating repetitive triage and response workflows.

---

## Chapter 1: Introduction to EDR

### EPPs (Antivirus) vs. EDR
- **Traditional Antivirus (AV / EPP):** Relies primarily on static file signatures (hashes/byte patterns) to block known malware before execution. Easily bypassed by fileless malware, obfuscated scripts, or **Living off the Land (LOLBins)**.
- **EDR (Endpoint Detection and Response):** Installs a kernel/user-mode sensor on every workstation and server (e.g., *CrowdStrike Falcon*, *Microsoft Defender for Endpoint*, *SentinelOne*, *Velociraptor*) to continuously record **behavioral telemetry**.

### Core Capabilities of an EDR
1. **Continuous Behavioral Telemetry:**
   - **Process Creation Trees:** Tracks parent-child relationships (`WINWORD.EXE` $\rightarrow$ `cmd.exe` $\rightarrow$ `powershell.exe`).
   - **File & Registry Modifications:** Tracks dropped binaries, persistence keys, and ransomware file renames.
   - **Network Connections:** Maps every outbound TCP/UDP connection and DNS query back to the exact owning process.
   - **Memory & API Monitoring:** Detects process injection (`CreateRemoteThread`), credential dumping (`lsass.exe` memory reads), and AMSI tampering.
2. **Real-Time Response Actions:**
   - **Network Isolation (Host Containment):** Cuts off all network communication to/from the infected host *except* communication with the EDR cloud console, stopping lateral movement immediately.
   - **Remote Shell / Live Response:** Allows analysts to remotely kill processes, quarantine files, or collect forensic artifacts (`RAM` dump, registry hives).

---

## Chapter 2: Introduction to SIEM

### Architecture of a SIEM Pipeline
1. **Data Sources:**
   - **Host-Centric Logs:** Windows Event Logs (`.evtx`), Sysmon, Linux `syslog`/`auditd`, EDR telemetry.
   - **Network-Centric Logs:** Firewall traffic logs, IDS/IPS alerts (`Snort`/`Suricata`), DNS queries, VPN concentrator logs, Web Proxy logs.
   - **Application & Cloud Logs:** Web server (`Apache`/`Nginx`/`IIS`), Active Directory/Entra ID, AWS CloudTrail, Microsoft 365 Unified Audit Logs.
2. **Log Ingestion & Forwarding:**
   - *Forwarders/Agents:* Splunk Universal Forwarder, Elastic Agent / Beats (`Winlogbeat`, `Filebeat`, `Auditbeat`).
   - *Push/Pull Collectors:* Syslog (`Port 514`), WEF (Windows Event Forwarding), REST API webhooks.
3. **Parsing, Normalization & Indexing:**
   - Converts heterogeneous log formats (`JSON`, `XML`, `CEF`, `CSV`, raw Syslog) into common schema fields (e.g., **ECS — Elastic Common Schema** or **Splunk CIM — Common Information Model**).
4. **Correlation Rules & Dashboards:**
   - Evaluates incoming normalized events against detection logic (e.g., **Sigma Rules** translated into SPL or KQL) to trigger SOC alerts.

---

## Chapter 3: Splunk: The Basics

### Core Splunk Components
- **Splunk Forwarder:** Lightweight agent installed on endpoints to collect and send logs.
- **Splunk Indexer:** Parses incoming data, stores it as compressed events in **Indexes** (`main`, `windows`, `network`), and executes search queries against them.
- **Splunk Search Head:** The web GUI where SOC analysts write **SPL (Search Processing Language)** queries, build dashboards, and review alerts.

### Essential Splunk SPL (Search Processing Language) Cheat Sheet
```spl
# 1. Basic Filtering (Always specify index, sourcetype, and time range first!)
index=windows sourcetype="WinEventLog:Security" EventCode=4625 "admin"

# 2. Boolean & Wildcard Operators (AND is implied between space-separated terms; OR/NOT must be UPPERCASE)
index=web status=200 AND (method=POST OR method=PUT) NOT clientip="10.10.1.*"

# 3. Selecting & Renaming Fields (fields, table, rename)
index=windows EventCode=4624
| fields Account_Name, Source_Network_Address, Logon_Type
| table _time, Account_Name, Source_Network_Address, Logon_Type
| rename Source_Network_Address as "Source IP"

# 4. Deduplication & Sorting (dedup, sort)
index=windows EventCode=4624
| dedup Account_Name
| sort - _time                  # '-' sorts descending, '+' sorts ascending

# 5. Aggregation & Statistics (stats, top, rare, timechart)
index=windows EventCode=4625
| stats count, values(Account_Name) as Targeted_Users, dc(Account_Name) as Unique_Users by Source_Network_Address
| where count > 20
| sort - count
```
- **Common `stats` Functions:**
  - `count`: Total number of matching events.
  - `dc(field)` (`distinct_count`): Number of unique values in a field (great for detecting port scans or password spraying!).
  - `values(field)`: Lists all unique values of a field.
  - `list(field)`: Lists all values (including duplicates) in order.

---

## Chapter 4: Elastic Stack: The Basics

### Core Components of the ELK / Elastic Stack
- **B — Beats / Elastic Agent:** Lightweight data shippers (`Filebeat`, `Winlogbeat`, `Packetbeat`) installed on hosts.
- **L — Logstash:** Server-side data processing pipeline that ingests, parses (via `grok` filters), and enriches logs before sending them to Elasticsearch.
- **E — Elasticsearch:** Distributed, RESTful JSON search and analytics engine that stores and indexes data.
- **K — Kibana:** Web interface for searching (`Discover`), visualizing (`Dashboards`), and managing alerts (`Elastic Security`).

### Essential KQL (Kibana Query Language) Cheat Sheet
```kql
# 1. Exact Field Match vs. Free Text Search
event.code: "4625" and user.name: "administrator"

# 2. Wildcards & Existence Checks
process.name: powershell* and process.command_line: *-enc*
source.ip: *                      # Matches events where the field 'source.ip' exists

# 3. Numerical & Range Comparisons
http.response.status_code >= 400 and http.response.bytes > 5000
source.ip: "192.168.1.0/24"       # CIDR notation supported natively on IP fields!

# 4. Grouping & Boolean Logic (and / or / not)
(event.code: "4624" or event.code: "4625") and not winlog.logon.type: "5"
```

### Common ECS (Elastic Common Schema) Field Names
| Category | ECS Field Examples |
| :--- | :--- |
| **Host / OS** | `host.name`, `host.ip`, `host.os.name` |
| **User** | `user.name`, `user.id`, `user.domain` |
| **Process** | `process.name`, `process.pid`, `process.command_line`, `process.executable`, `process.parent.name`, `process.hash.sha256` |
| **Network** | `source.ip`, `source.port`, `destination.ip`, `destination.port`, `network.protocol`, `dns.question.name` |
| **File** | `file.name`, `file.path`, `file.extension`, `file.hash.sha256` |

---

## Chapter 5: Introduction to SOAR

### What is SOAR?
- **SOAR (Security Orchestration, Automation, and Response):** Platforms (such as *Palo Alto Cortex XSOAR*, *Splunk SOAR / Phantom*, *Shuffle*, *Tines*) that connect disparate security tools via APIs to automate repetitive L1 triage and containment tasks.

### The Three Pillars of SOAR
1. **Security Orchestration:** Integrating different internal and external tools (SIEM, EDR, Firewall, Active Directory, VirusTotal, Jira/ServiceNow) so they can talk to each other through API connectors.
2. **Security Automation:** Executing machine-speed workflows (**Playbooks**) without human intervention—such as automatically extracting IPs/hashes from every new alert, querying VirusTotal, and appending the reputation score to the ticket before an L1 analyst even opens it.
3. **Incident Response (Case Management):** Providing a unified ticketing workspace where analysts collaborate, review automated enrichment results, and click one-button approval actions (e.g., *"Approve Firewall Block"* or *"Reset AD User Password"*).

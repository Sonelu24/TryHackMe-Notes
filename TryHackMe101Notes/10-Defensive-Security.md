# Module 10: Defensive Security

> **Overview:** Shifting to the Blue Team perspective, this module covers Security Operations Centers (SOC), Digital Forensics, Incident Response frameworks, and parsing system/application logs.

---

## Chapter 1: SOC Fundamentals

### What is a SOC (Security Operations Center)?
A centralized unit of people, processes, and technology dedicated to **24/7 continuous security monitoring**, threat detection, triage, and response across an organization's IT infrastructure.

### The Three Pillars of a SOC (PPT)
1. **People (Three-Tiered Analyst Structure):**
   - **Tier 1 — Alert Analyst (Triage Specialist):** Monitors incoming SIEM/EDR alerts, filters out **False Positives**, enriches indicators (IPs, hashes, domains), and escalates confirmed incidents (**True Positives**) to Tier 2.
   - **Tier 2 — Incident Responder:** Performs deep-dive root-cause analysis on escalated tickets, correlates multi-stage attacks, and executes containment and remediation actions.
   - **Tier 3 — Threat Hunter / SME:** Proactively hunts for advanced persistent threats (APTs) that bypass automated alerts, performs malware reverse engineering, and writes custom detection rules.
   - **SOC Manager:** Oversees operations, SLA metrics (**MTTD** — Mean Time to Detect, **MTTR** — Mean Time to Respond), and reporting to leadership.
2. **Processes:**
   - **Alert Triage:** Classifying alerts into:
     - *True Positive (TP):* Legitimate alert triggered by real malicious activity.
     - *False Positive (FP):* Alert triggered by benign activity (e.g., an admin script).
     - *True Negative (TN):* Normal traffic correctly ignored.
     - *False Negative (FN):* Malicious activity missed by detection rules (most dangerous!).
   - **Playbooks / Runbooks:** Standardized step-by-step checklists guiding analysts on how to investigate specific alert types (e.g., *Phishing Playbook*, *Ransomware Playbook*).
3. **Technology:**
   - **SIEM** (Splunk, ELK, Microsoft Sentinel), **EDR** (CrowdStrike, Velociraptor), **SOAR** (Security Orchestration, Automation, and Response), and **Threat Intelligence Feeds**.

---

## Chapter 2: Digital Forensics Fundamentals

### Core Concepts
- **Digital Forensics (DF):** The application of science to identify, collect, preserve, analyze, and present digital evidence in a manner that is legally admissible in court or internal investigations.
- **Chain of Custody:** A formal chronological document tracking **who** handled the evidence, **when**, **why**, and **where** it was stored from the moment of seizure to presentation. If the chain of custody is broken, the evidence becomes inadmissible!

### The Order of Volatility (RFC 3227)
When collecting evidence from a live compromised system, always collect the most **volatile** (short-lived) data first before powering off the machine:
1. **CPU Registers & Cache** (Nanoseconds)
2. **RAM / System Memory**, Routing Tables, ARP Cache, Running Processes, Active Network Connections
3. **Temporary File Systems / Swap Space / Pagefile (`pagefile.sys`)**
4. **Hard Disk / Non-Volatile Storage (`SSD` / `HDD`)**
5. **Remote Logging & Monitoring Data**
6. **Physical Configuration & Archival Media (Backups)**

### Forensic Acquisition & Write Blockers
- **Never analyze the original evidence drive directly!**
- Use a hardware or software **Write Blocker** to prevent accidental modification of timestamps or metadata.
- Create a bit-by-bit **Forensic Image** (`.raw`, `.dd`, `.E01`) and compute the **SHA-256 / MD5 hash** of both the original drive and the forensic copy. Matching hashes prove mathematical **Integrity**.

### Practical Artifact Analysis Tools
- **`exiftool` / `pdfinfo`:** Extract hidden metadata from images and PDFs (Author name, GPS coordinates, camera model, creation timestamps).
- **`strings`:** Extract readable ASCII/Unicode text strings from binary files or memory dumps.
- **`Autopsy` / `FTK Imager`:** GUI disk image analysis suites (recover deleted files, inspect registry hives, timeline analysis).
- **`Volatility`:** Framework for analyzing captured RAM dumps (`.mem`, `.vmem`).

---

## Chapter 3: Incident Response Fundamentals

### What is an Incident?
- **Event:** Any observable occurrence in a system or network (e.g., a user logs in, a firewall blocks a packet).
- **Security Incident:** An event (or series of events) that violates security policies and compromises the **Confidentiality, Integrity, or Availability (CIA)** of an asset (e.g., ransomware execution, data exfiltration).

### Incident Response Frameworks
#### 1. SANS 6-Step Framework (`PICERL`)
1. **P — Preparation:** Establish IR policies, train the CSIRT, deploy logging/SIEM/EDR, and maintain offline backups *before* an incident occurs.
2. **I — Identification:** Detect the breach via alerts/logs, determine scope, classify severity, and confirm it is a True Positive.
3. **C — Containment:** Stop the bleeding so the attacker cannot spread laterally:
   - *Short-term containment:* Isolate the infected host from the network (EDR host isolation or unplugging the VLAN port) while keeping the machine powered on for memory forensics.
   - *Long-term containment:* Apply temporary firewall blocks or network segmentation while rebuilding clean systems.
4. **E — Eradication:** Completely remove the root cause and all attacker persistence mechanisms (delete malware, reset compromised domain credentials, patch the exploited CVE).
5. **R — Recovery:** Restore systems to normal production from known-clean backups and monitor closely for re-infection.
6. **L — Lessons Learned (Post-Mortem):** Hold a retrospective meeting within 1–2 weeks to document the timeline, update detection rules, and fix security gaps.

#### 2. NIST SP 800-61 (4 Phases)
Consolidates the same steps into 4 lifecycle phases:
1. **Preparation**
2. **Detection and Analysis** *(SANS Identification)*
3. **Containment, Eradication, and Recovery**
4. **Post-Incident Activity** *(SANS Lessons Learned)*

---

## Chapter 4: Logs Fundamentals

### Why Logs Matter
Logs provide the historical audit trail ("black box recorder") of everything that occurred on a system or network.

### Common Log Types & Default Locations
| System / Source | Key Log Path / Tool | What It Records |
| :--- | :--- | :--- |
| **Linux Auth** | `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL) | SSH logins, `sudo` executions, user creation (`useradd`) |
| **Linux System** | `/var/log/syslog` or `/var/log/messages` | Cron jobs, kernel events, service startups/crashes |
| **Apache / Nginx** | `/var/log/apache2/access.log` & `/var/log/nginx/access.log` | Every HTTP request (Client IP, Timestamp, Method, URI, Status Code, User-Agent) |
| **Windows Security** | `C:\Windows\System32\winevt\Logs\Security.evtx` | Logon success (`4624`), Logon failure (`4625`), New process created (`4688`), User created (`4720`) |
| **Windows Sysmon** | `Microsoft-Windows-Sysmon/Operational` | Granular telemetry: Process creation with SHA256 hashes (`Event ID 1`), Network connections (`3`), DNS queries (`22`) |

### Anatomy of a Web Server Access Log (Combined Log Format)
```text
10.10.14.5 - - [26/Oct/2026:13:45:12 +0000] "GET /admin/config.php HTTP/1.1" 200 1420 "-" "sqlmap/1.7.2"
```
- `10.10.14.5`: Source IP address of the client.
- `[26/Oct/2026:13:45:12 +0000]`: Timestamp of the request.
- `"GET /admin/config.php HTTP/1.1"`: HTTP Method, requested URI, and protocol version.
- `200`: HTTP response status code (`200 OK` means the request succeeded!).
- `1420`: Response size in bytes.
- `"sqlmap/1.7.2"`: `User-Agent` string (reveals automated scanning tools!).

### Command-Line Log Parsing Cheat Sheet
```bash
# Find all failed SSH login attempts in auth.log
grep "Failed password" /var/log/auth.log

# Extract the top 10 IP addresses hitting an Apache web server
cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -nr | head -n 10

# Search for SQLi or Path Traversal attempts in web logs
grep -E "UNION|SELECT|\.\./|etc/passwd" access.log
```

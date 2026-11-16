# TryHackMe — SOC Level 1 Study Notes

A complete, modular reference and study guide covering the **14 Modules** of the [TryHackMe SOC Level 1](https://tryhackme.com/path/outline/soclevel1) learning path. Each module is organized into its own Markdown file, with individual rooms structured as chapters containing SOC workflows, detection engineering queries, log/packet analysis techniques, and incident triage takeaways.

---

## 📚 Curriculum & Module Index

| # | Module | Rooms Covered |
| :--- | :--- | :--- |
| **01** | [Blue Team Introduction](./01-Blue-Team-Introduction.md) | 1. Junior Security Analyst Intro<br>2. SOC Role in Blue Team<br>3. Human as Attack Vectors<br>4. System as Attack Vectors |
| **02** | [SOC Team Internals](./02-SOC-Team-Internals.md) | 1. SOC L1 Alert Triage<br>2. SOC L1 Alert Reporting<br>3. SOC Workbooks and Lookups<br>4. SOC Metrics and Objectives<br>5. Introduction to Phishing |
| **03** | [Core SOC Solutions](./03-Core-SOC-Solutions.md) | 1. Introduction to EDR<br>2. Introduction to SIEM<br>3. Splunk: The Basics<br>4. Elastic Stack: The Basics<br>5. Introduction to SOAR |
| **04** | [Cyber Defence Frameworks](./04-Cyber-Defence-Frameworks.md) | 1. Pyramid of Pain<br>2. Cyber Kill Chain<br>3. Unified Kill Chain<br>4. MITRE ATT&CK |
| **05** | [Phishing Analysis](./05-Phishing-Analysis.md) | 1. Phishing Analysis Fundamentals<br>2. Phishing Emails in Action<br>3. Phishing Analysis Tools<br>4. Phishing Prevention<br>5. The Greenholt Phish & Snapped Phish-ing Line |
| **06** | [Network Traffic Analysis](./06-Network-Traffic-Analysis.md) | 1. Network Traffic Basics<br>2. Wireshark: The Basics<br>3. Wireshark: Packet Operations<br>4. Wireshark: Traffic Analysis<br>5. NetworkMiner |
| **07** | [Network Security Monitoring](./07-Network-Security-Monitoring.md) | 1. Network Security Essentials<br>2. Network Discovery Detection<br>3. Data Exfiltration Detection<br>4. Man-in-the-Middle Detection<br>5. IDS Fundamentals & Snort |
| **08** | [Web Security Monitoring](./08-Web-Security-Monitoring.md) | 1. Web Security Essentials<br>2. Detecting Web Attacks<br>3. Detecting Web Shells<br>4. Detecting Web DDoS<br>5. Upload and Conquer |
| **09** | [Windows Security Monitoring](./09-Windows-Security-Monitoring.md) | 1. Windows Logging for SOC<br>2. Windows Threat Detection 1 (Initial Access)<br>3. Windows Threat Detection 2 (Discovery & Cred Theft)<br>4. Windows Threat Detection 3 (Persistence & C2) |
| **10** | [Linux Security Monitoring](./10-Linux-Security-Monitoring.md) | 1. Linux Logging for SOC<br>2. Linux Threat Detection 1 (Initial Access)<br>3. Linux Threat Detection 2 (Privesc & Evasion)<br>4. Linux Threat Detection 3 (Persistence & C2) |
| **11** | [Malware Concepts for SOC](./11-Malware-Concepts-for-SOC.md) | 1. Malware Classification<br>2. Intro to Malware Analysis<br>3. Living Off the Land Attacks (LOLBins)<br>4. Shadow Trace (Challenge) |
| **12** | [Threat Analysis Tools](./12-Threat-Analysis-Tools.md) | 1. Intro to Cyber Threat Intel (CTI)<br>2. File and Hash Threat Intel<br>3. IP and Domain Threat Intel<br>4. Invite Only (Challenge) |
| **13** | [SIEM Triage for SOC](./13-SIEM-Triage-for-SOC.md) | 1. Log Analysis with SIEM<br>2. Alert Triage with Splunk<br>3. Alert Triage with Elastic<br>4. ItsyBitsy & Benign (Challenges) |
| **14** | [SOC Level 1 Capstone Challenges](./14-SOC-Level-1-Capstone-Challenges.md) | 1. Tempest<br>2. Boogeyman 1, 2 & 3<br>3. Hidden Hooks & Open Door |

---

## 🛠️ Core SOC Toolset Practiced

- **SIEM & Log Analytics:** `Splunk (SPL)`, `Elastic Stack / Kibana (KQL / Lucene)`, `Windows Event Viewer`, `Sysmon`, `Linux auditd / syslog`
- **Network Analysis & NIDS:** `Wireshark`, `NetworkMiner`, `Snort`, `Zeek`, `tcpdump`
- **Threat Intelligence & Enrichment:** `VirusTotal`, `Abuse.ch (MalwareBazaar, URLhaus, ThreatFox)`, `AbuseIPDB`, `UrlScan.io`, `Cisco Talos`, `MITRE ATT&CK Navigator`, `CyberChef`
- **Endpoint & Phishing Triage:** `EDR Telemetry`, `PhishTool`, `MessageHeader Analyzer`, `PEStudio`, `Strings / ExifTool`

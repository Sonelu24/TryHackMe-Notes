# Module 01: Blue Team Introduction

> **Overview:** This module introduces the day-to-day responsibilities of a Junior (Tier 1) SOC Analyst, the structure of a Blue Team, and how adversaries target both humans (social engineering) and technical systems (vulnerabilities & misconfigurations).

---

## Chapter 1: Junior Security Analyst Intro

### Role of a Junior (Tier 1) Security Analyst
A **Junior Security Analyst (SOC L1 Analyst)** is on the front line of cyber defense, monitoring organizational networks and endpoints 24/7.
- **Core Responsibilities:**
  1. **Continuous Monitoring & Triage:** Reviewing real-time alerts inside the **SIEM** (Splunk, Elastic, Sentinel) and **EDR** consoles.
  2. **Log & Artifact Investigation:** Collecting context around an alert (checking authentication logs, process creation trees, network connections, and threat intelligence feeds).
  3. **Classification:** Determining whether an alert is a **True Positive (TP)** or **False Positive (FP)**.
  4. **Documentation & Escalation:** Writing clear, structured incident reports (5 Ws: *Who, What, When, Where, Why/How*) and escalating complex or confirmed breaches to **Tier 2 Incident Responders**.

---

## Chapter 2: SOC Role in Blue Team

### Blue Team Organizational Structure
Defensive security is broader than just the SOC. A mature Blue Team integrates several specialized units:
- **SOC (Security Operations Center):** Reactive and proactive 24/7 monitoring, alert triage, and initial containment.
- **CSIRT / DFIR (Computer Security Incident Response Team):** Deep-dive digital forensics (disk, memory) and major incident eradication/recovery.
- **Threat Intelligence (CTI):** Tracks adversary groups (APTs), collects Indicators of Compromise (IoCs), and feeds TTPs into detection engineering.
- **Security Engineering & Architecture:** Builds and maintains firewalls, EDRs, SIEM ingestion pipelines, and system hardening baselines.
- **Vulnerability Management:** Conducts regular authenticated/unauthenticated scans (`Nessus`, `Qualys`) and coordinates patching with IT Ops.

### The SOC Three-Tier Model
| Tier | Role Title | Primary Duties |
| :--- | :--- | :--- |
| **Tier 1** | **Alert Analyst** | Real-time queue monitoring, initial triage following **Workbooks/Playbooks**, IoC enrichment, filtering False Positives |
| **Tier 2** | **Incident Responder** | Investigates escalated True Positives, correlates multi-host compromise, performs host isolation and remediation |
| **Tier 3** | **Threat Hunter / SME** | Proactive hypothesis-driven threat hunting, malware reverse engineering, and authoring custom SIEM/EDR detection rules |

---

## Chapter 3: Human as Attack Vectors

### Why Target Humans?
Even the most hardened firewall cannot stop an attack if an employee is tricked into running a malicious payload or handing over their MFA token. **Social Engineering** manipulates human psychology (*Urgency, Fear, Authority, Greed, Curiosity, Helpfulness*).

### Common Social Engineering Vectors
1. **Phishing (and Variants):**
   - **Bulk Phishing:** Mass emails sent to thousands of users impersonating banks, IT helpdesks, or SaaS platforms.
   - **Spear Phishing:** Highly targeted phishing tailored to a specific individual or department using OSINT (e.g., targeting HR with a fake `CV_Resume.pdf.exe`).
   - **Whaling:** Spear phishing aimed specifically at C-level executives (`CEO`, `CFO`) to authorize fraudulent wire transfers (**BEC — Business Email Compromise**).
   - **Smishing & Vishing:** Phishing conducted via SMS text messages (`Smishing`) or voice calls (`Vishing`).
2. **Malicious Attachments & Links:**
   - **Weaponized Documents:** Office files with malicious VBA macros (`.docm`, `.xlsm`), ISO/IMG disk images (which bypass Mark-of-the-Web `MotW`), or archive files (`.zip`, `.7z`) containing `.lnk` shortcuts.
   - **Credential Harvesting Pages:** Lookalike login portals hosted on typosquatted domains (`micros0ft-support.com`) using reverse proxies (`Evilginx`) to steal session cookies and bypass MFA.
3. **Physical & In-Person Vectors:**
   - **Tailgating / Piggybacking:** Following an authorized employee through a badge-controlled door.
   - **USB Baiting ( USB Drop Attack):** Leaving infected USB drives labeled `"Q4 Executive Bonuses"` in the company parking lot.

---

## Chapter 4: System as Attack Vectors

### How Attackers Compromise Technical Assets
When attackers target systems directly rather than humans, they exploit weaknesses across the network, operating system, or application stack:

1. **Software Vulnerabilities (CVEs):**
   - **Known Vulnerabilities (N-Days):** Publicly disclosed flaws with assigned **CVE IDs** (e.g., `Log4Shell`, `EternalBlue`, `ProxyLogon`) where patches exist, but the target organization has not applied them yet.
   - **Zero-Day (`0-day`) Vulnerabilities:** Flaws unknown to the software vendor with no patch available at the time of exploitation.
2. **Security Misconfigurations:**
   - Exposed administrative services on the public internet (`RDP 3389`, `SMB 445`, `SSH 22`, `Docker API`, `Elasticsearch 9200`).
   - Default credentials (`admin:admin`), anonymous FTP access, or publicly readable cloud storage buckets (`AWS S3` / `Azure Blob`).
3. **Credential Attacks:**
   - **Brute Force:** Systematically trying thousands of passwords against a single account.
   - **Password Spraying:** Trying *one* common password (`Summer2026!`) across *hundreds* of usernames to avoid triggering account lockout thresholds.
   - **Credential Stuffing:** Reusing leaked `email:password` pairs from third-party data breaches against corporate portals.
4. **Supply Chain & Third-Party Compromise:**
   - Compromising a trusted software vendor update (e.g., *SolarWinds*) or an open-source library (`npm` / `PyPI`) to gain access to downstream customer networks.

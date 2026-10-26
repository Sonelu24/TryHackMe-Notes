# Module 01: Start Your Cyber Security Journey

> **Overview:** This introductory module establishes the core mindset for both offensive (Red Team) and defensive (Blue Team) security operations, along with practical open-source intelligence (OSINT) and technical research skills.

---

## Chapter 1: Offensive Security Intro

### Core Concepts
- **Offensive Security:** The practice of breaking into computer systems, exploiting software bugs, and finding loopholes in applications to test an organization's defenses before malicious actors do (Ethical Hacking / Penetration Testing).
- **Authorization & Scope:** Ethical hackers only test systems they have explicit, written legal permission to target (Rules of Engagement).

### Lab Walkthrough: Hacking Your First Website (FakeBank)
In this room, we simulated an authorized penetration test against a vulnerable banking application (`FakeBank`) to uncover hidden administrative functionality.

1. **Enumeration via Directory Brute-Forcing (`gobuster`):**
   Websites often contain unlinked pages (admin portals, backup directories) that aren't visible to regular users.
   ```bash
   gobuster dir -u http://fakebank.thm -w wordlist.txt
   ```
   - `-u`: Target URL.
   - `-w`: Path to wordlist containing common directory names.
2. **Findings:**
   - `/images` (Status: 301) — Standard static asset directory.
   - `/bank-transfer` (Status: 200) — Unprotected administrative transfer page!
3. **Exploitation:**
   - Navigated to `http://fakebank.thm/bank-transfer` which lacked authentication controls (Broken Access Control) and transferred `$2000` from account `2276` to our account `8881`.

### Key Takeaways
- Never rely on **security by obscurity** (hiding sensitive pages without authentication).
- Enumeration is the most critical step in offensive security.

---

## Chapter 2: Defensive Security Intro

### Core Concepts
- **Defensive Security (Blue Team):** Focuses on two primary tasks:
  1. **Preventing** intrusions from occurring.
  2. **Detecting** and responding to intrusions when they happen.
- **Core Defensive Domains:**
  - **SOC (Security Operations Center):** Team of security analysts monitoring network and system logs in real-time to detect threats.
  - **Threat Intelligence:** Gathering information about actual or potential adversaries (Tactics, Techniques, and Procedures — TTPs) to prepare defenses.
  - **DFIR (Digital Forensics and Incident Response):**
    - *Digital Forensics:* Analyzing digital evidence (file systems, memory, network logs) to reconstruct an attack.
    - *Incident Response:* Methodology to handle a breach (Preparation, Detection & Analysis, Containment, Eradication & Recovery, Post-Incident Activity).
  - **Malware Analysis:** Examining malicious software using **Static Analysis** (inspecting code/strings without running it) and **Dynamic Analysis** (running malware in a controlled sandbox).

### Lab Walkthrough: Investigating a SIEM Alert
1. **Inspecting the SIEM Alert:** Identified an alert for a suspicious login attempt from an external IP (`143.110.250.149`).
2. **Threat Intelligence Lookup:** Checked the IP reputation using an IP scanner / Threat Intel feed and confirmed the IP was malicious (associated with brute-force attacks).
3. **Escalation & Containment:** Escalated the incident to the SOC Team Lead and added a firewall block rule for the malicious IP address.

---

## Chapter 3: Search Skills

### Core Concepts
- **Evaluating Information:** Critical thinking when evaluating sources:
  - Verify the source credibility (official documentation vs. random blog).
  - Cross-reference multiple sources.
  - Check publication dates (security vulnerabilities and tools evolve fast).

### Advanced Search Operators (Google Dorking)
Search engines index massive amounts of public data. Using operators narrows down results for research or OSINT:

| Operator | Description | Example |
| :--- | :--- | :--- |
| `"exact phrase"` | Searches for the exact words in order | `"TryHackMe" cybersecurity` |
| `site:` | Restricts results to a specific domain | `site:tryhackme.com linux` |
| `-` | Excludes a specific term or domain | `encryption -aes` |
| `filetype:` | Searches for specific file extensions | `filetype:pdf "penetration testing"` |
| `intitle:` | Looks for keywords in the HTML page title | `intitle:"index of" backup` |
| `inurl:` | Looks for keywords inside the URL | `inurl:admin login` |

### Specialized Security Search Tools & Repositories
- **System Documentation:**
  - `man <command>` or `<command> --help` on Linux.
  - [tldr.sh](https://tldr.sh/) & [explainshell.com](https://explainshell.com/) for quick command breakdowns.
- **Vulnerability Databases:**
  - **CVE (Common Vulnerabilities and Exposures):** Standardized ID format (`CVE-YYYY-NNNNN`) managed by MITRE/NVD ([cve.org](https://www.cve.org/), [nvd.nist.gov](https://nvd.nist.gov/)).
  - **Exploit-DB:** Archive of public exploits and vulnerable software ([exploit-db.com](https://www.exploit-db.com/)) — searchable offline in Kali via `searchsploit`.
- **Threat & Asset Search Engines:**
  - **Shodan:** Search engine for internet-connected devices, open ports, and service banners.
  - **Censys:** Monitors internet assets, certificates, and exposed hosts.
  - **VirusTotal:** Inspects files, hashes, domains, and IPs against 70+ antivirus engines.
  - **Have I Been Pwned (HIBP):** Checks if emails or passwords appeared in known data breaches.
  - **GTFOBins / LOLBAS:** Catalogs of legitimate Linux (`GTFOBins`) and Windows (`LOLBAS`) binaries that can be abused for privilege escalation or file transfers.

# Module 04: Cyber Defence Frameworks

> **Overview:** Threat frameworks help SOC analysts structure investigations, understand adversary behavior, and map detections across the attack lifecycle. This module covers David Bianco's **Pyramid of Pain**, Lockheed Martin's **Cyber Kill Chain**, the **Unified Kill Chain**, and **MITRE ATT&CK®**.

---

## Chapter 1: Pyramid of Pain

### Core Concept
Created by **David J. Bianco**, the **Pyramid of Pain** ranks different types of **Indicators of Compromise (IoCs)** by how easy they are for defenders to detect/block versus how much **pain (cost and disruption)** it causes the adversary when defenders successfully detect and deny them.

```text
                  /\
                 /  \        TTPs (Tactics, Techniques & Procedures) -> [Tough! Adversary must relearn/rebuild]
                /----\
               / Tools\      Tools (Mimikatz, Cobalt Strike)         -> [Challenging! Must rewrite/obfuscate tools]
              /--------\
             / Artifacts\    Network/Host Artifacts (User-Agent, URI, Registry keys) -> [Annoying]
            /------------\
           / Domain Names \  Domain Names (evil-c2.com)              -> [Simple! Buy a new domain in minutes]
          /----------------\
         /   IP Addresses   \ IP Addresses (185.220.101.4)           -> [Easy! Spin up a new VPS/Proxy IP]
        /--------------------\
       /     Hash Values      \ Hash Values (MD5, SHA256)            -> [Trivial! Flip 1 bit / recompile binary]
      /________________________\
```

### Breakdown of the 6 Levels (Bottom to Top)
1. **Hash Values (`MD5`, `SHA-1`, `SHA-256`) — *Trivial*:**
   - Exact cryptographic fingerprint of a file. Appending a single space or recompiling the malware completely changes the hash (**Fuzzy Hashes** like `SSDEEP` or **ImpHash** help partially mitigate this).
2. **IP Addresses — *Easy*:**
   - Attackers rapidly rotate IPs using cloud VPS providers, Tor exit nodes, Fast Flux DNS, or residential proxies.
3. **Domain Names — *Simple*:**
   - Slightly harder than IPs because registering a domain and propagating DNS takes time/money, though attackers use **DGAs (Domain Generation Algorithms)** or URL shorteners.
4. **Network / Host Artifacts — *Annoying*:**
   - Observable traces left by attacker activity: custom HTTP `User-Agent` strings, specific C2 URI paths (`/jquery-3.3.1.min.js`), named pipes, or specific registry persistence keys.
5. **Tools — *Challenging*:**
   - Detecting the attacker's software capability itself (via YARA rules, Fuzzy Hashes, or PE imports) regardless of its file hash or C2 domain—forcing the attacker to find or write a new tool.
6. **TTPs (Tactics, Techniques, and Procedures) — *Tough!*:**
   - Detecting the underlying *behavior* (e.g., *Any process reading `lsass.exe` memory* or *`winword.exe` spawning `powershell.exe`*). When you detect at the TTP level, the attacker must completely reinvent how they operate!

---

## Chapter 2: Cyber Kill Chain

### Overview
Developed by **Lockheed Martin** in 2011, the **Cyber Kill Chain** models an external perimeter breach as a sequential **7-stage** pipeline. Stopping the adversary at *any* stage breaks the chain.

| Stage | Name | Adversary Goal & Examples | Defensive Controls |
| :--- | :--- | :--- | :--- |
| **1** | **Reconnaissance** | Harvesting email addresses, OSINT, port scanning target infrastructure | Web logs, firewall scan detection, minimizing public OSINT footprint |
| **2** | **Weaponization** | Coupling an exploit with a backdoor payload into a deliverable file (e.g., malicious `.docm` or `.pdf`) | *(Occurs offline on attacker infrastructure; invisible to target SOC, tracked via CTI)* |
| **3** | **Delivery** | Transmitting the weaponized bundle to the victim (Phishing email, USB drop, Watering hole website) | Email Security Gateways (SEG), Web Proxies, SPF/DKIM/DMARC |
| **4** | **Exploitation** | Triggering the vulnerability or user execution (`CVE-2024-21413`, VBA macro execution, SQLi) | Patch management, DEP/ASLR, disabling Office macros, WAF |
| **5** | **Installation** | Installing a persistent backdoor, web shell, Registry Run key, or scheduled task on the victim system | EDR behavioral blocking, Sysmon (`Event ID 11/12/13`), File Integrity Monitoring (FIM) |
| **6** | **Command & Control (C2)** | Establishing a two-way beacon channel back to the attacker (`HTTPS`, `DNS tunneling`, `IRC`) | Egress firewall filtering, NIDS (`Snort`/`Zeek`), DNS sinkholing |
| **7** | **Actions on Objectives** | Achieving the final goal: Data Exfiltration, Ransomware encryption, or Lateral Movement | DLP (Data Loss Prevention), Network Segmentation, Volume Shadow Copy protection |

### Limitations of the Classic Cyber Kill Chain
- Heavily focused on **perimeter/malware delivery**; poorly models post-exploitation **Internal Lateral Movement**, **Privilege Escalation**, or **Insider Threats**.

---

## Chapter 3: Unified Kill Chain

### Overview
Created by **Paul Pols** in 2017, the **Unified Kill Chain (UKC)** combines and expands Lockheed Martin's Cyber Kill Chain and MITRE ATT&CK into **18 distinct phases** grouped into **3 overarching cycles**, addressing internal lateral movement and post-breach behavior.

### The 3 Overarching Phases of the Unified Kill Chain
1. **Phase 1: Initial Foothold (Getting In)**
   - *Stages (1–8):* `Reconnaissance` $\rightarrow$ `Weaponization` $\rightarrow$ `Delivery` $\rightarrow$ `Social Engineering` $\rightarrow$ `Exploitation` $\rightarrow$ `Persistence` $\rightarrow$ `Defense Evasion` $\rightarrow$ `Command & Control`.
   - **Goal:** Compromise an initial perimeter endpoint or external-facing server.
2. **Phase 2: Network Propagation (Moving Laterally Inside)**
   - *Stages (9–14):* `Pivoting` $\rightarrow$ `Discovery` $\rightarrow$ `Privilege Escalation` $\rightarrow$ `Execution` $\rightarrow$ `Credential Access` $\rightarrow$ `Lateral Movement`.
   - **Goal:** Loop repeatedly through internal hosts to escalate privileges and reach critical crown-jewel assets (like the Active Directory Domain Controller).
3. **Phase 3: Action on Objectives (Mission Impact)**
   - *Stages (15–18):* `Collection` $\rightarrow$ `Exfiltration` $\rightarrow$ `Impact` (CIA compromise/Ransomware) $\rightarrow$ `Objectives`.

---

## Chapter 4: MITRE ATT&CK

### What is MITRE ATT&CK®?
- **MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge):** A globally accessible, real-world knowledge base of adversary behaviors observed in the wild, organized into a matrix of **Tactics** and **Techniques** across Enterprise (`Windows`, `macOS`, `Linux`, `Cloud`, `Active Directory`), Mobile, and ICS environments.

### Core Terminology
- **Tactics (The Columns — *"The Why"*):** The adversary's tactical goal at a given step. There are **14 Enterprise Tactics**:
  1. `Reconnaissance` (`TA0043`)
  2. `Resource Development` (`TA0042`)
  3. `Initial Access` (`TA0001`)
  4. `Execution` (`TA0002`)
  5. `Persistence` (`TA0003`)
  6. `Privilege Escalation` (`TA0004`)
  7. `Defense Evasion` (`TA0005`)
  8. `Credential Access` (`TA0006`)
  9. `Discovery` (`TA0007`)
  10. `Lateral Movement` (`TA0008`)
  11. `Collection` (`TA0009`)
  12. `Command and Control` (`TA0011`)
  13. `Exfiltration` (`TA0010`)
  14. `Impact` (`TA0040`)
- **Techniques & Sub-Techniques (The Cells — *"The How"*):** Specific technical methods used to achieve a Tactic:
  - *Technique:* `T1059` — Command and Scripting Interpreter.
  - *Sub-Technique:* `T1059.001` — PowerShell.
- **Procedures:** The exact real-world implementation used by a specific **Threat Group (`Gxxxx`)** or **Software/Malware (`Sxxxx`)** (e.g., *APT29 (`G0016`) uses encoded PowerShell scripts to download Cobalt Strike (`S0154`)*).
- **Mitigations (`Mxxxx`) & Data Sources (`DSxxxx`):** Each technique page documents how to prevent the technique (`Mitigations`) and which log sources detect it (`Process: Process Creation`, `Command: Command Execution`).

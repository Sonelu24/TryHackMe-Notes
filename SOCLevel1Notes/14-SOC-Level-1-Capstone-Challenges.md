# Module 14: SOC Level 1 Capstone Challenges

> **Overview:** The Capstone module tests every skill across the **SOC Level 1** path through realistic, multi-stage breach scenarios (`Tempest`, `Boogeyman 1/2/3`, `Hidden Hooks`, `Open Door`), combining phishing emails, malicious attachments, `.pcap` network captures, memory dumps, and SIEM (`Splunk` / `Elastic`) endpoint telemetry.

---

## Chapter 1: Tempest (Full-Scope Endpoint & Network Incident)

### Scenario & Attack Chain Summary
In **Tempest**, we acted as an incident responder investigating a workstation compromised via a weaponized Word document (`maldoc`) leading to full C2 takeover.

1. **Phase 1 — Initial Access (Malicious Document):**
   - Analyzed Sysmon logs in `Timeline Explorer` / SIEM and identified `WINWORD.EXE` opening a `.doc` file from the user's Downloads folder and immediately spawning `cmd.exe` / `powershell.exe` (`Sysmon Event ID 1`).
2. **Phase 2 — Execution & Staging (Obfuscated PowerShell):**
   - Extracted the Base64-encoded PowerShell command (`-e ...`) and decoded it using **CyberChef** (`From Base64` $\rightarrow$ `Decode text UTF-16LE`).
   - The script used `Invoke-WebRequest` (`iwr`) to download a stage-2 binary (`final.exe`) and a C# reverse shell.
3. **Phase 3 — Discovery, Privilege Escalation & C2:**
   - Correlated `Sysmon Event ID 22` (DNS queries) and `Event ID 3` (Network connections) with Wireshark `.pcap` traffic to identify the attacker's HTTP C2 server, user-agent anomalies, and privilege escalation checks (`chrasco.exe` / `SystemInfo` / token impersonation).

---

## Chapter 2: The Boogeyman Series (Boogeyman 1, 2, and 3)

### Boogeyman 1: Phishing, PowerShell & DNS/Network Forensics
- **Artifacts Analyzed:** Raw `.eml` phishing email, PowerShell history/logs, and a `.pcap` network capture.
- **Attack Chain:**
  1. Victim (`maxine.beck`) received a phishing email with an attached `.iso` / `.lnk` file that executed a PowerShell script.
  2. PowerShell downloaded a stage-2 payload and established a **C2 channel** over HTTP/DNS.
  3. Used Wireshark and command-line log parsing to trace the attacker's lateral movement, C2 domains, and exfiltrated data.

### Boogeyman 2: Memory Forensics (`Volatility 3`) & Maldoc Analysis
- **Artifacts Analyzed:** Phishing `.eml` with weaponized Word `.doc` attachment (`olehba`/`oledump.py`) and a raw Windows RAM dump (`.raw` / `.vmem`).
- **Key `Volatility 3` Commands Used:**
  ```bash
  # 1. Identify OS profile and kernel details
  vol -f memory.dmp windows.info

  # 2. View process hierarchy (spot WINWORD.EXE -> powershell.exe / updater.exe)
  vol -f memory.dmp windows.pstree

  # 3. Inspect full command-line arguments of running processes
  vol -f memory.dmp windows.cmdline

  # 4. List active and closed network sockets (identify C2 IP & Port)
  vol -f memory.dmp windows.netscan

  # 5. Dump a suspicious process binary or memory region to disk for strings/hash lookup
  vol -f memory.dmp -o ./dump windows.pslist --pid <PID> --dump
  vol -f memory.dmp windows.filescan | grep -i "appdata"
  ```

### Boogeyman 3: SIEM Investigation in Elastic (Credential Dumping & Persistence)
- **Artifacts Analyzed:** Elastic Stack (`Kibana`) containing `Winlogbeat`, `Sysmon`, and `PowerShell` logs.
- **Attack Chain:**
  1. Initial access via phishing (`OUTLOOK.EXE` $\rightarrow$ `mshta.exe` / `powershell.exe`).
  2. Attacker enumerated the host, dumped credentials, established persistence via **Scheduled Tasks / WMI / Services**, and pivoted internally.

---

## Chapter 3: Master SOC L1 Capstone Triage Playbook

When dropped into any multi-artifact SOC Capstone challenge or real-world incident, follow this systematic 6-step playbook:

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. INITIAL ACCESS: How did the attacker get in?                         │
│    • Phishing: Check .eml headers, attachments, Sysmon ID 15 (MotW),    │
│      and Office child processes (WINWORD/EXCEL/OUTLOOK -> cmd/ps/mshta) │
│    • Brute Force: Check Event ID 4625 bursts followed by 4624           │
│    • Web Exploit: Check access.log POST/GET -> w3wp/www-data child proc │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 2. EXECUTION: What payload ran?                                         │
│    • Check Sysmon ID 1 / auditd / PowerShell 4104                       │
│    • Decode Base64 / XOR / Hex commands in CyberChef                    │
│    • Extract file hashes (SHA256) and check VirusTotal / MalwareBazaar  │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 3. PERSISTENCE: How did the attacker maintain access?                   │
│    • Windows: Registry Run keys (Sysmon 13), Scheduled Tasks (4698),    │
│      Services (7045/4697), Startup folder (Sysmon 11), New Users (4720) │
│    • Linux: crontabs, ~/.ssh/authorized_keys, systemd services, .bashrc │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 4. PRIVILEGE ESCALATION & CREDENTIAL ACCESS:                            │
│    • Windows: Sysmon ID 10 (lsass.exe access), comsvcs.dll MiniDump,    │
│      reg save HKLM\SAM, Event ID 4672 / 4732                            │
│    • Linux: sudo -l, SUID binaries (uid != euid), reading /etc/shadow   │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 5. COMMAND & CONTROL (C2): Where did the host beacon out to?            │
│    • Check Sysmon ID 22 (DNS) & ID 3 (Network) + Wireshark PCAPs        │
│    • Enrich external IPs/Domains on AbuseIPDB, ThreatFox, UrlScan       │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 6. LATERAL MOVEMENT & EXFILTRATION (IMPACT):                            │
│    • Check internal SMB (445), RDP (3389), WinRM (5985), or SSH (22)    │
│      connections originating FROM the compromised workstation           │
│    • Check archive staging (.zip/.7z) and large outbound transfers      │
└─────────────────────────────────────────────────────────────────────────┘
```

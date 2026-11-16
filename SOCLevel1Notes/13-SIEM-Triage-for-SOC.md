# Module 13: SIEM Triage for SOC

> **Overview:** This module brings together endpoint telemetry, network logs, and threat intelligence inside enterprise SIEM platforms (**Splunk** and **Elastic Security**) to execute end-to-end alert triage and incident reconstruction.

---

## Chapter 1: Log Analysis with SIEM

### Correlating Multi-Source Telemetry
A single log source rarely tells the whole story. Effective SIEM triage correlates events across multiple log types using shared pivot fields (**Timestamp**, **Internal IP**, **Hostname**, **Username**, **Process ID / GUID**):

```text
[1. Email Gateway / Proxy Log] -> User 's.connor' clicked URL 'http://185.220.101.4/invoice.zip' at 14:02:10 UTC
                                      │ (Pivot on Hostname / User + Time Window 14:02:00 - 14:10:00)
                                      ▼
[2. Sysmon Event ID 11 & 1]    -> 'chrome.exe' created 'invoice.zip'; 'explorer.exe' ran 'invoice.lnk' -> spawned 'powershell.exe'
                                      │ (Pivot on ProcessGuid / PID of powershell.exe)
                                      ▼
[3. Sysmon Event ID 22 & 3]    -> 'powershell.exe' resolved 'c2.badguy.com' and connected to '198.51.100.99:443'
                                      │ (Pivot on ParentProcessGuid / Registry & Scheduled Task logs)
                                      ▼
[4. Sysmon Event ID 13 / 4698] -> Created Registry Run key 'Updater' pointing to 'C:\Users\Public\svchost.exe'
```

---

## Chapter 2: Alert Triage with Splunk

### Structured Splunk Investigation Workflow
1. **Start with the Triggered Alert Query:**
   Inspect the exact search query and fields that triggered the alert, then widen the time window ($\pm 30$ minutes) around `_time` for that specific `host` or `user`.
2. **Trace the Process Lineage (`ParentProcessGuid` / `ProcessId`):**
   ```spl
   index=sysmon host="WKSTN-02" EventCode=1
   | table _time, User, ParentImage, ParentCommandLine, Image, CommandLine, Hashes
   | sort + _time
   ```
3. **Inspect Network Activity by Process:**
   ```spl
   index=sysmon host="WKSTN-02" (EventCode=3 OR EventCode=22)
   | stats count, values(QueryName) as DNS_Queries, values(DestinationIp) as Dest_IPs, values(DestinationPort) as Ports by Image
   ```
4. **Hunt for Persistence & Privilege Escalation:**
   ```spl
   index=* host="WKSTN-02" (EventCode=12 OR EventCode=13 OR EventCode=4697 OR EventCode=4698 OR EventCode=4720)
   | table _time, EventCode, Image, TargetObject, Details, TaskName, ServiceName
   ```

---

## Chapter 3: Alert Triage with Elastic

### Structured Kibana / Elastic Security Investigation Workflow
1. **Review the Alert in `Security -> Alerts`:**
   - Use **Timeline / Graphical Process Tree (`Analyze Event`)** to visually expand parent, sibling, and child processes of the alerting process.
2. **Pivot in `Discover` using KQL:**
   ```kql
   # 1. View all Sysmon process creations on the compromised host chronologically
   host.name: "WKSTN-02" and event.code: "1"

   # 2. Track all activity by a specific compromised user or malicious process PID
   host.name: "WKSTN-02" and (process.pid: 4812 or process.parent.pid: 4812)

   # 3. Hunt for lateral movement (Network/RDP logons from the infected host to other servers)
   event.code: "4624" and source.ip: "10.10.25.14" and winlog.logon.type: ("3" or "10")
   ```
3. **Field Statistics in the Left Sidebar:**
   - Click on fields like `process.name`, `destination.ip`, `dns.question.name`, or `event.code` in Kibana's left field list to immediately see the top 5 values and rare outliers.

---

## Chapter 4: Practical SIEM Challenges (ItsyBitsy & Benign)

### Key Investigation Takeaways
- **ItsyBitsy (ELK C2 Investigation):**
  - Investigated an alert for a suspicious outbound HTTP connection using `bitsadmin.exe` (`LOLBin`).
  - Pivoted in Kibana around the timestamp and discovered `bitsadmin` was downloading a Base64-encoded payload from a raw GitHub/external URL and establishing C2 communication.
- **Benign (Splunk Threat Hunting & Triage):**
  - Practiced distinguishing normal administrative scripts from genuine malicious **Living off the Land** activity across multiple departments (`HR`, `IT`, `Finance`).
  - Identified an infection triggered on a Finance host (`WinEventLog:Sysmon`) where a scheduled task / encoded PowerShell command downloaded an executable and created a backdoor local user account.

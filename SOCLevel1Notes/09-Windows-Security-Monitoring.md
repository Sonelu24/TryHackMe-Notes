# Module 09: Windows Security Monitoring

> **Overview:** Windows endpoints and servers generate rich security telemetry through native **Windows Event Logs (`.evtx`)**, **PowerShell Logs**, and **Sysmon (System Monitor)**. This module covers essential Event IDs and how to detect adversary tactics from Initial Access through Discovery, Credential Theft, Persistence, and C2.

---

## Chapter 1: Windows Logging for SOC

### Essential Windows Security Event IDs (`Security.evtx`)
| Event ID | Description | Key SOC Investigation Details |
| :--- | :--- | :--- |
| **`4624`** | **Successful Logon** | Check **Logon Type** (`2` = Interactive/Keyboard, `3` = Network/SMB, `7` = Unlock, `10` = RDP/RemoteInteractive) and `Source Network Address` |
| **`4625`** | **Failed Logon** | High volume indicates brute-force or password spraying |
| **`4672`** | **Special Privileges Assigned to New Logon** | Indicates an Administrator-level logon (`SeDebugPrivilege`, `SeBackupPrivilege`) |
| **`4688`** | **A New Process Has Been Created** | Native process creation log (enable *"Include command line in process creation events"* via GPO!) |
| **`4697` / `7045`** | **A Service Was Installed in the System** | `4697` (`Security.evtx`) & `7045` (`System.evtx`) — critical for catching `PsExec` and persistence services! |
| **`4698`** | **A Scheduled Task Was Created** | Catching scheduled task persistence (`schtasks /create`) |
| **`4720`** | **A User Account Was Created** | Catching backdoor local/domain user creation (`net user hacker Pass123 /add`) |
| **`4732` / `4728`** | **A Member Was Added to a Security-Enabled Group** | Catching privilege escalation (`net localgroup administrators hacker /add`) |
| **`1102`** | **The Audit Log Was Cleared** | High-severity alert! Attacker ran `wevtutil cl Security` or `Clear-EventLog` to cover tracks |

### Essential Sysmon Event IDs (`Microsoft-Windows-Sysmon/Operational`)
**Sysmon** (part of Microsoft Sysinternals) provides EDR-grade visibility by logging process hashes, parent processes, network sockets, and registry tampering:

| Sysmon ID | Event Name | What It Captures |
| :--- | :--- | :--- |
| **`Event ID 1`** | **Process Creation** | Full `CommandLine`, `ParentImage`, `ParentCommandLine`, `Hashes` (`SHA256`, `IMPHASH`), `User`, and `CurrentDirectory` |
| **`Event ID 3`** | **Network Connection** | Maps outbound/inbound TCP/UDP connections (`DestinationIp`, `DestinationPort`) directly to the exact `Image` (process) and `User` |
| **`Event ID 7`** | **Image Loaded (DLL)** | Logs when a DLL is loaded by a process (detects **DLL Search Order Hijacking** / **DLL Sideloading**) |
| **`Event ID 8`** | **CreateRemoteThread** | Detects **Process Injection** (one process injecting shellcode/threads into another process like `explorer.exe`) |
| **`Event ID 10`** | **ProcessAccess** | Detects **LSASS Credential Dumping** (`Mimikatz` opening `C:\Windows\System32\lsass.exe` memory) |
| **`Event ID 11`** | **FileCreate** | Logs newly created/downloaded files on disk (especially in `Downloads`, `Temp`, `AppData`, `Startup`) |
| **`Event ID 12 / 13 / 14`** | **Registry Event** | Registry object Create/Delete (`12`), Value Set (`13` — `Run` keys!), and Key Rename (`14`) |
| **`Event ID 15`** | **FileCreateStreamHash** | Captures NTFS **Alternate Data Streams (ADS)** and **Mark-of-the-Web (`Zone.Identifier`)** origin URLs! |
| **`Event ID 22`** | **DNSEvent (DNS Query)** | Logs every domain name (`QueryName`) resolved by a specific process (`Image`) |

### PowerShell Logging (`Microsoft-Windows-PowerShell/Operational`)
- **`Event ID 4103` (Module Logging):** Logs pipeline execution details and loaded modules.
- **`Event ID 4104` (Script Block Logging):** Automatically captures the **full, de-obfuscated source code** of executed PowerShell script blocks, even if the attacker launched them with `powershell.exe -EncodedCommand`!

---

## Chapter 2: Windows Threat Detection 1 (Initial Access)

### Detecting Common Windows Initial Access Vectors
1. **RDP & SMB Brute-Forcing:**
   - Hundreds of `Event ID 4625` (Logon Type `3` or `10`) followed by a single `Event ID 4624` from the same external IP.
2. **Phishing Attachments & Malicious LNK / ISO Files:**
   - **Double Extensions:** `Invoice_2026.pdf.exe` or `Report.docx.scr`.
   - **Malicious `.LNK` (Shortcut) Files:** Clicking a `.lnk` file spawns `cmd.exe` or `powershell.exe` with `explorer.exe` as the parent, while passing silent download flags (`curl`, `mshta`, `Invoke-WebRequest`).
   - **Macro-Enabled Office Documents:** `WINWORD.EXE` or `EXCEL.EXE` spawning `cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, or `rundll32.exe` (`Sysmon Event ID 1`).
   - **Check `Sysmon Event ID 15` (`Zone.Identifier`):** Files downloaded from the internet receive a `ZoneId=3` stream containing `HostUrl=` and `ReferrerUrl=`, proving where the payload was downloaded from!
3. **Removable Media (USB) Execution:**
   - Process creation (`Sysmon ID 1`) executing from drive letters `D:\`, `E:\`, or `F:\`.

---

## Chapter 3: Windows Threat Detection 2 (Discovery, Credential Theft & Exfiltration)

### 1. Post-Compromise Discovery Commands (`T1082` / `T1087` / `T1016`)
When an attacker lands on a Windows box, they immediately run a burst of reconnaissance utilities within seconds of each other (`Sysmon Event ID 1`):
```cmd
whoami /all
systeminfo
ipconfig /all
net user /domain
net group "Domain Admins" /domain
nltest /dclist:thm.local
arp -a
netstat -ano
tasklist /svc
cmdkey /list
```

### 2. Credential Access (`T1003` — OS Credential Dumping)
- **LSASS Memory Dumping:**
  - *Mimikatz:* `sekurlsa::logonpasswords` (`Sysmon Event ID 10`: TargetImage `C:\Windows\System32\lsass.exe` with `GrantedAccess: 0x1010` or `0x1fffff`).
  - *Task Manager / ProcDump / `comsvcs.dll` LOLBin:*
    ```cmd
    rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Temp\lsass.dmp full
    ```
- **SAM & SYSTEM Registry Hive Dumping:**
  ```cmd
  reg save HKLM\SAM C:\Temp\sam.hiv
  reg save HKLM\SYSTEM C:\Temp\sys.hiv
  ```
- **Browser Credential & Cookie Theft:**
  - Processes accessing Chrome (`...\AppData\Local\Google\Chrome\User Data\Default\Login Data`) or Edge SQLite credential databases.

### 3. Data Staging & Exfiltration
- Compressing sensitive folders into password-protected archives in `C:\Temp` or `C:\Users\Public` using `7z.exe a -pSecret`, `rar.exe`, or PowerShell `Compress-Archive`, followed by `curl`/`rclone`/PowerShell `Invoke-RestMethod` (`Sysmon ID 1`, `3`, `22`).

---

## Chapter 4: Windows Threat Detection 3 (Persistence & C2)

### High-Priority Windows Persistence Mechanisms
| Persistence Technique | Key Telemetry / Artifacts to Inspect |
| :--- | :--- |
| **Registry Run / RunOnce Keys (`T1547.001`)** | `Sysmon Event ID 13` modifying:<br>`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`<br>`HKLM\Software\Microsoft\Windows\CurrentVersion\Run` |
| **Startup Folder (`T1547.001`)** | `Sysmon Event ID 11` dropping files/shortcuts into:<br>`C:\Users\<User>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` |
| **Scheduled Tasks (`T1053.005`)** | `Security Event ID 4698` or `Sysmon ID 1` executing `schtasks.exe /create /tn ... /tr ... /sc onlogon` |
| **Windows Services (`T1543.003`)** | `System Event ID 7045` / `Security 4697` or `sc.exe create` installing a service pointing to `C:\Users\Public\...` or `cmd.exe /c ...` |
| **Backdoor Local/Domain Account (`T1136`)** | `Security Event ID 4720` (User Created) + `4732` (Added to `Administrators` or `Remote Desktop Users`) |
| **WMI Event Subscription (`T1546.003`)** | `Sysmon Event IDs 19, 20, 21` (`WmiEventFilter`, `WmiEventConsumer`, `WmiEventConsumerToFilter`) |

# Module 12: Defensive Security Tooling

> **Overview:** When investigating suspicious files, obfuscated scripts, or malware samples, Blue Teamers and DFIR analysts use specialized analysis toolkits. This module covers **CyberChef**, **CAPA**, **REMnux**, and **FlareVM**.

---

## Chapter 1: CyberChef: The Basics

### What is CyberChef?
- **CyberChef ("The Cyber Swiss Army Knife"):** A web-based, client-side data transformation application developed by **GCHQ** (UK intelligence agency). It allows analysts to chain together operations ("Recipes") to decode, decompress, decrypt, and parse malicious payloads safely in the browser.

### Layout of the CyberChef Interface
1. **Operations (Left Pane):** Searchable catalog of 300+ operations (`Base64`, `XOR`, `AES`, `Regular expression`, `Extract IP addresses`).
2. **Recipe (Middle Pane):** Drag-and-drop pipeline where operations execute sequentially from top to bottom (**Bake!**).
3. **Input (Top-Right Pane):** Paste obfuscated text, hex strings, or upload raw files.
4. **Output (Bottom-Right Pane):** Displays the transformed result (includes the **Magic Wand** icon when CyberChef automatically detects an encoding layer).

### Essential CyberChef Operations
| Category | Key Operations | Typical Use Case |
| :--- | :--- | :--- |
| **Extractors** | `Extract IP addresses`, `Extract URLs`, `Extract email addresses`, `Strings` | Quickly pull Indicators of Compromise (IoCs) from raw logs or malware dumps |
| **Date / Time** | `From UNIX Timestamp`, `To UNIX Timestamp` | Convert epoch timestamps (`1729950000`) into human-readable UTC dates |
| **Data Format** | `From Base64`, `From Hex`, `From Charcode`, `URL Decode`, `From Binary` | De-obfuscate multi-layered PowerShell/JavaScript malware loaders |
| **Encryption / Encoding** | `XOR`, `XOR Brute Force`, `ROT13`, `AES Decrypt`, `RC4` | Decrypt payloads obfuscated with single-byte XOR keys or hardcoded AES keys |
| **Networking** | `Defang URL`, `Defang IP Addresses` | Convert clickable malicious URLs (`http://evil.com`) into safe text (`hxxp[://]evil[.]com`) for incident reports |
| **Magic** | `Magic` (with *Intensive mode*) | Automatically detects and unpacks nested encodings |

---

## Chapter 2: CAPA: The Basics

### What is CAPA?
- **CAPA (`capa`):** An open-source command-line tool created by **Mandiant (FLARE Team)** that analyzes executable binaries (`PE`, `ELF`, `.NET`, shellcode) to automatically identify **capabilities**—what a program *can* do—without executing it (Static Analysis).
- **Framework Mapping:** Maps discovered binary capabilities directly to:
  - **MITRE ATT&CK®** Tactics and Techniques (e.g., `T1055 Process Injection`, `T1547.001 Registry Run Keys`).
  - **MBC (Malware Behavior Catalog)** Objectives and Behaviors (e.g., `Anti-Analysis`, `Cryptography::Encrypt Data::RC4`).

### Essential CAPA Commands & Flags
```bash
# 1. Standard summary analysis of a suspicious executable
capa suspicious.exe

# 2. Verbose mode (-v): Shows the exact memory offsets and API calls that triggered each rule
capa -v suspicious.exe

# 3. Very Verbose mode (-vv): Shows detailed YAML rule logic, assembly addresses, and imports
capa -vv suspicious.exe

# 4. Output in JSON format for automated parsing or GUI inspection in CAPA Web Explorer
capa -j suspicious.exe > capa_result.json
```

### Reading CAPA Output Table
1. **File Metadata Header:** Displays `md5`, `sha1`, `sha256`, OS, Architecture (`i386` / `amd64`), and Format (`pe`).
2. **ATT&CK Tactic & Technique Table:** Lists high-level adversary tactics (`DEFENSE EVASION`, `DISCOVERY`, `EXECUTION`) and specific techniques (`Obfuscated Files or Information [T1027]`).
3. **Malware Behavior Catalog (MBC) Table:** Highlights malware-specific behaviors (`Anti-Behavioral Analysis::Virtual Machine Detection`).
4. **Capability Table:** Lists concrete capabilities matched against CAPA's open-source YAML ruleset alongside the number of matches (`create service (2 matches)`, `encode data using XOR`).

---

## Chapter 3: REMnux: Getting Started

### What is REMnux?
- **REMnux:** A free, specialized Ubuntu-based **Linux distribution** created by Lenny Zeltser for reverse-engineering and analyzing malicious software, malicious documents (`PDF`, `Office macros`), and memory dumps in an isolated sandbox.

### Analyzing Malicious Office Documents (Maldocs)
Attackers frequently weaponize Microsoft Word/Excel files using **VBA Macros** to download and execute second-stage payloads.
- **`oledump.py`:** Inspects OLE2 compound files (`.doc`, `.xls`, `.ppt`) and identifies streams containing VBA macros (marked with `M` or `m`):
  ```bash
  oledump.py invoice.doc                 # List all data streams in the document
  oledump.py -s 8 -v invoice.doc         # Decompress and dump VBA macro code from stream 8 (-s 8 -v)
  oledump.py -s 8 -S invoice.doc         # Extract strings from stream 8
  ```
- **`olevba` (`oletools`):** Automatically extractsVBA macros, de-obfuscates strings (`Chr()`, `Hex`), and highlights suspicious keywords (`AutoOpen`, `Document_Open`, `Shell`, `WScript.Shell`, `URLDownloadToFile`):
  ```bash
  olevba invoice.doc
  ```

### Analyzing Malicious PDFs
- **`pdfid.py`:** Scans a PDF file for suspicious PDF tags/objects (`/JS`, `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFiles`):
  ```bash
  pdfid.py urgent.pdf
  ```
- **`pdf-parser.py`:** Extracts and inspects the contents of specific PDF objects identified by `pdfid`:
  ```bash
  pdf-parser.py --search javascript urgent.pdf
  pdf-parser.py --object 12 --filter --raw urgent.pdf
  ```

### Simulating Network Services (`INetSim` & `FakeDNS`)
During **Dynamic Analysis**, malware often tries to reach its Command & Control (C2) server over HTTP/HTTPS/DNS.
- **`inetsim`:** Simulates common internet services (`HTTP`, `HTTPS`, `DNS`, `FTP`, `SMTP`) inside an isolated lab network so the malware thinks it has internet access, allowing you to capture its network requests in Wireshark.

---

## Chapter 4: FlareVM: Arsenal of Tools

### What is FlareVM?
- **FLARE VM:** A **Windows-based** security distribution developed by Mandiant's FLARE (FireEye Labs Advanced Reverse Engineering) team. Built via PowerShell/Chocolatey installer scripts on top of a Windows VM, it provides a complete arsenal for Windows malware analysis, reverse engineering, and incident response.

### Core Tool Categories in FlareVM

#### 1. Static Analysis & PE Inspection
- **PEStudio:** Inspects Windows Portable Executable (`PE` — `.exe`, `.dll`, `.sys`) headers, imports (IAT), exports, entropy (high entropy > `7.0` indicates packing/encryption), strings, and VirusTotal indicators.
- **CFF Explorer:** View and edit internal PE header structures (`DOS Header` `MZ`, `NT Headers`, `Section Headers` like `.text`, `.rdata`, `.data`, `.rsrc`).
- **DIE (Detect It Easy) / PEiD:** Identifies the compiler, linker, or **Packer** (e.g., `UPX`) used to build or compress the executable.
- **FLOSS (FLARE Obfuscated String Solver):** Automatically extracts static strings as well as obfuscated/stack/decoded strings from malware binaries.

#### 2. Disassemblers, Decompilers & Debuggers
- **Ghidra / IDA Free / Binary Ninja:** Disassemble machine code into assembly and decompile it into pseudo-C code for deep reverse engineering.
- **dnSpy / ILSpy:** Decompile and debug **.NET (`C#`)** assemblies directly back into readable source code.
- **x64dbg / x32dbg:** Dynamic user-mode Windows debuggers used to step through malware execution instruction-by-instruction, set breakpoints, and dump unpacked payloads from memory.

#### 3. Dynamic Behavioral & System Monitoring (Sysinternals)
- **Process Monitor (`Procmon.exe`):** Captures real-time file system activity, Registry modifications, Process/Thread creation, and Network events (filter by `Process Name is malware.exe`).
- **Process Explorer (`Procexp.exe`):** Supercharged Task Manager showing parent-child process trees (e.g., `winword.exe -> powershell.exe`), loaded DLLs, and memory strings.
- **Autoruns (`Autoruns.exe`):** Comprehensive viewer of every persistence location in Windows (Startup folders, `HKLM\...\Run` Registry keys, Scheduled Tasks, Services, WMI).
- **Process Hacker / System Informer:** Inspects process memory, handles, tokens, and network sockets.

# Module 04: Command Line

> **Overview:** Proficiency in the command line across both Windows (`cmd.exe` and `PowerShell`) and Linux (`bash`/`zsh`) is vital for system administration, incident response, and penetration testing.

---

## Chapter 1: Windows Command Line (`cmd.exe`)

### System & Network Inspection
| Command | Description | Example |
| :--- | :--- | :--- |
| `set` | Display environment variables | `set` |
| `ver` | Display OS version | `ver` |
| `systeminfo` | Comprehensive OS, patch (hotfix), and hardware info | `systeminfo` |
| `ipconfig` | View network adapter IP configurations | `ipconfig /all` |
| `ping` | Test ICMP reachability to a host | `ping 10.10.10.10` |
| `tracert` | Trace the network route (hops) to a destination | `tracert tryhackme.com` |
| `nslookup` | Query DNS servers for domain/IP records | `nslookup tryhackme.com` |
| `netstat` | Display active TCP/UDP connections and listening ports | `netstat -ano` |

> **Tip:** `netstat -ano` is essential for incident triage: `-a` shows all connections/listening ports, `-n` displays numerical IPs/ports, and `-o` reveals the owning Process ID (PID).

### File & Directory Management
| Command | Action | Linux Equivalent |
| :--- | :--- | :--- |
| `cd` | Display current directory or change directory | `pwd` / `cd` |
| `dir` | List contents of a directory (`dir /a` shows hidden files) | `ls -la` |
| `tree` | Visually display folder structure | `tree` |
| `mkdir` / `rmdir` | Create or remove a directory (`rmdir /s` for non-empty) | `mkdir` / `rm -r` |
| `type` | Display the contents of a text file | `cat` |
| `more` | Paginate long output one screen at a time | `more` / `less` |
| `copy` / `move` | Copy or move files | `cp` / `mv` |
| `del` / `erase` | Delete one or more files | `rm` |
| `findstr` | Search for strings in files or piped output | `grep` |

### Process & Task Management
- `tasklist`: Lists all currently running processes and their PIDs (`tasklist /FI "IMAGENAME eq sshd.exe"`).
- `taskkill`: Terminates a process by PID (`/PID`) or image name (`/IM`):
  ```cmd
  taskkill /F /PID 4532
  ```
- `sfc /scannow`: System File Checker — scans and restores corrupted Windows system files.
- `chkdsk`: Checks the file system and disk volume for errors.

---

## Chapter 2: Windows PowerShell

### Core Concepts
- **Object-Oriented Pipeline:** Unlike `cmd.exe` or `bash` which pass plain text between commands, PowerShell passes structured **.NET Objects** with properties and methods through the pipeline (`|`).
- **Cmdlet Naming Convention (`Verb-Noun`):** Every command follows a predictable pattern like `Get-Process`, `Stop-Service`, `New-Item`, `Invoke-WebRequest`.

### Essential Cmdlets & Exploration
| Cmdlet | Purpose | Example |
| :--- | :--- | :--- |
| `Get-Help` | Read documentation and examples for any cmdlet | `Get-Help Get-ChildItem -Examples` |
| `Get-Command` | Search all available cmdlets by verb or noun | `Get-Command -Verb Get` |
| `Get-Member` | Inspect the object properties and methods in a pipeline | `Get-Process \| Get-Member` |
| `Get-ChildItem` | List files, directories, or registry keys (alias: `ls`, `dir`) | `Get-ChildItem -Path C:\ -Hidden -Recurse` |
| `Get-Content` | Read file contents (alias: `cat`, `type`) | `Get-Content C:\flag.txt` |
| `Set-Location` | Change working directory (alias: `cd`) | `Set-Location C:\Users` |
| `New-Item` | Create files or folders | `New-Item -Path .\note.txt -ItemType File` |

### Filtering, Sorting, and Searching Objects
- **`Select-Object`:** Choose specific properties from an object:
  ```powershell
  Get-Process | Select-Object Name, Id, CPU
  ```
- **`Where-Object`:** Filter objects based on property values (`$_` represents the current pipeline object):
  ```powershell
  Get-Service | Where-Object { $_.Status -eq "Running" }
  ```
  *Comparison Operators:* `-eq` (equal), `-ne` (not equal), `-gt` (greater than), `-lt` (less than), `-like` (wildcard match).
- **`Sort-Object`:** Sort output by a specific property:
  ```powershell
  Get-ChildItem | Sort-Object Length -Descending
  ```
- **`Measure-Object`:** Count lines, words, characters, or sum numerical properties (`Get-Content file.txt | Measure-Object -Line -Word`).
- **`Select-String`:** PowerShell's `grep` for searching regex/text patterns in files:
  ```powershell
  Select-String -Path C:\Users\*\*.txt -Pattern "password"
  ```

### System & Security Enumeration via PowerShell
```powershell
Get-ComputerInfo                       # Full OS and hardware details
Get-LocalUser                          # List local user accounts
Get-LocalGroupMember -Group "Administrators"  # List local admins
Get-NetIPAddress                       # View IP addresses
Get-NetTCPConnection -State Listen     # View listening TCP ports
Get-MpComputerStatus                   # Check Windows Defender status
```

---

## Chapter 3: Linux Shells

### Types of Linux Shells
- **`sh` (Bourne Shell):** Original Unix shell.
- **`bash` (Bourne Again Shell):** Default shell on most Linux distributions (`~/.bashrc`, `~/.bash_history`).
- **`zsh` (Z Shell):** Default on Kali Linux and macOS; supports advanced auto-completion, themes (`Oh My Zsh`), and spelling correction.
- **`fish` (Friendly Interactive Shell):** Focuses on out-of-the-box syntax highlighting and auto-suggestions.
- Check available shells on a system: `cat /etc/shells`
- Check current shell: `echo $SHELL`
- Change default shell: `chsh -s /bin/zsh`

### Shell Scripting Fundamentals
A shell script automates sequences of commands.

```bash
#!/bin/bash
# The shebang (#!) tells the OS which interpreter to use

name="CyberSec101"
echo "Welcome to $name!"

# Reading user input
read -p "Enter target IP: " target_ip

# Conditional Statement
if [ "$target_ip" = "127.0.0.1" ]; then
    echo "Scanning localhost is not allowed!"
else
    echo "Pinging $target_ip..."
    ping -c 1 "$target_ip"
fi

# For Loop (iterating over ports or items)
for port in 22 80 443; do
    echo "Checking port $port on $target_ip"
done
```

### Script Execution & Permissions
1. Grant execute permission: `chmod +x scanner.sh`
2. Run the script: `./scanner.sh` (or `bash scanner.sh`)

### Investigating `.bash_history` & Environment Variables
- During post-exploitation or forensics, always check `~/.bash_history`—administrators frequently leave plaintext passwords or sensitive file paths in previously typed commands!
- `env` or `printenv`: Lists environment variables (e.g., `$PATH`, `$USER`, `$HOME`).

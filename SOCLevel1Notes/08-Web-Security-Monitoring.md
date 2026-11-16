# Module 08: Web Security Monitoring

> **Overview:** Public-facing web servers are constantly probed by automated scanners and attackers. This module teaches SOC analysts how to inspect HTTP access/error logs and network telemetry to detect web reconnaissance, SQLi, XSS, LFI, Web Shells, and DDoS attacks.

---

## Chapter 1: Web Security Essentials

### Key Log Sources for Web Monitoring
1. **Web Server Access Logs:**
   - **Apache / Nginx:** `/var/log/apache2/access.log`, `/var/log/nginx/access.log`
   - **Microsoft IIS:** `C:\inetpub\logs\LogFiles\W3SVC1\u_exYYMMDD.log`
   - *Fields Recorded:* Client IP (`c-ip`), Timestamp, HTTP Method (`cs-method`), URI Stem & Query (`cs-uri-stem`, `cs-uri-query`), HTTP Status Code (`sc-status`), Bytes Sent (`sc-bytes`), Referer, and User-Agent (`cs(User-Agent)`).
2. **Web Server Error Logs (`error.log`):**
   - Captures backend PHP/Python stack traces, missing files, permission errors, and failed command executions.
3. **WAF (Web Application Firewall) & Reverse Proxy Logs:**
   - Captures full **HTTP POST request bodies** (which standard Apache/Nginx access logs do *not* record by default!).

---

## Chapter 2: Detecting Web Attacks

### Identifying Automated Reconnaissance & Fuzzing
- **Indicators in Access Logs:**
  1. **High Request Rate:** Hundreds of requests per minute from a single IP resulting in a massive spike of **`404 Not Found`** or **`403 Forbidden`** status codes (Directory brute-forcing with `Gobuster`, `Dirb`, `ffuf`).
  2. **Scanner User-Agents:** `Gobuster`, `Nikto`, `sqlmap`, `Nuclei`, `Feroxbuster`, `wpscan`, `python-requests`, `curl`.

### Signatures of Common Web Vulnerabilities in Logs
| Attack Type | Suspicious Patterns in URI Query / POST Body / Headers |
| :--- | :--- |
| **SQL Injection (SQLi)** | `'`, `%27`, `OR 1=1`, `UNION SELECT`, `information_schema`, `SLEEP(5)`, `WAITFOR DELAY`, `--`, `/**/` |
| **Cross-Site Scripting (XSS)** | `<script>`, `%3Cscript%3E`, `javascript:`, `onerror=`, `onload=`, `alert(`, `document.cookie` |
| **Path Traversal / LFI** | `../`, `..%2f`, `%2e%2e/`, `/etc/passwd`, `/etc/shadow`, `C:\Windows\win.ini`, `php://filter/convert.base64-encode` |
| **OS Command Injection** | `;`, `\|`, `&&`, `` ` ``, `$(...)`, `whoami`, `id`, `cat /etc/passwd`, `nc -e`, `powershell`, `wget`, `curl` |
| **IDOR / Brute Force** | Rapid sequential requests iterating through numeric IDs (`/profile?id=101`, `102`, `103`) or rapid `POST /login` attempts returning `401`/`200` |

> **Differentiating Attempt vs. Successful Exploitation:**
> - **Failed Attempt:** All SQLi/LFI requests return `400`/`403`/`404`/`500` with identical small response sizes (`sc-bytes`).
> - **Successful Exploitation:** Amidst dozens of failed probes, one request returns **`200 OK`** with a significantly **larger response size (`sc-bytes`)** (e.g., dumping a database table or `/etc/passwd`), or triggers a suspicious child process on the web server!

---

## Chapter 3: Detecting Web Shells

### What is a Web Shell?
After exploiting an **Unrestricted File Upload**, **RFI/LFI**, or **RCE** flaw, attackers drop a persistent script (`shell.php`, `cmd.aspx`, `b374k.php`, `weevely.php`) inside a web-accessible directory (`/var/www/html/uploads/` or `C:\inetpub\wwwroot\images\`) to execute OS commands over HTTP/HTTPS.

### Three-Layer Detection Strategy for Web Shells
1. **Network / Web Access Logs:**
   - Look for `POST` request to an upload script (`POST /upload.php` $\rightarrow$ `200 OK`) immediately followed by `GET` or `POST` requests to a newly created `.php`/`.aspx`/`.jsp` file inside a static media/upload folder:
     ```text
     GET /uploads/avatar.php?cmd=whoami HTTP/1.1 200
     ```
   - Unusual URI access patterns: A single external IP repeatedly hitting the exact same uncommon file with no `Referer` header.
2. **Host Process Telemetry (EDR / Sysmon / `auditd`) — *The Gold Standard!***
   - The web server service account (`www-data`, `apache`, `nginx`, or Windows `IIS APPPOOL\DefaultAppPool` / `w3wp.exe`) should **never** spawn a command shell or reconnaissance utility!
   - **Suspicious Parent-Child Process Tree:**
     ```text
     w3wp.exe / apache2 / php-fpm
       └── cmd.exe / /bin/sh / /bin/bash
             ├── whoami
             ├── ipconfig / ip a
             ├── net user / cat /etc/passwd
             └── powershell.exe / curl / nc
     ```
3. **File System & Static Inspection:**
   - Newly created or modified `.php`/`.aspx` files in static asset directories.
   - Grep web directories for dangerous functions combined with encoding:
     ```bash
     grep -rnE "(eval|system|passthru|shell_exec|exec|popen|base64_decode)\s*\(" /var/www/html/
     ```

---

## Chapter 4: Detecting Web DDoS

### DoS vs. DDoS & Attack Layers
- **DoS (Denial of Service):** Single source overwhelming a target's availability.
- **DDoS (Distributed Denial of Service):** Thousands of compromised bots (a **Botnet**) simultaneously flooding the target.
- **Categories of DDoS Attacks:**
  1. **Volumetric Attacks (Layer 3/4):** Consuming all network bandwidth (`UDP Flood`, `ICMP Flood`, `DNS/NTP Amplification`).
  2. **Protocol / State-Exhaustion Attacks (Layer 4):** Exhausting firewall state tables or server TCP queues (`TCP SYN Flood` — sending thousands of `SYN` packets without ever completing the `ACK`).
  3. **Application Layer Attacks (Layer 7 — HTTP Floods):** Sending seemingly legitimate HTTP `GET`/`POST` requests targeting resource-heavy pages (e.g., `/search?q=...` or `/login`) or holding sockets open (`Slowloris`).

### SOC Mitigation Strategies
- Rate limiting per IP/Session, deploying a CDN / Anti-DDoS Reverse Proxy (**Cloudflare**, **AWS Shield**, **Akamai**), enabling **SYN Cookies**, Geo-IP blocking, and tuning WAF challenge rules.

---

## Chapter 5: Upload and Conquer (Practical Challenge Takeaways)

### Reconstructing a Web Server Breach Timeline
1. **Identify Initial Enumeration:** Look for `Gobuster`/`Dirb` bursts of `404` responses discovering `/upload` or `/admin`.
2. **Identify the Upload Request:** Locate the `POST` request (check `Content-Type: multipart/form-data`) where the attacker bypassed file extension filters (e.g., uploading `shell.phtml`, `shell.php5`, or spoofing magic bytes `GIF89a; <?php system($_GET['c']); ?>`).
3. **Trace Post-Exploitation Commands:** Pivot to host logs (`Sysmon Event ID 1` or `auditd`) or URL query strings (`?cmd=...`) to see what commands the attacker ran, whether they established a reverse shell, and which sensitive files were exfiltrated.

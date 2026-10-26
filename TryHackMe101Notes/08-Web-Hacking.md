# Module 08: Web Hacking

> **Overview:** Web applications represent the largest external attack surface of modern organizations. This module covers how web applications function under the hood, client-side JavaScript, database queries (`SQL`), and intercepting/manipulating web traffic with **Burp Suite**.

---

## Chapter 1: Web Application Basics

### Anatomy of a URL (Uniform Resource Locator)
```text
https://admin:pass@store.tryhackme.com:8443/products/view.php?id=12&sort=asc#reviews
\___/   \________/ \_________________/ \__/ \_______________/ \____________/ \_____/
Scheme     User          Host          Port       Path         Query String  Fragment
```
- **Scheme:** Protocol used (`http://`, `https://`).
- **User/Pass:** Optional HTTP authentication credentials.
- **Host (Domain):** Resolved via DNS to the web server's IP.
- **Port:** Default `80` (HTTP) or `443` (HTTPS).
- **Path:** File or route on the web server.
- **Query String:** Key-value parameters (`?key=value&key2=value2`) sent to the backend application.
- **Fragment (`#`):** Client-side anchor handled entirely by the browser (never sent to the server!).

### HTTP Requests & Responses
**Example HTTP Request:**
```http
POST /login.php HTTP/1.1
Host: tryhackme.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64)
Cookie: PHPSESSID=u89s7df98s7df98s7df
Content-Type: application/x-www-form-urlencoded
Content-Length: 29

username=admin&password=123
```

**Example HTTP Response & Security Headers:**
```http
HTTP/1.1 200 OK
Server: Apache/2.4.52 (Ubuntu)
Set-Cookie: session=xyz; HttpOnly; Secure; SameSite=Strict
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000
X-Frame-Options: DENY
Content-Type: text/html; charset=UTF-8
```
- **Important Security Headers:**
  - `Content-Security-Policy (CSP)`: Restricts where scripts/resources can be loaded from (mitigates XSS).
  - `Strict-Transport-Security (HSTS)`: Forces browsers to only communicate via HTTPS.
  - `X-Frame-Options` (`DENY` / `SAMEORIGIN`): Prevents Clickjacking attacks by blocking `<iframe>` embedding.
  - `HttpOnly` Cookie Flag: Prevents client-side JavaScript (`document.cookie`) from accessing session cookies.

---

## Chapter 2: JavaScript Essentials

### Core Concepts for Web Pentesting
- **JavaScript (JS):** Runs directly in the user's browser (client-side) to manipulate the **DOM (Document Object Model)**, validate forms, and make asynchronous requests (`fetch()` / `XMLHttpRequest`).
- **Rule #1 of Web Security:** **Never trust client-side validation!** Because JS executes in the user's browser, an attacker can inspect, modify, or completely bypass client-side checks using Browser Developer Tools (`F12`) or an intercepting proxy like Burp Suite.

### Common Security Issues in Client-Side JS
1. **Hardcoded Secrets / Credentials:** Developers accidentally leave API keys, admin URLs, or passwords inside `.js` files or `<script>` tags.
2. **Obfuscation vs. Minification:**
   - *Minification:* Removes whitespace and shortens variable names to reduce file size (`app.min.js`).
   - *Obfuscation:* Scrambles JS logic (using hex/base64 arrays or tools like `jsfuck` / `obfuscator.io`) to make reverse-engineering harder—still completely reversible in the browser console!
3. **DOM Manipulation & XSS Sinks:**
   - Unsafe JS properties like `element.innerHTML = userInput`, `document.write()`, or `eval()` allow attackers to execute arbitrary JavaScript (**Cross-Site Scripting — XSS**).

### Browser Console Quick Tricks
```javascript
document.cookie                          // Read accessible (non-HttpOnly) cookies
atob("VEhNe2Jhc2U2NF9kZWNvZGVkfQ==")     // Base64 decode string in browser console
btoa("plaintext")                        // Base64 encode string in browser console
```

---

## Chapter 3: SQL Fundamentals

### Core Concepts
- **DBMS (Database Management System):** Software managing databases.
  - **Relational (SQL):** Organizes data into structured **Tables** with **Columns** (fields) and **Rows** (records) — e.g., `MySQL`, `MariaDB`, `PostgreSQL`, `Microsoft SQL Server (MSSQL)`, `SQLite`, `Oracle`.
  - **Non-Relational (NoSQL):** Document/key-value stores — e.g., `MongoDB`, `Redis`.

### Essential SQL Commands Cheat Sheet
```sql
-- Database & Table Inspection
SHOW DATABASES;
USE online_shop;
SHOW TABLES;
DESCRIBE users;

-- CRUD Operations (Create, Read, Update, Delete)
INSERT INTO users (username, password, role) VALUES ('alice', 'secret123', 'user');
SELECT id, username, role FROM users WHERE role = 'admin';
UPDATE users SET role = 'admin' WHERE username = 'alice';
DELETE FROM users WHERE id = 5;
```

### SQL Clauses, Operators & Functions
- **`WHERE` Operators:** `=`, `!=`, `<`, `>`, `AND`, `OR`, `NOT`, `BETWEEN`.
- **`LIKE` Wildcards:** `SELECT * FROM books WHERE title LIKE '%hack%';` (`%` matches any sequence of characters; `_` matches a single character).
- **`UNION` Operator:** Combines the result set of two or more `SELECT` statements into a single output (both queries must have the exact same number of columns!).
  ```sql
  SELECT name, price FROM products UNION SELECT username, password FROM users;
  ```
- **SQL Comments** (critical for truncating queries during SQL Injection):
  - `-- ` (Dash-dash-space: MySQL, PostgreSQL, MSSQL, SQLite)
  - `#` (MySQL)
  - `/* comment */` (Inline multi-line comment)

---

## Chapter 4: Burp Suite: The Basics

### What is Burp Suite?
- **Burp Suite** (by PortSwigger) is the de facto framework for web application penetration testing. At its core is an **Intercepting Proxy** that sits between your browser and the target web server, allowing you to inspect, pause, and tamper with every HTTP/HTTPS request and response.

### Core Burp Suite Modules
| Module | Primary Use Case |
| :--- | :--- |
| **Proxy** | Intercept, view (`HTTP history`), and modify live browser HTTP/HTTPS requests on the fly |
| **Target (`Site map` & `Scope`)** | Automatically maps out all visited endpoints/directories and restricts testing to in-scope domains |
| **Repeater (`Ctrl+R`)** | Manually modify and resend a single HTTP request repeatedly while inspecting the raw/rendered response |
| **Intruder (`Ctrl+I`)** | Automated fuzzing and brute-forcing tool (credential stuffing, parameter fuzzing, IDOR enumeration) |
| **Decoder** | Built-in utility to encode/decode strings (`URL`, `Base64`, `Hex`, `HTML`, `ASCII`) and compute hashes |
| **Comparer** | Visual diff tool to compare two HTTP responses byte-by-byte or word-by-word |

### HTTPS Interception Setup
- Because HTTPS traffic is encrypted with TLS, Burp generates its own **PortSwigger CA Certificate** (`http://burp/cert`) which must be imported into your browser's Trusted Root Certification Authorities to intercept HTTPS without TLS warnings.

### Practical Bypass Example: Client-Side Filter Evasion
In the room's practical lab, a ticket price form validated on the client side that the price could not be negative or modified:
1. Turned **Intercept is on** in `Burp Proxy`.
2. Submitted the form in the browser.
3. Captured the outgoing `POST` request in Burp before it reached the server.
4. Modified `price=100.00` to `price=0.01` (or injected an XSS payload bypassing HTML `<input>` restrictions) and clicked **Forward** (or sent to **Repeater** via `Ctrl+R`).

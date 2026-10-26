# Module 13: Build Your Cyber Security Career

> **Overview:** Cybersecurity is a vast industry spanning offensive, defensive, engineering, and governance roles. This module maps out key career tracks, foundational security principles/models, and the day-to-day responsibilities of a Security Engineer.

---

## Chapter 1: Careers in Cyber

### Overview of Major Cybersecurity Roles
| Role | Team / Focus | Core Responsibilities |
| :--- | :--- | :--- |
| **Security Analyst (SOC Analyst)** | Blue Team (Defensive) | Monitors SIEM/EDR alerts, triages security events, investigates suspicious network/host activity, and escalates incidents |
| **Security Engineer** | Blue / Purple (Architecture) | Designs, builds, and maintains security controls (firewalls, SIEMs, IAM, cloud security, vulnerability management) |
| **Incident Responder (DFIR)** | Blue Team (Response) | Leads active breach investigations, performs memory/disk forensics, contains threats, and eradicates attacker persistence |
| **Malware Analyst / Reverse Engineer** | Blue / Threat Intel | Dissects malicious binaries using static and dynamic analysis (`Ghidra`, `x64dbg`, `CAPA`) to extract IoCs and understand TTPs |
| **Penetration Tester (Ethical Hacker)** | Red Team (Offensive) | Conducts authorized security assessments against web apps, networks, and cloud environments to find exploitable flaws |
| **Red Teamer** | Red Team (Adversary Emulation) | Simulates full-scope real-world adversaries (social engineering, physical security, C2 evasion, Active Directory lateral movement) to test the Blue Team's detection and response |
| **GRC Analyst** | Governance, Risk & Compliance | Audits and aligns organizations with legal/regulatory standards (`ISO 27001`, `NIST CSF`, `PCI-DSS`, `GDPR`, `SOC 2`) |

---

## Chapter 2: Security Principles

### 1. The CIA Triad & DAD Triad
Every security control aims to protect one or more pillars of the **CIA Triad** against its opposite counterpart in the **DAD Triad**:

| CIA Pillar | Definition | DAD Counterpart (Failure) | Example Controls |
| :--- | :--- | :--- | :--- |
| **Confidentiality** | Ensuring data is accessible only to authorized parties | **Disclosure** (Data leak/breach) | Encryption (`AES`, `TLS`), Access Control (`IAM`, `MFA`) |
| **Integrity** | Ensuring data is accurate, complete, and unaltered | **Alteration** (Unauthorized tampering) | Cryptographic Hashing (`SHA-256`), Digital Signatures, Version Control |
| **Availability** | Ensuring systems and data are accessible when needed | **Destruction / Denial** (Outage / Ransomware) | Redundancy (`RAID`, Load Balancers), Backups (`3-2-1 Rule`), DDoS Mitigation |

### 2. Core Access Control & Security Concepts
- **IAAA:**
  1. **Identification:** Claiming an identity (*"I am `alice`"* — Username).
  2. **Authentication:** Proving that identity (*Password, Hardware Token, Biometrics* — **MFA** combines 2+ factors: *Something you know*, *Something you have*, *Something you are*).
  3. **Authorization:** Determining what the authenticated user is allowed to do (*Permissions / RBAC*).
  4. **Accountability (Non-Repudiation):** Logging and auditing actions so a user cannot deny having performed them.

### 3. Formal Security Models
- **Bell-LaPadula Model:** Focuses strictly on **Confidentiality** (used in military/government classifications: *Unclassified -> Confidential -> Secret -> Top Secret*):
  - *Simple Security Property:* **"No Read Up"** (A Secret user cannot read Top Secret documents).
  - *Star (`*`) Property:* **"No Write Down"** (A Top Secret user cannot write/copy data into a Secret file, preventing accidental leaks).
- **Biba Model:** Focuses strictly on **Integrity**:
  - **"No Read Down"** (Do not read untrusted lower-integrity data).
  - **"No Write Up"** (Do not corrupt higher-integrity data).

### 4. Fundamental Security Design Principles
- **Defense-in-Depth (Layered Security):** Placing multiple independent security controls in series (Perimeter Firewall -> VLAN Segmentation -> Host EDR -> MFA -> Disk Encryption) so if one layer fails, others stop the attack.
- **Principle of Least Privilege (PoLP):** Users, processes, and service accounts should be granted only the bare minimum permissions required to perform their duties.
- **Separation of Duties (SoD):** Requiring more than one person to complete a critical task to prevent fraud or insider abuse.
- **Zero Trust ("Never Trust, Always Verify"):** Assumes the internal network is already compromised; requires continuous authentication and authorization for every request regardless of network location (contrasts with legacy perimeter **"Trust but Verify"**).
- **Threat, Vulnerability, and Risk:**
  - **Vulnerability:** A weakness in an asset or control.
  - **Threat:** A potential cause of an unwanted incident (Threat Actor / Natural Disaster).
  - **Risk:** The intersection of **Likelihood** (probability of a threat exploiting a vulnerability) and **Impact** ($\text{Risk} = \text{Likelihood} \times \text{Impact}$).

---

## Chapter 3: Security Engineer Intro

### The Role of a Security Engineer
A **Security Engineer** acts as the architect and builder of an organization's defensive posture—designing secure systems from the ground up and continuously hardening existing infrastructure.

### Core Responsibilities
1. **Asset Inventory & Management:**
   - *"You cannot protect what you do not know you have."*
   - Maintaining an accurate inventory of hardware, software, cloud instances, and **Shadow IT** (unauthorized systems deployed without IT approval).
2. **Security Policies, Standards, Guidelines, and Procedures:**
   - **Policies:** High-level mandatory rules set by executive management (e.g., *Acceptable Use Policy*).
   - **Standards:** Mandatory technical requirements (`AES-256` must be used for data at rest).
   - **Procedures:** Step-by-step operational instructions on how to implement a standard.
   - **Exception Handling:** Formal risk acceptance process when a legacy business system cannot immediately comply with a security standard (applying **Compensating Controls** like network isolation).
3. **Secure by Design & Hardening:**
   - Applying **CIS Benchmarks** (Center for Internet Security) to harden Operating Systems, Databases, and Cloud environments.
   - Disabling unused ports/services, removing default credentials, and enforcing least privilege.
4. **Change Management & Continuous Improvement:**
   - Reviewing architectural changes (CAB — Change Advisory Board) to ensure new features or firewall updates do not introduce security regressions.
   - Collaborating with Red Teams (**Purple Teaming**) and running tabletop exercises to validate and tune security controls.

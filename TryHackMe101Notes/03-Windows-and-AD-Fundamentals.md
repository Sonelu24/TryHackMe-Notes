# Module 03: Windows and AD Fundamentals

> **Overview:** Windows and Active Directory (AD) form the backbone of almost every enterprise network. This module covers Windows OS architecture, administrative tools, security controls, and Active Directory domain management.

---

## Chapter 1: Windows Fundamentals 1

### Core Concepts
- **Windows Editions:** Desktop (Windows 10/11 Home, Pro, Enterprise) vs. Server (Windows Server 2016/2019/2022).
- **File System — NTFS (New Technology File System):**
  - Replaces legacy FAT16/FAT32.
  - Supports files larger than 4GB, journaling (automatic crash recovery), encryption (EFS), compression, and granular **Access Control Lists (ACLs)**.
  - **NTFS Permissions:** Full Control, Modify, Read & Execute, List Folder Contents, Read, Write.
  - **Alternate Data Streams (ADS):** An NTFS feature allowing files to contain multiple streams of data (`file.txt:hidden.exe`), occasionally abused by malware to hide payloads.

### Key Windows Directories
- `C:\Windows`: Core OS directory (`winver` shows OS version/build).
- `C:\Windows\System32`: Contains critical 64-bit OS DLLs, executables (`cmd.exe`, `taskmgr.exe`), and configuration files.
- `C:\Program Files` & `C:\Program Files (x86)`: Installed 64-bit and 32-bit applications.
- `C:\Users`: User profile folders (`Desktop`, `Documents`, `AppData`).

### User Accounts & UAC
- **Account Types:**
  - **Administrator:** Can install software, modify system settings, and access all files.
  - **Standard User:** Restricted from making system-wide changes.
- **Local Users and Groups (`lusrmgr.msc`):** Manage local accounts and built-in security groups (`Administrators`, `Remote Desktop Users`, `Users`).
- **UAC (User Account Control):** Prevents unauthorized system changes by prompting for elevation (admin credentials or consent) even when logged in as an Administrator.
- **Task Manager (`taskmgr.exe`):** Monitors running processes, CPU/RAM/Disk/Network usage, startup apps, and services.

---

## Chapter 2: Windows Fundamentals 2

### Administrative Utilities
| Utility | Command / Run Shortcut | Purpose |
| :--- | :--- | :--- |
| **System Configuration** | `msconfig` | Configure boot options, safe mode, startup services, and diagnostic tools |
| **Computer Management** | `compmgmt.msc` | Umbrella console combining Task Scheduler, Event Viewer, Shared Folders, Local Users/Groups, Disk Management, and Services |
| **System Information** | `msinfo32` | Detailed hardware resources, environment variables (`PATH`), and software components |
| **Resource Monitor** | `resmon.exe` | Granular real-time tracking of process handles, network connections, and disk I/O |
| **Registry Editor** | `regedit` | View and edit the Windows Registry database |

### Event Viewer (`eventvwr.msc`)
Centralized log management categorized into Windows Logs:
- **Application:** Events logged by software applications.
- **Security:** Audit events such as successful/failed logins (e.g., Event ID `4624` = Successful Logon, `4625` = Failed Logon).
- **Setup:** Events related to application and OS installation/updates.
- **System:** Events logged by Windows system components and drivers.

### Windows Registry (`regedit`)
Hierarchical database storing low-level OS and application settings. Structured into five root keys (**Hives**):
1. `HKEY_CURRENT_USER (HKCU)`: Configuration specific to the currently logged-in user.
2. `HKEY_USERS (HKU)`: Contains all actively loaded user profiles on the machine.
3. `HKEY_LOCAL_MACHINE (HKLM)`: System-wide hardware, SAM, Security, Software, and System settings.
4. `HKEY_CLASSES_ROOT (HKCR)`: File associations and COM object registrations.
5. `HKEY_CURRENT_CONFIG (HKCC)`: Hardware profile used by the local computer at system startup.

---

## Chapter 3: Windows Fundamentals 3

### Built-in Windows Security Controls
- **Windows Updates:** Patches OS vulnerabilities (`Patch Tuesday` occurs on the second Tuesday of every month).
- **Windows Security (Defender Security Center):**
  - **Virus & Threat Protection:** Windows Defender Antivirus (Real-time protection, cloud-delivered protection, Tamper Protection, Controlled Folder Access against ransomware).
  - **Firewall & Network Protection:** Host-based firewall (`wf.msc`) filtering inbound/outbound traffic across three network profiles: **Domain**, **Private**, and **Public**.
  - **App & Browser Control:** SmartScreen filter blocking unrecognized applications and phishing sites.
  - **Device Security:**
    - *Core Isolation / Memory Integrity:* Uses virtualization-based security to isolate critical OS processes in memory.
    - *TPM (Trusted Platform Module):* Dedicated cryptographic hardware chip storing encryption keys and platform integrity measurements.
- **BitLocker:** Full-disk encryption protecting data at rest (integrates with TPM).
- **Volume Shadow Copy Service (`VSS`):** Creates backup snapshots (`Shadow Copies`) of files/volumes. *Note: Ransomware frequently runs `vssadmin delete shadows /all /quiet` to prevent recovery.*

---

## Chapter 4: Active Directory Basics

### What is Active Directory?
- **Active Directory Domain Services (AD DS):** Microsoft's centralized directory service that stores information about objects on a network (Users, Computers, Printers, Groups) and makes this policy/authentication management accessible to administrators.
- **Why use AD?** Instead of managing local accounts across 500 individual machines (Workgroup model), a single Domain Controller authenticates users across the entire enterprise.

### Core AD Components
```
Forest
 └── Tree (thm.local)
      ├── Domain (uk.thm.local)
      │    ├── Organizational Unit (OU: IT)
      │    │    ├── User Objects
      │    │    └── Computer Objects
      │    └── Organizational Unit (OU: Sales)
      └── Domain (us.thm.local)
```
- **Domain Controller (DC):** The Windows Server running AD DS that authenticates users, enforces security policies, and holds the AD database (`NTDS.dit`).
- **Active Directory Objects:**
  - **Users:** Security principals representing people or services (Service Accounts like `svc_sql`).
  - **Machines (Computers):** Every domain-joined computer has a machine account (named `<HOSTNAME>$`).
  - **Security Groups:** Used to assign permissions to multiple users at once (e.g., `Domain Admins`, `Backup Operators`).
- **Organizational Units (OUs):** Containers within a domain used to group objects logically (e.g., by department) and apply **Group Policy Objects (GPOs)** or delegate administrative control.
- **Group Policy Objects (GPOs):** Collection of settings/policies pushed from the DC (via the `SYSVOL` share) to users and computers in specific OUs (e.g., password complexity rules, disabling USB drives, deploying software).
- **Trees, Forests, and Trusts:**
  - **Tree:** A hierarchy of domains sharing a contiguous namespace (`thm.local` -> `uk.thm.local`).
  - **Forest:** A collection of one or more domain trees sharing a common schema and global catalog. The forest is the ultimate security boundary.
  - **Trust Relationships:** Mechanisms allowing users in one domain/forest to access resources in another (One-way vs. Two-way trusts; Transitive vs. Non-transitive).

### Authentication in Active Directory
1. **Kerberos (Default since Windows 2000):**
   - Ticket-based authentication protocol using a **Key Distribution Center (KDC)** on the Domain Controller.
   - User authenticates to the KDC to receive a **TGT (Ticket Granting Ticket)**, then presents the TGT to request a **TGS (Ticket Granting Service)** ticket to access specific network services.
2. **NetNTLM:**
   - Legacy challenge-response authentication protocol used when Kerberos cannot be used (e.g., connecting via IP address instead of hostname).

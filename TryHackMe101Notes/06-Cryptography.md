# Module 06: Cryptography

> **Overview:** Cryptography underpins modern digital security, ensuring confidentiality, integrity, authentication, and non-repudiation. This module covers symmetric encryption, public key (asymmetric) cryptography, hashing, and password hash cracking with `John the Ripper`.

---

## Chapter 1: Cryptography Basics

### Core Terminology
- **Plaintext:** The original, readable message or data before encryption.
- **Ciphertext:** The scrambled, unreadable output produced by encrypting plaintext.
- **Cipher:** The mathematical algorithm used to encrypt and decrypt data (e.g., `AES`, `ChaCha20`, `RSA`).
- **Key:** The secret piece of information used by a cipher to customize the encryption/decryption output.
- **Encryption vs. Encoding:**
  - *Encryption* requires a secret key to protect confidentiality (`AES`, `RSA`).
  - *Encoding* transforms data into a publicly known format for usability/transport (`Base64`, `URL Encoding`, `Hex`, `ASCII`) — **encoding provides zero security!**

### Historical Ciphers
- **Caesar Cipher:** Shifts every letter in the alphabet by a fixed number of positions (e.g., `ROT13` shifts by 13). Vulnerable to brute force (only 25 possible keys) and frequency analysis.
- **Vigenère Cipher:** Polyalphabetic substitution cipher using a repeating keyword.

### Symmetric Encryption
Uses the **exact same secret key** to both encrypt and decrypt data ($P \xrightarrow{K} C \xrightarrow{K} P$).
- **Pros:** Extremely fast and computationally efficient for bulk data encryption.
- **Cons:** **Key Distribution Problem** — how do you securely share the secret key over an untrusted network?
- **Types of Symmetric Ciphers:**
  - **Stream Ciphers:** Encrypt data bit-by-bit or byte-by-byte (`ChaCha20`, `RC4`).
  - **Block Ciphers:** Encrypt fixed-size blocks of data (`DES` = 64-bit blocks/56-bit key [Insecure/Deprecated]; `3DES`; **`AES` (Advanced Encryption Standard)** = 128-bit blocks with `128`, `192`, or `256`-bit keys).

### Mathematical Building Blocks
- **XOR ($\oplus$ — Exclusive OR):** Binary operation that returns `1` only when inputs differ (`0 ^ 0 = 0`, `1 ^ 1 = 0`, `1 ^ 0 = 1`).
  - Self-inverse property: $(A \oplus B) \oplus B = A$.
- **Modular Arithmetic ($a \bmod n$):** Returns the remainder of division; forms the foundation of public-key cryptography ("clock arithmetic").

---

## Chapter 2: Public Key Cryptography Basics

### Asymmetric Encryption
Solves the key distribution problem by using a mathematically linked **Key Pair**:
1. **Public Key:** Shared openly with everyone; used to **encrypt** messages or **verify** digital signatures.
2. **Private Key:** Kept strictly secret by the owner; used to **decrypt** messages or **create** digital signatures.

> **Hybrid Encryption (How TLS/HTTPS works):** Asymmetric encryption is ~1000x slower than symmetric encryption. In practice, systems use Asymmetric Cryptography (`RSA` / `ECDHE`) to securely exchange or agree upon a temporary **Symmetric Session Key**, and then use `AES-GCM` or `ChaCha20` for the actual data transfer.

### Key Asymmetric Algorithms
1. **RSA (Rivest–Shamir–Adleman):**
   - Security relies on the computational difficulty of factoring the product of two massive prime numbers ($n = p \times q$).
   - Key sizes: `2048-bit` (minimum recommended) or `4096-bit`.
2. **Diffie-Hellman Key Exchange (DH / ECDHE):**
   - Allows two parties (Alice & Bob) who have never met to establish a shared secret over an insecure channel without ever transmitting the secret itself.
   - Uses modular exponentiation: $g^{ab} \bmod p$.
3. **Elliptic Curve Cryptography (ECC):**
   - Provides equivalent security to RSA with much smaller key sizes (e.g., a `256-bit` ECC key is comparable to a `3072-bit` RSA key).

### Practical Cryptographic Applications
- **SSH Authentication:**
  - Generate key pair: `ssh-keygen -t ed25519` or `ssh-keygen -t rsa -b 4096`.
  - Private key stays at `~/.ssh/id_rsa` (must have strict permissions: `chmod 600 id_rsa`).
  - Public key (`id_rsa.pub`) is placed in the remote server's `~/.ssh/authorized_keys`.
- **Digital Signatures & Certificates (PKI):**
  - Hashing a document and encrypting the hash with your **Private Key** produces a **Digital Signature**. Anyone with your **Public Key** can decrypt the signature and verify both **Authenticity** and **Integrity**.
- **PGP / GPG (GNU Privacy Guard):**
  ```bash
  gpg --import private.key          # Import a private key
  gpg --decrypt secret_message.gpg  # Decrypt a GPG-encrypted file
  ```

---

## Chapter 3: Hashing Basics

### What is a Hash Function?
A cryptographic hash function takes an input of any arbitrary size and produces a fixed-length output called a **hash**, **digest**, or **checksum**.

### Essential Properties of Cryptographic Hashes
1. **One-Way (Pre-image Resistance):** Mathematically infeasible to reverse a hash back into the original input.
2. **Deterministic:** The exact same input will *always* produce the exact same hash output.
3. **Avalanche Effect:** Changing even a single bit of the input completely changes the resulting hash.
4. **Collision Resistance:** Infeasible to find two different inputs ($x \neq y$) that produce the same hash ($H(x) = H(y)$).

### Common Hash Algorithms & Lengths
| Algorithm | Hash Length (Bits / Hex Chars) | Security Status / Common Usage |
| :--- | :--- | :--- |
| **MD5** | 128 bits (32 hex chars) | **Broken** (vulnerable to collisions). Used only for basic file integrity checks (`md5sum`) |
| **SHA-1** | 160 bits (40 hex chars) | **Deprecated** (collision attacks demonstrated). Legacy Git commits/certificates |
| **SHA-256 (SHA-2)** | 256 bits (64 hex chars) | **Secure**. Standard for file integrity (`sha256sum`), TLS certificates, blockchain |
| **NTLM** | 128 bits (32 hex chars) | Windows local (`SAM`) and domain (`NTDS.dit`) password hash format (fast/unsalted!) |
| **bcrypt** | Variable (`$2a$`, `$2b$`, `$2y$`) | **Secure password hashing** (incorporates a salt and configurable work/cost factor) |
| **yescrypt / sha512crypt** | Variable (`$y$`, `$6$`) | Modern Linux password hashes stored in `/etc/shadow` |

### Password Salting & Integrity Verification
- **Rainbow Tables:** Precomputed tables of millions of plaintext passwords and their corresponding hashes.
- **Salting:** Appending a unique, random string (the **Salt**) to each password *before* hashing it (`Hash(password + salt)`). This defeats rainbow tables and ensures two users with the same password have completely different hashes.
- **HMAC (Hash-based Message Authentication Code):** Combines a hash function with a secret key to verify both data integrity and authenticity.

---

## Chapter 4: John the Ripper: The Basics

### Core Concepts
- **John the Ripper (`john`):** One of the most popular open-source offline password hash cracking tools.
- Since hashes cannot be "decrypted," cracking works by taking candidate words from a **wordlist** (like `rockyou.txt` located at `/usr/share/wordlists/rockyou.txt`), hashing each candidate using the target algorithm, and comparing it against the target hash.

### Identifying Hashes
Before cracking, identify the hash type using `hash-identifier`, `hashid`, or `nth` (Name That Hash):
```bash
hash-identifier
# Or check John's supported formats:
john --list=formats | grep -i "nt"
```

### Core `john` Commands
```bash
# 1. Automatic format detection + Wordlist attack
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# 2. Specify hash format explicitly (e.g., Raw-MD5, Raw-SHA256, NT)
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# 3. Display already cracked passwords from ~/.john/john.pot
john --show hashes.txt

# 4. Single Crack Mode (mangles the username/GECOS fields into password guesses)
# Requires hash file format: username:hash
john --single hashes_with_user.txt
```

### Cracking Linux `/etc/shadow` Hashes (`unshadow`)
To crack Linux system passwords, combine `/etc/passwd` and `/etc/shadow` using the `unshadow` utility:
```bash
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```

### Cracking Password-Protected Files (`*2john` Utilities)
John includes helper scripts (`zip2john`, `rar2john`, `ssh2john`, `pdf2john`, `office2john`) that extract a crackable hash from protected files:

1. **Password-Protected ZIP Archive:**
   ```bash
   zip2john secure.zip > zip_hash.txt
   john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt
   ```
2. **Password-Protected RAR Archive:**
   ```bash
   rar2john archive.rar > rar_hash.txt
   john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt
   ```
3. **Passphrase-Protected SSH Private Key (`id_rsa`):**
   ```bash
   ssh2john id_rsa > ssh_hash.txt
   john --wordlist=/usr/share/wordlists/rockyou.txt ssh_hash.txt
   ```

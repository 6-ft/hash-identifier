# 🔐 Hash Identifier

![Version](https://img.shields.io/badge/version-1.0-brightgreen?style=for-the-badge)
![GitHub Repo stars](https://img.shields.io/github/stars/6-ft/hash-identifier?style=for-the-badge)
![GitHub forks](https://img.shields.io/github/forks/6-ft/hash-identifier?style=for-the-badge)
![GitHub issues](https://img.shields.io/github/issues/6-ft/hash-identifier?style=for-the-badge)
![Python](https://img.shields.io/badge/python-3.7%2B-blue?style=for-the-badge)

---

## 🔍 Overview

**Hash Identifier** is a fast and reliable tool to detect the type of a given hash.  
It works as both a **CLI tool** and a **web-based utility**.  

Made for **beginners**, **CTF players**, and **security enthusiasts** who want a clean, easy-to-use hash identifier.

---

## ⚙️ Features

- 🧠 Detects 30+ common hash formats  
- 🔐 Identifies salted vs non-salted hashes  
- 📊 Shows matching confidence  
- 💻 CLI-based (offline)  
- 🌐 Easy to extend to web front-end  
- 🛠 Beginner-friendly, clean code  

---

## 🧾 Supported Hash Types

| Category | Examples |
|--------|---------|
| Classic | MD5, MD4, SHA1 |
| SHA Family | SHA224, SHA256, SHA384, SHA512 |
| SHA‑3 & SHAKE | SHA3‑256, SHA3‑512, SHAKE128, SHAKE256 |
| Key Derivation | PBKDF2, bcrypt, Argon2 |
| CMS / Web | WordPress, phpBB3, Drupal7 |
| Database | MySQL, PostgreSQL, MSSQL, Oracle |
| Network | WPA PMKID, WPA‑EAPOL |
| Files | ZIP, RAR, PDF, Office 2016+ |
| Others | RIPEMD-160, Tiger, Whirlpool, Blake2 |

---

## 🚀 Run the Tool (CLI)

### Clone the Project

```bash
git clone https://github.com/6-ft/hash-identifier
cd hash-format-identifier
```

### Run 
```bash
python3 hash_identifier.py
```

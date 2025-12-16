# 🔐 Hash Identifier

![Version](https://img.shields.io/badge/version-1.0-brightgreen?style=for-the-badge)
![GitHub Repo stars](https://img.shields.io/github/stars/6-ft/hash-identifier?style=for-the-badge)
![GitHub forks](https://img.shields.io/github/forks/6-ft/hash-identifier?style=for-the-badge)
![GitHub issues](https://img.shields.io/github/issues/6-ft/hash-identifier?style=for-the-badge)
![Python](https://img.shields.io/badge/python-3.7%2B-blue?style=for-the-badge)

---

## 🔍 Overview

**Hash Identifier** is a fast and reliable tool to detect the type of a given hash.  
Use it in **CLI mode** or instantly online via the **web version**.  

Made for **beginners**, **CTF players**, and anyone exploring cybersecurity with an easy-to-use hash tool.

---

## ⚙️ Features

- 🧠 Detects common hash formats  
- 🔐 Identifies salted vs non-salted hashes  
- 📊 Shows Match Strength  
- 💻 CLI-based (offline)  
- 🛠 Beginner-friendly 



## ⚡ Terminal Launch

### Clone the Project

```bash
git clone https://github.com/6-ft/hash-identifier
cd hash-format-identifier
```

### Run 
```bash
python3 hash_identifier.py
```
---
## 🌐 Web Version
A web version of this tool is available for quick checks without a terminal:

🔗[Visit Web Version](https://hash-identifier.netlify.app)

---

## 🧠 How It Works

Uses regular expressions to match hashes against a database of known formats.
Estimates confidence if multiple hash types are possible.

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


---
## 👤 Author

Made with ❤️ by 6-ft:

📌[github.com/6-ft](https://github.com/6-ft)

---
## ⭐ Support
If you like this project:

-Give it a ⭐ on GitHub

-Share it with friends

-Use it and learn

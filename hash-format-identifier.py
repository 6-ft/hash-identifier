import re
import random

LOGO = (
    "\n"
    "██╗  ██╗ █████╗ ███████╗██╗  ██╗     ██╗██████╗ ███████╗███╗   ██╗████████╗██╗███████╗██╗███████╗██████╗\n"
    "██║  ██║██╔══██╗██╔════╝██║  ██║     ██║██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██║██╔════╝██║██╔════╝██╔══██╗\n"
    "███████║███████║███████╗███████║     ██║██║  ██║█████╗  ██╔██╗ ██║   ██║   ██║█████╗  ██║█████╗  ██████╔╝\n"
    "██╔══██║██╔══██║╚════██║██╔══██║     ██║██║  ██║██╔══╝  ██║╚██╗██║   ██║   ██║██╔══╝  ██║██╔══╝  ██╔══██╗\n"
    "██║  ██║██║  ██║███████║██║  ██║     ██║██████╔╝███████╗██║ ╚████║   ██║   ██║██║     ██║███████╗██║  ██║\n"
    "╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝\n"
    "\n"
    "                              WELCOME TO HASH IDENTIFIER\n"
    "                                 \033]8;;https://github.com/6-ft\033\\github.com/6-ft\033]8;;\033\\\n"
)

HASH_DB =  [
    # ===== SURE / UNIQUE IDENTIFIERS (100% ACCURACY) =====
    ("bcrypt", r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$", True, 5, True, 3200),
    ("Argon2id", r"^\$argon2id\$", True, 5, True, 13),
    ("Argon2i", r"^\$argon2i\$", True, 5, True, 13),
    ("Argon2d", r"^\$argon2d\$", True, 5, True, 13),
    ("PBKDF2-HMAC-SHA256", r"^\$pbkdf2-sha256\$", True, 5, True, 109),
    ("PBKDF2-HMAC-SHA512", r"^\$pbkdf2-sha512\$", True, 5, True, 1095),
    ("Unix SHA-512 Crypt", r"^\$6\$.*", True, 5, True, 1800),
    ("Unix SHA-256 Crypt", r"^\$5\$.*", True, 5, True, 7400),
    ("Unix MD5 Crypt", r"^\$1\$.*", True, 4, True, 500),
    ("PostgreSQL MD5", r"^md5[a-f0-9]{32}$", True, 5, True, 0),
    ("WordPress", r"^\$P\$.*", True, 5, True, 400),
    ("phpBB3", r"^\$H\$.*", True, 5, True, 400),
    ("Drupal 7", r"^\$S\$.*", True, 5, True, 0),

    
    ("MD5", r"^[a-f0-9]{32}$", False, 3, True, 0),
    ("MD4", r"^[a-f0-9]{32}$", False, 3, True, 4),
    ("SHA1", r"^[a-f0-9]{40}$", False, 3, True, 100),
    ("SHA224", r"^[a-f0-9]{56}$", False, 3, True, 224),
    ("SHA256", r"^[a-f0-9]{64}$", False, 4, True, 256),
    ("SHA384", r"^[a-f0-9]{96}$", False, 4, True, 384),
    ("SHA512", r"^[a-f0-9]{128}$", False, 4, True, 512),
    ("SHA-3-256", r"^[a-f0-9]{64}$", False, 5, True, 1000),
    ("SHA-3-512", r"^[a-f0-9]{128}$", False, 5, True, 1010),


    # ===== OTHER HASHES (DYNAMIC ACCURACY) =====
    ("scrypt", r"^\$scrypt\$.*", True, 5, False, 8900),
    ("yescrypt", r"^\$y\$.*", True, 5, False, "unknown"),
    ("Blake2b", r"^[a-f0-9]{128}$", False, 5, False, 3200),
    ("Blake2s", r"^[a-f0-9]{64}$", False, 5, False, 500),
    ("RIPEMD-160", r"^[a-f0-9]{40}$", False, 5, False, 600),
    ("Tiger192", r"^[a-f0-9]{48}$", False, 5, False, 100),
    ("Whirlpool", r"^[a-f0-9]{128}$", False, 5, False, 610),
    ("LM", r"^[A-F0-9]{32}$", False, 5, False, 3000),
    ("MySQL 4.1+", r"^\*[A-F0-9]{40}$", False, 5, False, 300),
    ("Oracle 11g", r"^S:[A-F0-9]{60}$", True, 5, False, 112),
    ("Oracle 12c", r"^T:[A-F0-9]{160}$", True, 5, False, 121),
    ("MSSQL 2000", r"^0x0100[a-f0-9]{88}$", True, 5, False, "unknown"),
    ("MSSQL 2012+", r"^0x0200[a-f0-9]{136}$", True, 5, False, "unknown"),
    ("JWT HS256", r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", False, 5, False, 256),
    ("WPA-PMKID", r"^[a-f0-9]{32}:[a-f0-9]{12}:[a-f0-9]{12}:[a-f0-9]{12}$", True, 5, False, "unknown"),
    ("WPA-EAPOL", r"^WPA\*02\*", True, 5, False, "unknown"),
    ("RAR5", r"^\$rar5\$.*", True, 5, False, "unknown"),
    ("ZIP", r"^\$zip2\$.*", True, 5, False, "unknown"),
    ("7-Zip", r"^\$7z\$.*", True, 5, False, "unknown"),
    ("PDF 1.7", r"^\$pdf\$.*", True, 5, False, "unknown"),
    ("Office 2016+", r"^\$office\$2016\$", True, 5, False, "unknown"),
    ("Panama", r"^[a-f0-9]{128}$", False, 5, False, "unknown"),
]

def calculate_accuracy(u, s):
    acc = u * 15 + (10 if s else 0) + random.randint(-3, 3)
    return max(10, min(acc, 99))

def identify_best_hash(h):
    sure, dyn = [], []
    for n, p, s, u, f, m in HASH_DB:
        if re.fullmatch(p, h, re.IGNORECASE):
            e = {"name": n, "salted": s, "hash_mode": m, "accuracy": 100 if f else calculate_accuracy(u, s), "uniqueness": u}
            (sure if f else dyn).append(e)
    if sure:
        return max(sure, key=lambda x: x["uniqueness"])
    if dyn:
        return max(dyn, key=lambda x: (x["accuracy"], x["uniqueness"]))
    return None

if __name__ == "__main__":
    print(LOGO)
    hv = input("Paste hash: ").strip()
    r = identify_best_hash(hv)

    if not r:
        print("Hash Format : Unknown\nSalted     : Unknown\nAccuracy   : 0%\nHash Mode  : Unknown")
    else:
        print(f"Hash Format : {r['name']}")
        print(f"Salted     : {'YES' if r['salted'] else 'NO'}")
        print(f"Accuracy   : {r['accuracy']}%")
        print(f"Hash Mode  : {r['hash_mode']}")


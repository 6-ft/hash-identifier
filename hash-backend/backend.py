from flask import Flask, request, jsonify
import re
import random
import os

app = Flask(__name__)

# ==================================================
# HASH DATABASE (with hash mode)
# ==================================================
HASH_DB = [
    ("bcrypt", r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$", True, 5, True, "bcrypt"),
    ("Argon2id", r"^\$argon2id\$", True, 5, True, "argon2id"),
    ("Argon2i", r"^\$argon2i\$", True, 5, True, "argon2i"),
    ("Argon2d", r"^\$argon2d\$", True, 5, True, "argon2d"),
    ("PBKDF2-HMAC-SHA256", r"^\$pbkdf2-sha256\$", True, 5, True, "pbkdf2-sha256"),
    ("PBKDF2-HMAC-SHA512", r"^\$pbkdf2-sha512\$", True, 5, True, "pbkdf2-sha512"),
    ("Unix SHA-512 Crypt", r"^\$6\$.*", True, 5, True, "sha512"),
    ("Unix SHA-256 Crypt", r"^\$5\$.*", True, 5, True, "sha256"),
    ("Unix MD5 Crypt", r"^\$1\$.*", True, 4, True, "md5-crypt"),
    ("PostgreSQL MD5", r"^md5[a-f0-9]{32}$", True, 5, True, "postgresql-md5"),
    
    # Standard hashes
    ("MD5", r"^[a-f0-9]{32}$", False, 3, True, "md5"),
    ("SHA1", r"^[a-f0-9]{40}$", False, 3, True, "sha1"),
    ("SHA224", r"^[a-f0-9]{56}$", False, 3, True, "sha224"),
    ("SHA256", r"^[a-f0-9]{64}$", False, 4, True, "sha256"),
    ("SHA384", r"^[a-f0-9]{96}$", False, 4, True, "sha384"),
    ("SHA512", r"^[a-f0-9]{128}$", False, 4, True, "sha512"),
    
    # Dynamic hashes
    ("scrypt", r"^\$scrypt\$.*", True, 5, False, "scrypt"),
    ("Blake2b", r"^[a-f0-9]{128}$", False, 5, False, "blake2b"),
    ("Whirlpool", r"^[a-f0-9]{128}$", False, 5, False, "whirlpool"),
    ("WPA-PMKID", r"^[a-f0-9]{32}:[a-f0-9]{12}:[a-f0-9]{12}:[a-f0-9]{12}$", True, 5, False, "wpa-pmkid")
]

# ==================================================
# ACCURACY CALCULATION FOR DYNAMIC HASHES
# ==================================================
def calculate_accuracy(uniqueness: int, salted: bool):
    base = uniqueness * 15
    if salted:
        base += 10
    noise = random.randint(-3, 3)
    acc = base + noise
    return max(10, min(acc, 99))  # dynamic hashes never reach 100%

# ==================================================
# IDENTIFY HASH
# ==================================================
def identify_best_hash(hash_value: str):
    sure_matches = []
    dynamic_matches = []

    for name, pattern, salted, uniqueness, sure, mode in HASH_DB:
        try:
            if re.fullmatch(pattern, hash_value, re.IGNORECASE):
                if sure:
                    sure_matches.append({
                        "name": name,
                        "salted": salted,
                        "accuracy": 100,
                        "uniqueness": uniqueness,
                        "hash_mode": mode
                    })
                else:
                    acc = calculate_accuracy(uniqueness, salted)
                    dynamic_matches.append({
                        "name": name,
                        "salted": salted,
                        "accuracy": acc,
                        "uniqueness": uniqueness,
                        "hash_mode": mode
                    })
        except re.error:
            continue

    # Prioritize sure matches
    if sure_matches:
        sure_matches.sort(key=lambda x: x["uniqueness"], reverse=True)
        return sure_matches[0]
    elif dynamic_matches:
        dynamic_matches.sort(key=lambda x: (x["accuracy"], x["uniqueness"]), reverse=True)
        return dynamic_matches[0]
    else:
        return None

# ==================================================
# API ROUTE
# ==================================================
@app.route('/identify', methods=['POST'])
def identify():
    data = request.get_json()
    hash_value = data.get("hash")
    result = identify_best_hash(hash_value)
    
    if result:
        response = {
            "name": result["name"],
            "hash_mode": result["hash_mode"],
            "accuracy": result["accuracy"],
            "salted": result["salted"]
        }
    else:
        response = {
            "name": "Unknown",
            "hash_mode": "Unknown",
            "accuracy": 0,
            "salted": "Unknown"
        }

    return jsonify(response)

# ==================================================
# MAIN
# ==================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=True)

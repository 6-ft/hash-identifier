from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import random

app = Flask(__name__)
CORS(app)  # Enable CORS so frontend can make API requests

# ==================================================
# HASH DATABASE (Hash name, regex pattern, salted, uniqueness score, sure match, hash mode)
# ==================================================
HASH_DB = [
    # Sure/Unique Identifiers (100% accuracy)
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
    
    # Other hashes (with dynamic accuracy)
    ("MD5", r"^[a-f0-9]{32}$", False, 3, True, 0),
    ("MD4", r"^[a-f0-9]{32}$", False, 3, True, 4),
    ("SHA1", r"^[a-f0-9]{40}$", False, 3, True, 100),
    ("SHA256", r"^[a-f0-9]{64}$", False, 4, True, 256),
    ("SHA512", r"^[a-f0-9]{128}$", False, 4, True, 512),
    ("SHA-3-256", r"^[a-f0-9]{64}$", False, 5, True, 1000),
    ("SHA-3-512", r"^[a-f0-9]{128}$", False, 5, True, 1010),
    ("SHAKE128", r"^[a-f0-9]{32,64}$", False, 5, True, "unknown"),
    ("SHAKE256", r"^[a-f0-9]{64,128}$", False, 5, True, "unknown"),

    # Other dynamic hashes
    ("scrypt", r"^\$scrypt\$.*", True, 5, False, 8900),
    ("Blake2b", r"^[a-f0-9]{128}$", False, 5, False, 3200),
    ("Whirlpool", r"^[a-f0-9]{128}$", False, 5, False, 610),
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

    # Loop through hash DB and check against regex
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
# ROUTES
# ==================================================
@app.route('/identify', methods=['POST'])
def identify():
    data = request.get_json()
    hash_value = data.get("hash")

    if not hash_value:
        return jsonify({"error": "No hash value provided"}), 400

    result = identify_best_hash(hash_value)

    if not result:
        return jsonify({
            "name": "Unknown",
            "hash_mode": "Unknown",
            "accuracy": 0,
            "salted": False
        })

    return jsonify({
        "name": result["name"],
        "hash_mode": result["hash_mode"],
        "accuracy": result["accuracy"],
        "salted": result["salted"]
    })

# ==================================================
# MAIN
# ==================================================
if __name__ == "__main__":
    app.run(debug=True)

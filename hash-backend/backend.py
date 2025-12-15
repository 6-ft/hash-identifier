from flask import Flask, request, jsonify
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)  # Allow frontend to call API

@app.route('/identify', methods=['POST'])
def identify():
    data = request.get_json()
    hash_value = data.get("hash")

    # Check if hash is provided
    if not hash_value:
        return jsonify({"error": "No hash provided"}), 400

    # Logic to identify hash type, accuracy, and hash mode
    if len(hash_value) == 32:
        # MD5 Hash
        hash_type = "MD5"
        accuracy = 95
        salted = False
        hash_mode = "numeric" if hash_value.isdigit() else "unknown"
    elif len(hash_value) == 40:
        # SHA-1 Hash
        hash_type = "SHA-1"
        accuracy = 92
        salted = False
        hash_mode = "numeric" if hash_value.isdigit() else "unknown"
    elif len(hash_value) == 64:
        # SHA-256 Hash
        hash_type = "SHA-256"
        accuracy = 98
        salted = False
        hash_mode = "numeric" if hash_value.isdigit() else "unknown"
    elif len(hash_value) == 56:
        # SHA-224 Hash
        hash_type = "SHA-224"
        accuracy = 96
        salted = False
        hash_mode = "numeric" if hash_value.isdigit() else "unknown"
    elif len(hash_value) == 128:
        # SHA-512 Hash
        hash_type = "SHA-512"
        accuracy = 99
        salted = False
        hash_mode = "numeric" if hash_value.isdigit() else "unknown"
    elif len(hash_value) == 16:
        # MD4 Hash
        hash_type = "MD4"
        accuracy = 90
        salted = False
        hash_mode = "numeric" if hash_value.isdigit() else "unknown"
    else:
        # Unknown Hash Type
        hash_type = "Unknown"
        accuracy = 0
        salted = False
        hash_mode = "unknown"

    # Return the identified hash data
    response = {
        "name": hash_type,
        "hash_mode": hash_mode,
        "accuracy": accuracy,
        "salted": salted
    }
    return jsonify(response)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)

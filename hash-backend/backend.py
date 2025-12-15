from flask import Flask, request, jsonify
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)  # Allow frontend to call API

@app.route('/identify', methods=['POST'])
def identify():
    data = request.get_json()
    hash_value = data.get("hash")

    # Example hash identification logic (you can replace this with actual hash logic)
    if not hash_value:
        return jsonify({"error": "No hash provided"}), 400

    # Placeholder for actual hash type detection
    if len(hash_value) == 32:
        hash_type = "MD5"
        accuracy = 95
        salted = False
    elif len(hash_value) == 40:
        hash_type = "SHA-1"
        accuracy = 92
        salted = False
    elif len(hash_value) == 64:
        hash_type = "SHA-256"
        accuracy = 98
        salted = False
    else:
        hash_type = "Unknown"
        accuracy = 0
        salted = False

    # Response object to send back
    response = {
        "name": hash_type,
        "hash_mode": hash_type,
        "accuracy": accuracy,
        "salted": salted
    }
    return jsonify(response)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)

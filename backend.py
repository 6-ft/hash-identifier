from flask import Flask, request, jsonify
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)  # Allow frontend to call API

@app.route('/identify', methods=['POST'])
def identify():
    data = request.get_json()
    hash_value = data.get("hash")

    # Example logic (replace with actual hash detection)
    response = {
        "name": "MD5",       # placeholder
        "hash_mode": "MD5",
        "accuracy": 95,
        "salted": False
    }
    return jsonify(response)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)

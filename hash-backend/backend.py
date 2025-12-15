from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

# Serve frontend HTML
@app.route("/", methods=["GET"])
def home():
    return send_from_directory("static", "index.html")  # loads index.html

# Hash identification API
@app.route("/identify", methods=["POST"])
def identify():
    data = request.get_json()
    hash_value = data.get("hash")

    if not hash_value:
        return jsonify({"error": "No hash provided"}), 400

    response = {
        "name": "MD5",
        "hash_mode": "MD5",
        "accuracy": 95,
        "salted": False
    }
    return jsonify(response)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)

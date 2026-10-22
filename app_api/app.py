from flask import Flask, request, jsonify
import requests
import jwt
import datetime
import os
from functools import wraps

app = Flask(__name__)

# SECURITY FIX: Read secret from environment variable (Defaults to string for local dev)
JWT_SECRET = os.environ["JWT_SECRET"]
RESOURCE_SERVICE_URL = "http://127.0.0.1:5002"
PROCESSING_SERVICE_URL = "http://127.0.0.1:5003"

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Authorization token missing"}), 401
        try:
            token_clean = token.replace("Bearer ", "")
            current_user = jwt.decode(token_clean, JWT_SECRET, algorithms=["HS256"])
        except Exception:
            return jsonify({"error": "Invalid token"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route("/api/auth/login", methods=["POST"])
def login():
    creds = request.get_json() or {}
    try:
        res = requests.post(f"{RESOURCE_SERVICE_URL}/resources/auth_user", json=creds, timeout=2)
        if res.status_code != 200:
            return jsonify({"error": "Invalid credentials"}), 401
        user_info = res.json()
    except Exception:
        return jsonify({"error": "Service unavailable"}), 503

    token = jwt.encode({
        "user_id": user_info["id"],
        "role": user_info["role"],
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
    }, JWT_SECRET, algorithm="HS256")

    return jsonify({"token": token, "role": user_info["role"]}), 200

@app.route("/api/datasets/search", methods=["GET"])
@token_required
def search_datasets(current_user):
    q = request.args.get("q", "")
    res = requests.get(f"{RESOURCE_SERVICE_URL}/resources/search", params={"q": q}, timeout=3)
    return jsonify(res.json()), res.status_code

@app.route("/api/datasets/<int:dataset_id>", methods=["GET"])
@token_required
def get_dataset(current_user, dataset_id):
    headers = {"Authorization": request.headers.get("Authorization")}
    res = requests.get(f"{RESOURCE_SERVICE_URL}/resources/dataset/{dataset_id}", headers=headers, timeout=3)
    return jsonify(res.json()), res.status_code

@app.route("/api/datasets/consume-quota", methods=["POST"])
@token_required
def consume_quota(current_user):
    res = requests.post(f"{RESOURCE_SERVICE_URL}/resources/quota/consume", json={"user_id": current_user["user_id"]}, timeout=3)
    return jsonify(res.json()), res.status_code

@app.route("/api/export-job", methods=["POST"])
@token_required
def export_job(current_user):
    payload = request.get_json() or {}
    headers = {"Authorization": request.headers.get("Authorization")}
    try:
        res = requests.post(f"{PROCESSING_SERVICE_URL}/process/export", json=payload, headers=headers, timeout=4)
        return jsonify(res.json()), res.status_code
    except Exception as e:
        return jsonify({"error": f"Pipeline failed: {str(e)}"}), 502

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
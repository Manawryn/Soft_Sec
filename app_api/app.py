from flask import Flask, request, jsonify
import requests
import jwt
import datetime
import os
from functools import wraps

app = Flask(__name__)

# SECURITY FIX: Read secret from environment variable, fail closed
JWT_SECRET = os.environ["JWT_SECRET"]
RESOURCE_SERVICE_URL = "http://127.0.0.1:5002"
PROCESSING_SERVICE_URL = "http://127.0.0.1:5003"
JOB_TOKEN_TTL_SECONDS = 60

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
    headers = {"Authorization": request.headers.get("Authorization")}
    res = requests.get(f"{RESOURCE_SERVICE_URL}/resources/search", params={"q": q}, headers=headers, timeout=3)
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
    headers = {"Authorization": request.headers.get("Authorization")}
    res = requests.post(f"{RESOURCE_SERVICE_URL}/resources/quota/consume", headers=headers, timeout=3)
    return jsonify(res.json()), res.status_code

# SECURITY FIX (authority binding): instead of forwarding the caller's full
# 2-hour session JWT (which carries ambient role/identity authority) to the
# Processing Service, mint a short-lived JOB-SCOPED DELEGATION TOKEN. It is
# bound to:
#   - the SERVICE allowed to accept it ("aud": "resource_service")
#   - the ACTION it authorizes          ("action": "export")
#   - the specific RESOURCE it covers   ("dataset_id")
#   - a short VALIDITY PERIOD           (60 seconds)
# The Processing Service never receives, and cannot use, authority beyond
# exactly this one export of this one dataset.
@app.route("/api/export-job", methods=["POST"])
@token_required
def export_job(current_user):
    payload = request.get_json() or {}
    dataset_id = payload.get("dataset_id")
    if not dataset_id:
        return jsonify({"error": "dataset_id required"}), 400

    now = datetime.datetime.now(datetime.timezone.utc)
    job_token = jwt.encode({
        "user_id": current_user["user_id"],
        "role": current_user["role"],
        "aud": "resource_service",
        "action": "export",
        "dataset_id": dataset_id,
        "iat": now,
        "exp": now + datetime.timedelta(seconds=JOB_TOKEN_TTL_SECONDS)
    }, JWT_SECRET, algorithm="HS256")

    headers = {"Authorization": f"Bearer {job_token}"}
    try:
        res = requests.post(f"{PROCESSING_SERVICE_URL}/process/export", json=payload, headers=headers, timeout=4)
        return jsonify(res.json()), res.status_code
    except Exception as e:
        return jsonify({"error": f"Pipeline failed: {str(e)}"}), 502

# Retrieve a previously completed export. Forwards the caller's own session
# token, so the Resource Service's ownership/admin check applies.
@app.route("/api/exports/<int:export_id>", methods=["GET"])
@token_required
def get_export(current_user, export_id):
    headers = {"Authorization": request.headers.get("Authorization")}
    res = requests.get(f"{RESOURCE_SERVICE_URL}/resources/exports/{export_id}", headers=headers, timeout=3)
    return jsonify(res.json()), res.status_code

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)

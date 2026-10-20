from flask import Flask, request, jsonify
import requests
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

# INTENTIONAL SAST FLAW: Hardcoded secret (CWE-798, Bandit B105 - high severity finding)
JWT_SECRET = "super-secret-hardcoded-key-12345"

RESOURCE_SERVICE_URL = "http://127.0.0.1:5002"
PROCESSING_SERVICE_URL = "http://127.0.0.1:5003"

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            # Secure Principle: Fail-Safe Defaults (Fail closed)
            return jsonify({"error": "Authorization token is missing (Fail-Safe Default)"}), 401
        try:
            token_clean = token.replace("Bearer ", "")
            data = jwt.decode(token_clean, JWT_SECRET, algorithms=["HS256"])
            current_user = data
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception:
            return jsonify({"error": "Invalid token"}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# OP-1: Authentication & Token Issuance
@app.route("/api/auth/login", methods=["POST"])
def login():
    creds = request.get_json() or {}
    username = creds.get("username")
    password = creds.get("password")

    try:
        res = requests.post(
            f"{RESOURCE_SERVICE_URL}/resources/auth_user",
            json={"username": username, "password": password},
            timeout=2
        )
        if res.status_code != 200:
            return jsonify({"error": "Invalid credentials"}), 401
        user_info = res.json()
    except Exception:
        return jsonify({"error": "Resource Service unavailable"}), 503

    token = jwt.encode({
        "user_id": user_info["id"],
        "username": user_info["username"],
        "role": user_info["role"],
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
    }, JWT_SECRET, algorithm="HS256")

    return jsonify({"token": token, "role": user_info["role"], "user_id": user_info["id"]}), 200

# OP-2: Dataset Search (Routes to SQLi-vulnerable endpoint)
@app.route("/api/datasets/search", methods=["GET"])
@token_required
def search_datasets(current_user):
    q = request.args.get("q", "")
    res = requests.get(f"{RESOURCE_SERVICE_URL}/resources/search?q={q}")
    return jsonify(res.json()), res.status_code

# OP-2: Direct Dataset Retrieval (Exposes IDOR)
@app.route("/api/datasets/<int:dataset_id>", methods=["GET"])
@token_required
def get_dataset(current_user, dataset_id):
    # FLAW: Fails Complete Mediation. Does not check if current_user owns the dataset
    res = requests.get(f"{RESOURCE_SERVICE_URL}/resources/dataset/{dataset_id}")
    return jsonify(res.json()), res.status_code

# OP-3: State Modification (Exposes Race Condition)
@app.route("/api/datasets/consume-quota", methods=["POST"])
@token_required
def consume_quota(current_user):
    res = requests.post(f"{RESOURCE_SERVICE_URL}/resources/quota/consume", json={"user_id": current_user["user_id"]})
    return jsonify(res.json()), res.status_code

# OP-4: 3-Tier Asynchronous Export Pipeline (Exposes Composition Flaw / Confused Deputy)
@app.route("/api/export-job", methods=["POST"])
@token_required
def export_job(current_user):
    payload = request.get_json() or {}
    dataset_id = payload.get("dataset_id")
    if not dataset_id:
        return jsonify({"error": "dataset_id required"}), 400

    # FLAW: Gateway does not verify ownership before dispatching the job.
    # Processing Service will use ambient trust to export any dataset requested.
    try:
        res = requests.post(f"{PROCESSING_SERVICE_URL}/process/export", json={"dataset_id": dataset_id}, timeout=4)
        return jsonify(res.json()), res.status_code
    except Exception as e:
        return jsonify({"error": f"Failed to contact Processing pipeline: {str(e)}"}), 502

if __name__ == "__main__":
    print("[*] Starting Application API Gateway on port 5001...")
    app.run(host="127.0.0.1", port=5001, debug=False)
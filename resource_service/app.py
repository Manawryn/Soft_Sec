from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash
from database import get_db, init_db, DB_FILE
import os
import time

app = Flask(__name__)

# Authentication Verification (Boundary Check: only returns identity and role, no password/hash leaks)
@app.route("/resources/auth_user", methods=["POST"])
def auth_user():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash, role, export_quota FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "export_quota": user["export_quota"]
    }), 200

# VULNERABILITY 1 (Catalog: Trust Failure / SQL Injection - CWE-89, Bandit B608)
@app.route("/resources/search", methods=["GET"])
def search_dataset():
    keyword = request.args.get("q", "")
    conn = get_db()
    cursor = conn.cursor()
    # INTENTIONAL FLAW: String formatting creates injection vector
    query = f"SELECT id, title, owner_id, classification FROM datasets WHERE title LIKE '%{keyword}%'"
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        return jsonify([dict(row) for row in rows]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# VULNERABILITY 2 (Catalog: Authority Failure / IDOR - CWE-639)
@app.route("/resources/dataset/<int:dataset_id>", methods=["GET"])
def get_dataset(dataset_id):
    # INTENTIONAL FLAW: Does not verify that the requester is the resource owner
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM datasets WHERE id = ?", (dataset_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Dataset not found"}), 404
    return jsonify(dict(row)), 200

# VULNERABILITY 3 (Catalog: State Failure / Concurrency Race Condition - CWE-362)
@app.route("/resources/quota/consume", methods=["POST"])
def consume_quota():
    data = request.get_json() or {}
    user_id = data.get("user_id")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT export_quota FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if not user or user["export_quota"] <= 0:
        conn.close()
        return jsonify({"error": "Insufficient export quota"}), 403

    current_quota = user["export_quota"]

    # INTENTIONAL FLAW: Non-atomic check-then-act with simulated context switch
    time.sleep(0.1)

    new_quota = current_quota - 1
    cursor.execute("UPDATE users SET export_quota = ? WHERE id = ?", (new_quota, user_id))
    conn.commit()
    conn.close()

    return jsonify({"message": "Quota consumed successfully", "remaining_quota": new_quota}), 200

# Internal target endpoint used by Processing Service (Confused Deputy target)
@app.route("/resources/internal/dataset/<int:dataset_id>", methods=["GET"])
def internal_get_dataset(dataset_id):
    # INTENTIONAL FLAW: Relies solely on an ambient internal header without caller user context
    internal_token = request.headers.get("X-Internal-Service")
    if internal_token != "processing-engine-internal-secret":
        return jsonify({"error": "Unauthorized internal call"}), 403

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM datasets WHERE id = ?", (dataset_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Dataset not found"}), 404
    return jsonify(dict(row)), 200

if __name__ == "__main__":
    if not os.path.exists(DB_FILE):
        init_db()
    print("[*] Starting Resource Service on port 5002...")
    app.run(host="127.0.0.1", port=5002, debug=False)
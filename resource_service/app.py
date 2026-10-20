from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash
from database import get_db, DB_FILE
import os
import jwt

app = Flask(__name__)
JWT_SECRET = os.environ.get("JWT_SECRET", "super-secret-hardcoded-key-12345")

def decode_token(request_obj):
    """Helper to extract user context from forwarded JWTs."""
    token = request_obj.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return None
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None

@app.route("/resources/auth_user", methods=["POST"])
def auth_user():
    data = request.get_json() or {}
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash, role, export_quota FROM users WHERE username = ?", (data.get("username"),))
    user = cursor.fetchone()
    conn.close()

    if not user or not check_password_hash(user["password_hash"], data.get("password")):
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({"id": user["id"], "username": user["username"], "role": user["role"], "export_quota": user["export_quota"]}), 200

# FIX 1: SQL Injection eliminated via parameterized queries
@app.route("/resources/search", methods=["GET"])
def search_dataset():
    keyword = request.args.get("q", "")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, owner_id, classification FROM datasets WHERE title LIKE ?", ('%' + keyword + '%',))
    rows = cursor.fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows]), 200

# FIX 2 & FIX 4: IDOR and Confused Deputy eliminated via Complete Mediation
@app.route("/resources/dataset/<int:dataset_id>", methods=["GET"])
def get_dataset(dataset_id):
    user = decode_token(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    cursor = conn.cursor()
    # Enforce Authorization: Only the owner or an admin can access the dataset
    cursor.execute("SELECT * FROM datasets WHERE id = ? AND (owner_id = ? OR ? = 'admin')", 
                   (dataset_id, user["user_id"], user["role"]))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "Dataset not found or access denied"}), 403
    return jsonify(dict(row)), 200

# FIX 3: Race Condition eliminated via Atomic Transactions
@app.route("/resources/quota/consume", methods=["POST"])
def consume_quota():
    data = request.get_json() or {}
    user_id = data.get("user_id")

    conn = get_db()
    cursor = conn.cursor()
    # Atomic update prevents concurrent thread overlap
    cursor.execute("UPDATE users SET export_quota = export_quota - 1 WHERE id = ? AND export_quota > 0", (user_id,))
    
    if cursor.rowcount == 0:
        conn.commit()
        conn.close()
        return jsonify({"error": "Insufficient export quota"}), 403

    cursor.execute("SELECT export_quota FROM users WHERE id = ?", (user_id,))
    new_quota = cursor.fetchone()["export_quota"]
    conn.commit()
    conn.close()

    return jsonify({"message": "Quota consumed successfully", "remaining_quota": new_quota}), 200

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=False)
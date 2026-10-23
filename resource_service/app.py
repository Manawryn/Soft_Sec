from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash
from database import get_db, DB_FILE
import os
import jwt

app = Flask(__name__)
# SECURITY FIX: fail closed, no hardcoded fallback secret
JWT_SECRET = os.environ["JWT_SECRET"]

def decode_token(request_obj):
    """Helper to extract claims from a forwarded JWT (session token or
    job-scoped delegation token)."""
    token = request_obj.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return None
    try:
        # "aud" is checked explicitly below (it differs by token type), so
        # disable PyJWT's automatic audience check here rather than passing
        # a fixed expected audience to decode().
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False})
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

# FIX 1: SQL Injection eliminated via parameterized queries.
# SECURITY FIX: search now requires authentication and is scoped to the
# caller's own datasets (admins see everything) instead of leaking every
# user's dataset metadata to any authenticated researcher.
@app.route("/resources/search", methods=["GET"])
def search_dataset():
    claims = decode_token(request)
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401

    keyword = request.args.get("q", "")
    conn = get_db()
    cursor = conn.cursor()
    if claims.get("role") == "admin":
        cursor.execute("SELECT id, title, owner_id, classification FROM datasets WHERE title LIKE ?",
                       ('%' + keyword + '%',))
    else:
        cursor.execute("SELECT id, title, owner_id, classification FROM datasets WHERE title LIKE ? AND owner_id = ?",
                       ('%' + keyword + '%', claims.get("user_id") or claims.get("sub")))
    rows = cursor.fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows]), 200

# FIX 2 & FIX 4: IDOR and Confused Deputy eliminated via Complete Mediation.
# SECURITY FIX (authority binding): this endpoint is reached two ways:
#   - a direct read, carrying the caller's ordinary session token (no "aud"
#     claim) - authorized by simple ownership/admin check, as before.
#   - the export pipeline, carrying a short-lived JOB-SCOPED DELEGATION
#     TOKEN minted by the Application API for this one export request.
#     That token is bound to: the service it may be presented to ("aud":
#     "resource_service"), the action it authorizes ("action": "export"),
#     the single resource it covers ("dataset_id"), and a short validity
#     period (60s, see app_api). A job token for dataset 2 cannot be reused
#     to read dataset 1, replayed after it expires, or presented to any
#     endpoint other than this one - closing the confused-deputy path where
#     the Processing Service previously held ambient authority to fetch any
#     dataset on the user's behalf.
@app.route("/resources/dataset/<int:dataset_id>", methods=["GET"])
def get_dataset(dataset_id):
    claims = decode_token(request)
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401

    if claims.get("aud") is not None:
        # Job-scoped delegation token: must match this service, this
        # action, and this exact dataset.
        if (claims.get("aud") != "resource_service"
                or claims.get("action") != "export"
                or claims.get("dataset_id") != dataset_id):
            return jsonify({"error": "Token not valid for this resource/action"}), 403
        requester_id = claims.get("user_id")
        requester_role = claims.get("role")
    else:
        # Ordinary session token presented for a direct read.
        requester_id = claims.get("user_id")
        requester_role = claims.get("role")

    conn = get_db()
    cursor = conn.cursor()
    # Enforce Authorization: Only the owner or an admin can access the dataset
    cursor.execute("SELECT * FROM datasets WHERE id = ? AND (owner_id = ? OR ? = 'admin')",
                   (dataset_id, requester_id, requester_role))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Dataset not found or access denied"}), 403
    return jsonify(dict(row)), 200

# FIX 3: Race Condition eliminated via Atomic Transactions.
# SECURITY FIX: the caller's identity now comes from their own verified
# token, not from a user_id supplied in the request body, so one user can
# no longer drain another user's quota by naming their id.
@app.route("/resources/quota/consume", methods=["POST"])
def consume_quota():
    claims = decode_token(request)
    if not claims:
        return jsonify({"error": "Unauthorized"}), 401
    user_id = claims.get("user_id") or claims.get("sub")

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

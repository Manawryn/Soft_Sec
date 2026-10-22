import concurrent.futures, os, sqlite3
import requests

API = "http://127.0.0.1:5001"
DB = os.path.join(os.path.dirname(__file__), "..", "resource_service", "research_vault.db")
ALICE, BOB, ADMIN = ("alice", "AlicePass!123"), ("bob", "BobPass!456"), ("admin", "AdminSecret!2026")

def auth(creds):
    r = requests.post(f"{API}/api/auth/login", json={"username": creds[0], "password": creds[1]})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['token']}"}

# ---- functional ----
def test_login_rejects_bad_password():
    r = requests.post(f"{API}/api/auth/login", json={"username": "alice", "password": "wrong"})
    assert r.status_code == 401

def test_owner_reads_own_dataset():
    assert requests.get(f"{API}/api/datasets/1", headers=auth(ALICE)).status_code == 200

def test_admin_reads_any_dataset():
    assert requests.get(f"{API}/api/datasets/2", headers=auth(ADMIN)).status_code == 200

def test_owner_exports_own_dataset():
    r = requests.post(f"{API}/api/export-job", json={"dataset_id": 1}, headers=auth(ALICE))
    assert r.status_code == 200 and r.json()["status"] == "COMPLETED"

# ---- security (TH-01..TH-04) ----
def test_th01_sql_injection_neutralised():
    r = requests.get(f"{API}/api/datasets/search", params={"q": "' OR '1'='1"}, headers=auth(ALICE))
    assert r.status_code == 200 and len(r.json()) == 0

def test_th02_idor_blocked():
    assert requests.get(f"{API}/api/datasets/2", headers=auth(ALICE)).status_code == 403

def test_th03_quota_race_blocked():
    with sqlite3.connect(DB) as c:
        c.execute("UPDATE users SET export_quota = 1 WHERE username = 'alice'")
    h = auth(ALICE)
    call = lambda: requests.post(f"{API}/api/datasets/consume-quota", headers=h).status_code
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        codes = sorted(f.result() for f in [ex.submit(call), ex.submit(call)])
    assert codes == [200, 403]

def test_th04_confused_deputy_blocked():
    r = requests.post(f"{API}/api/export-job", json={"dataset_id": 2}, headers=auth(ALICE))
    assert r.status_code == 403

# ---- malformed artifacts ----
def test_missing_token_rejected():
    assert requests.get(f"{API}/api/datasets/1").status_code == 401

def test_tampered_token_rejected():
    r = requests.get(f"{API}/api/datasets/1", headers={"Authorization": "Bearer a.b.c"})
    assert r.status_code == 401

def test_missing_payload_rejected():
    r = requests.post(f"{API}/api/export-job", json={}, headers=auth(ALICE))
    assert r.status_code == 400 and "dataset_id" in r.json()["error"]
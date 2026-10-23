"""
Experiment B - a compromised supplier release gets approved, then runs for
real inside the application, against the actual Resource Service database.

Scenario (per the assignment spec): in an isolated experimental run, the
malicious data_exporter build's digest is explicitly approved as a new,
trusted version - modelling a compromised supplier account or build
pipeline whose update gets accepted. The malicious build is then installed
for real, the three services are started exactly as they run normally, and
a single ordinary, fully-authorized export request (Alice exporting her
own dataset) is made through the real HTTP API - not a staged bypass.

This script:
  1. Writes a scratch manifest that approves the malicious wheel's SHA-256
     under data_exporter (the "compromised update got accepted" step), and
     shows the gate now treats it as approved.
  2. Installs the malicious wheel for real (--force-reinstall).
  3. Resets and seeds the real resource_service/research_vault.db, exactly
     like the test suite's own service-lifecycle fixture.
  4. Starts resource_service, processing_service and app_api as real
     subprocesses, with the project root as their working directory - the
     same way run_all.sh/run_all.bat and tests/conftest.py start them.
  5. Starts a local "attacker" listener (attacker_server.py) on 127.0.0.1:9099.
  6. Logs in as Alice and requests an export of HER OWN dataset (dataset_id=1)
     through the real Application API - the normal, legitimate workflow.
  7. Checks whether the attacker's listener received the real database
     file, and whether Alice's export still completed successfully.
  8. Restores the benign package and tears everything down.

Expected result on `main` (no runtime containment around the dependency
call): the malicious build's _exfiltrate() reaches the real
research_vault.db via a relative file search and POSTs it to the attacker
listener - VERDICT: COMPROMISED. Expected result on `fixed-version`
(processing_service/sandboxed_dependency.py isolates every call): the
dependency never sees a real project file or a reachable network, nothing
is captured, and Alice's export still completes normally - VERDICT:
CONTAINED.

Run:
    python run_experiment_B.py
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent
MALICIOUS_WHEEL = HERE / "built_wheels" / "malicious" / "data_exporter-1.1.0-py3-none-any.whl"
BENIGN_WHEEL = HERE / "built_wheels" / "benign" / "data_exporter-1.1.0-py3-none-any.whl"
REAL_MANIFEST = HERE / "manifest.json"

sys.path.insert(0, str(HERE))
import attacker_server  # noqa: E402

SERVICES = [("resource_service/app.py", 5002), ("processing_service/app.py", 5003), ("app_api/app.py", 5001)]
API = "http://127.0.0.1:5001"


def _port_up(port):
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def sha256_of(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def step1_approve_malicious_as_trusted():
    print("\n--- Step 1: a compromised update gets approved ---\n")
    real_manifest = json.loads(REAL_MANIFEST.read_text())
    malicious_hash = sha256_of(MALICIOUS_WHEEL)

    compromised_manifest = json.loads(json.dumps(real_manifest))  # deep copy
    compromised_manifest["approved"]["data_exporter"]["sha256"] = malicious_hash
    compromised_manifest["approved"]["data_exporter"]["source"] = (
        "EXPERIMENT B FIXTURE ONLY - malicious build mistakenly approved to model a "
        "compromised supplier release. Never written to the real manifest.json."
    )

    scratch_manifest = Path(tempfile.mkdtemp(prefix="compromised_manifest_")) / "manifest.json"
    scratch_manifest.write_text(json.dumps(compromised_manifest, indent=2))

    print(f"Scratch manifest (NOT the real supply_chain/manifest.json): {scratch_manifest}")
    print(f"Its 'data_exporter' entry now trusts the malicious build's hash: {malicious_hash}")

    result = subprocess.run([sys.executable, str(HERE / "verify_and_install.py"),
                              str(MALICIOUS_WHEEL), "--manifest", str(scratch_manifest), "--no-install"])
    if result.returncode != 0:
        print("\nEXPERIMENT B FAILED: the scratch manifest should have approved this build.")
        sys.exit(1)
    print("\nUnder this compromised-but-approved manifest, the gate now says APPROVED.")
    print("This models the premise of Experiment B: the hash check alone cannot help once")
    print("the trusted entry itself has been poisoned. Everything from here on tests whether")
    print("a SEPARATE, runtime control still contains the damage.")


def step2_install_malicious():
    print("\n--- Step 2: install the (now 'approved') malicious build for real ---\n")
    subprocess.run([sys.executable, "-m", "pip", "install", "--force-reinstall", "--no-deps", str(MALICIOUS_WHEEL)],
                   check=True)


def step3_reset_database():
    print("\n--- Step 3: reset and seed the real resource_service database ---\n")
    subprocess.run([sys.executable, "resource_service/database.py"], cwd=str(ROOT), check=True)


def step4_start_services():
    print("\n--- Step 4: start the three services for real (cwd = project root) ---\n")
    busy = [p for _, p in SERVICES if _port_up(p)]
    if busy:
        print(f"ERROR: ports {busy} already in use - stop any running services first.")
        sys.exit(1)
    env = dict(os.environ)
    env.setdefault("JWT_SECRET", "local-experiment-only-secret")
    procs = [subprocess.Popen([sys.executable, s], cwd=str(ROOT), env=env,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
             for s, _ in SERVICES]
    deadline = time.time() + 20
    while time.time() < deadline and not all(_port_up(p) for _, p in SERVICES):
        time.sleep(0.3)
    if not all(_port_up(p) for _, p in SERVICES):
        print("ERROR: services did not come up in time.")
        for p in procs:
            p.terminate()
        sys.exit(1)
    print("All three services are up.")
    return procs


def step5_run_real_export():
    print("\n--- Step 5/6: Alice logs in and exports HER OWN dataset (normal workflow) ---\n")
    import requests
    r = requests.post(f"{API}/api/auth/login", json={"username": "alice", "password": "AlicePass!123"})
    r.raise_for_status()
    headers = {"Authorization": f"Bearer {r.json()['token']}"}

    r = requests.post(f"{API}/api/export-job", json={"dataset_id": 1}, headers=headers, timeout=10)
    export_ok = r.status_code == 200 and r.json().get("status") == "COMPLETED"
    print(f"Export request status: {r.status_code}, body: {r.text[:200]}")

    export_id = r.json().get("export_id") if export_ok else None
    retrieval_ok = False
    if export_id is not None:
        r2 = requests.get(f"{API}/api/exports/{export_id}", headers=headers, timeout=10)
        retrieval_ok = r2.status_code == 200 and "csv_data" in r2.json()
        print(f"Export retrieval status: {r2.status_code}")

    return export_ok and retrieval_ok


def step7_verdict(benign_workflow_ok):
    print("\n--- Step 7: verdict ---\n")
    time.sleep(0.5)  # let any background exfiltration attempt land
    captured = attacker_server.captured
    if captured:
        print("[RESULT] The attacker's listener received data during Alice's ordinary export request:")
        print(json.dumps(captured, indent=2))
    else:
        print("[RESULT] The attacker's listener received nothing.")

    print(f"[RESULT] Alice's legitimate export completed and was retrievable: {benign_workflow_ok}")

    if captured:
        print("\nVERDICT: COMPROMISED - the malicious build exfiltrated real data during a normal, "
              "fully-authorized request. Approving its digest was enough; nothing at runtime stopped it.")
        return 1
    if not benign_workflow_ok:
        print("\nVERDICT: INCONCLUSIVE - nothing was captured, but the legitimate export itself failed, "
              "so this is not a clean containment result.")
        return 1
    print("\nVERDICT: CONTAINED - even with the malicious build's digest approved and installed, "
          "nothing reached the attacker's listener, and Alice's legitimate export still completed "
          "normally. The runtime isolation around the dependency call is holding this boundary, "
          "independent of the (now-defeated) manifest hash check.")
    return 0


def main():
    print("=" * 70)
    print("EXPERIMENT B - compromised supplier update, approved and run for real")
    print("=" * 70)

    if not MALICIOUS_WHEEL.is_file() or not BENIGN_WHEEL.is_file():
        print("ERROR: expected wheels not found under built_wheels/. See supply_chain/README.md.")
        sys.exit(1)

    step1_approve_malicious_as_trusted()
    step2_install_malicious()

    attacker_server.start_in_background()
    procs = None
    exit_code = 1
    try:
        step3_reset_database()
        procs = step4_start_services()
        benign_workflow_ok = step5_run_real_export()
        exit_code = step7_verdict(benign_workflow_ok)
    finally:
        if procs:
            for p in procs:
                p.terminate()
            for p in procs:
                try:
                    p.wait(5)
                except subprocess.TimeoutExpired:
                    p.kill()
        attacker_server.stop()
        print("\n--- Cleanup: reinstalling the benign build and resetting the database ---")
        subprocess.run([sys.executable, "-m", "pip", "install", "--force-reinstall", "--no-deps", str(BENIGN_WHEEL)],
                       capture_output=True)
        subprocess.run([sys.executable, "resource_service/database.py"], cwd=str(ROOT), capture_output=True)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()

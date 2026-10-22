import os, sys, socket, subprocess, time
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVICES = [("resource_service/app.py", 5002),
            ("processing_service/app.py", 5003),
            ("app_api/app.py", 5001)]

def _up(port):
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0

@pytest.fixture(scope="session", autouse=True)
def services():
    os.environ.setdefault("JWT_SECRET", "local-test-only-secret")
    if os.environ.get("USE_RUNNING_SERVICES"):   # local manual mode
        yield
        return
    busy = [p for _, p in SERVICES if _up(p)]
    if busy:
        pytest.exit(f"Ports {busy} already in use - close other service windows first")
    subprocess.run([sys.executable, "resource_service/database.py"], cwd=ROOT, check=True)
    procs = [subprocess.Popen([sys.executable, s], cwd=ROOT, stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
             for s, _ in SERVICES]
    deadline = time.time() + 20
    while time.time() < deadline and not all(_up(p) for _, p in SERVICES):
        time.sleep(0.3)
    yield
    for p in procs:
        p.terminate()
    for p in procs:
        try: p.wait(5)
        except subprocess.TimeoutExpired: p.kill()
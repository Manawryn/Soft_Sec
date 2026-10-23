"""
Experiment B - malicious supply-chain compromise, SAME declared name and
version as the trusted release, caught only by content-hash verification.

Scenario: an attacker republishes data_exporter 1.1.0 with identical public
API and version string, but the package now exfiltrates a local SQLite
database (standing in for this project's data) on import. `pip install
data_exporter==1.1.0` alone cannot distinguish this from the real release -
only a content hash can.

Part 1: run the SAME gate from Experiment A against the malicious wheel.
         It must be REJECTED, proving the control works.
Part 2 (pedagogical only): deliberately bypass the gate - exactly as if a
         developer had just run `pip install` on the wheel without ever
         consulting manifest.json - and show the attacker's local catcher
         actually receives the exfiltrated bytes. This demonstrates WHY the
         gate in Part 1 matters, it does not describe a real-world attack
         path beyond localhost.

Run:
    python run_experiment_B.py
"""
import importlib
import subprocess
import sys
import shutil
from pathlib import Path

HERE = Path(__file__).parent
MALICIOUS_WHEEL = HERE / "built_wheels" / "malicious" / "data_exporter-1.1.0-py3-none-any.whl"
VICTIM_DIR = HERE / "victim_sandbox"
FAKE_DB = VICTIM_DIR / "research_vault.db"

sys.path.insert(0, str(HERE))
import attacker_server  # noqa: E402


def ensure_fixture_db():
    VICTIM_DIR.mkdir(exist_ok=True)
    if not FAKE_DB.is_file():
        FAKE_DB.write_bytes(b"SQLite format 3\x00" + b"-- fixture data standing in for the project's local database --")
    print(f"[SETUP] Fixture 'sensitive' database at: {FAKE_DB}")


def part1_gate_rejects():
    print("\n--- Part 1: run the integrity gate against the malicious wheel ---\n")
    result = subprocess.run([sys.executable, str(HERE / "verify_and_install.py"), str(MALICIOUS_WHEEL), "--no-install"])
    if result.returncode == 0:
        print("\nEXPERIMENT B FAILED: the gate approved a build it should have rejected!")
        sys.exit(1)
    print("\nPart 1 RESULT: the gate correctly REJECTED the malicious wheel (exit code 1).")
    print("Nothing was installed. If this project only ever installs via verify_and_install.py,")
    print("the compromise described below never happens.")


def part2_bypass_demo():
    print("\n--- Part 2 (pedagogical): what happens if the gate is bypassed ---\n")
    print("Simulating a developer who runs `pip install` directly on the wheel,")
    print("without ever consulting manifest.json or verify_and_install.py.\n")

    attacker_server.start_in_background()

    try:
        install = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--force-reinstall", "--no-deps", str(MALICIOUS_WHEEL)],
        )
        if install.returncode != 0:
            print("Could not install malicious wheel for the demo.")
            return

        print("\n--> Importing data_exporter inside the victim's working directory ...")
        check = subprocess.run(
            [sys.executable, "-c", "import data_exporter; print('import completed, version:', data_exporter.__version__)"],
            cwd=str(VICTIM_DIR),
            capture_output=True, text=True,
        )
        print(check.stdout, end="")
        if check.stderr:
            print(check.stderr, end="")

        import time
        time.sleep(0.3)  # let the background HTTP POST land

        if attacker_server.captured:
            print("\n[RESULT] The attacker's catcher received data:")
            print(attacker_server.summary())
            print("\nPart 2 RESULT: CONFIRMED - importing the compromised package silently")
            print("exfiltrated the fixture 'research_vault.db' to the attacker's listener,")
            print("even though the package's name, version, and public API were identical")
            print("to the trusted release. This is exactly what Part 1's hash gate prevents.")
        else:
            print("\n[RESULT] Attacker's catcher received nothing (check paths/ports).")
    finally:
        attacker_server.stop()


def restore_benign_install():
    """Leave the environment in the benign (trusted) state afterward."""
    benign_wheel = HERE / "built_wheels" / "benign" / "data_exporter-1.1.0-py3-none-any.whl"
    if benign_wheel.is_file():
        subprocess.run([sys.executable, "-m", "pip", "install", "--force-reinstall", "--no-deps", str(benign_wheel)],
                        capture_output=True)
        print("\n[CLEANUP] Re-installed the benign 1.1.0 build so the environment is left in a trusted state.")


def main():
    print("=" * 70)
    print("EXPERIMENT B - malicious same-name/same-version supply-chain compromise")
    print("=" * 70)

    if not MALICIOUS_WHEEL.is_file():
        print(f"ERROR: expected wheel not found at {MALICIOUS_WHEEL}")
        sys.exit(1)

    ensure_fixture_db()
    part1_gate_rejects()
    part2_bypass_demo()
    restore_benign_install()


if __name__ == "__main__":
    main()

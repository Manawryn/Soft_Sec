"""
Experiment A - consumer-controlled manifest with content-hash verification.

Per the assignment spec: store the approved package's name, source,
version and content digest (SHA-256) in a manifest controlled by the
consumer (this project), not the supplier. The build/install phase must
verify a package against this manifest before installing it. Then replace
the supplier artifact with different bytes while keeping its declared
identity/version unchanged, and demonstrate that the integrity gate blocks
its use - while the legitimate build still installs normally.

Both cases below use data_exporter==1.1.0:
  - the BENIGN build is the one actually recorded in manifest.json.
  - the MALICIOUS build declares the exact same name and version, but its
    bytes (and therefore its SHA-256) differ - exactly the "different
    bytes, unchanged identity" tamper the spec describes.

Run:
    python run_experiment_A.py
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
BENIGN_WHEEL = HERE / "built_wheels" / "benign" / "data_exporter-1.1.0-py3-none-any.whl"
MALICIOUS_WHEEL = HERE / "built_wheels" / "malicious" / "data_exporter-1.1.0-py3-none-any.whl"


def run_gate(wheel, install):
    args = [sys.executable, str(HERE / "verify_and_install.py"), str(wheel)]
    if not install:
        args.append("--no-install")
    return subprocess.run(args).returncode


def main():
    print("=" * 70)
    print("EXPERIMENT A - consumer-controlled manifest, content-hash verification")
    print("=" * 70)

    for wheel in (BENIGN_WHEEL, MALICIOUS_WHEEL):
        if not wheel.is_file():
            print(f"ERROR: expected wheel not found at {wheel}")
            sys.exit(1)

    print("\n--> Case 1: the approved build installs normally\n")
    rc = run_gate(BENIGN_WHEEL, install=True)
    if rc != 0:
        print("\nEXPERIMENT A FAILED: the gate rejected the build it should have approved.")
        sys.exit(1)

    check = subprocess.run(
        [sys.executable, "-c",
         "import data_exporter; print('version:', data_exporter.__version__); "
         "print(data_exporter.summarize_metrics('demo', [3, 7, 9, 12]))"],
        capture_output=True, text=True,
    )
    print(check.stdout, end="")
    if check.returncode != 0:
        print(check.stderr)
        print("\nEXPERIMENT A FAILED: the installed package did not import/run correctly.")
        sys.exit(1)

    print("\n--> Case 2: same declared name and version, different bytes -> blocked\n")
    print(f"{BENIGN_WHEEL.name} and {MALICIOUS_WHEEL.name} declare the identical package")
    print("name and version (data_exporter 1.1.0). Only their content hash differs.\n")
    rc = run_gate(MALICIOUS_WHEEL, install=False)
    if rc == 0:
        print("\nEXPERIMENT A FAILED: the gate approved a build it should have rejected.")
        sys.exit(1)

    print("\nEXPERIMENT A RESULT: PASS")
    print("The manifest's SHA-256 pin, not the package's name or version string, is what the")
    print("gate actually trusts. The genuinely approved build installs and runs normally")
    print("(Case 1); a same-identity build with different bytes is rejected outright (Case 2),")
    print("which a plain `pip install data_exporter==1.1.0` version pin would not have caught.")


if __name__ == "__main__":
    main()

"""
verify_and_install.py - the supply-chain integrity gate (SSDLC_PLAN.md TH-05 / Boundary B4).

Usage:
    python verify_and_install.py <path_to_wheel> [--package-name data_exporter] [--manifest manifest.json]

What it does:
    1. Reads manifest.json, which holds the SHA-256 digest of the ONLY wheel
       build the project trusts for a given package name.
    2. Computes the SHA-256 of the wheel file actually handed to it.
    3. Compares the two digests (NOT the filename, NOT the declared version
       inside the wheel's metadata - both of those can be, and in Experiment B
       are, forged to look identical to the real release).
    4. On a match: proceeds to `pip install` the wheel and exits 0.
    5. On a mismatch: refuses to install anything and exits 1 with a clear,
       actionable error.

This is the control. Experiment A proves it lets a legitimate version bump
through. Experiment B proves it blocks a same-name/same-version compromised
build that `pip install data_exporter==1.1.0` alone would happily accept.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Verify a wheel's content hash against the consumer-controlled manifest before installing it.")
    parser.add_argument("wheel_path", help="Path to the .whl file to verify and (if approved) install.")
    parser.add_argument("--package-name", default="data_exporter", help="Key to look up in the manifest's 'approved' map (default: data_exporter).")
    parser.add_argument("--manifest", default=str(Path(__file__).parent / "manifest.json"), help="Path to the manifest file.")
    parser.add_argument("--no-install", action="store_true", help="Only verify, do not actually run pip install (used by Experiment B's demonstration path).")
    args = parser.parse_args()

    wheel_path = Path(args.wheel_path)
    manifest_path = Path(args.manifest)

    if not wheel_path.is_file():
        print(f"[GATE] ERROR: wheel not found: {wheel_path}", file=sys.stderr)
        sys.exit(2)

    manifest = json.loads(manifest_path.read_text())
    approved = manifest.get("approved", {}).get(args.package_name)
    if approved is None:
        print(f"[GATE] ERROR: no approved entry for package '{args.package_name}' in {manifest_path}", file=sys.stderr)
        sys.exit(2)

    actual_hash = sha256_of(wheel_path)
    expected_hash = approved["sha256"]

    print(f"[GATE] Package:        {args.package_name}")
    print(f"[GATE] Wheel file:     {wheel_path.name}")
    print(f"[GATE] Declared version in manifest: {approved['version']}")
    print(f"[GATE] Expected SHA-256 (manifest):  {expected_hash}")
    print(f"[GATE] Actual   SHA-256 (this file): {actual_hash}")

    if actual_hash != expected_hash:
        print("[GATE] RESULT: REJECTED - content hash does not match the approved build.")
        print("[GATE] This wheel's filename and declared version look identical to the")
        print("[GATE] trusted release, but its CONTENTS differ. Version pinning alone")
        print("[GATE] (e.g. data_exporter==1.1.0) would NOT have caught this. Refusing")
        print("[GATE] to install. Treat this artifact as a potential supply-chain compromise.")
        sys.exit(1)

    print("[GATE] RESULT: APPROVED - content hash matches the trusted build exactly.")

    if args.no_install:
        print("[GATE] --no-install set: skipping the actual pip install step.")
        sys.exit(0)

    print(f"[GATE] Installing {wheel_path.name} ...")
    result = subprocess.run([sys.executable, "-m", "pip", "install", "--force-reinstall", "--no-deps", str(wheel_path)])
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()

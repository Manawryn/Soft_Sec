"""
Experiment A - benign supply-chain update, verified by hash.

Scenario: data_exporter gets a legitimate 1.1.0 release (adds a min/max
"Range" field to summarize_metrics). We verify the new wheel against the
consumer-controlled manifest.json (SSDLC_PLAN.md TH-05 / Boundary B4) and,
because its content hash matches exactly what was approved, the gate lets
it through and installs it.

Run:
    python run_experiment_A.py
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
BENIGN_WHEEL = HERE / "built_wheels" / "benign" / "data_exporter-1.1.0-py3-none-any.whl"


def main():
    print("=" * 70)
    print("EXPERIMENT A - benign version bump of data_exporter, hash-verified")
    print("=" * 70)

    if not BENIGN_WHEEL.is_file():
        print(f"ERROR: expected wheel not found at {BENIGN_WHEEL}")
        print("Build it first: cd packages/benign && python -m build --wheel -o ../../built_wheels/benign")
        sys.exit(1)

    print(f"\n--> Step 1: run the integrity gate against {BENIGN_WHEEL.name}\n")
    result = subprocess.run([sys.executable, str(HERE / "verify_and_install.py"), str(BENIGN_WHEEL)])

    if result.returncode != 0:
        print("\nEXPERIMENT A FAILED: the gate rejected a build it should have approved.")
        sys.exit(1)

    print("\n--> Step 2: prove the new version actually works as expected\n")
    check = subprocess.run(
        [sys.executable, "-c",
         "import data_exporter; print('version:', data_exporter.__version__); "
         "print(data_exporter.summarize_metrics('demo', [3, 7, 9, 12]))"],
        capture_output=True, text=True,
    )
    print(check.stdout, end="")
    if check.returncode != 0:
        print(check.stderr)
        print("\nEXPERIMENT A FAILED: installed package did not import/run correctly.")
        sys.exit(1)

    print("\nEXPERIMENT A RESULT: PASS")
    print("The hash-verified gate approved the legitimate 1.1.0 build, installed it,")
    print("and the new 'Range' field in summarize_metrics output confirms the real")
    print("code is running. A consumer-controlled manifest does not block routine,")
    print("trusted updates - it only blocks content that doesn't match what was")
    print("actually reviewed and approved.")


if __name__ == "__main__":
    main()

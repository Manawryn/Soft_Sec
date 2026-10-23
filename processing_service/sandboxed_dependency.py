"""
sandboxed_dependency.py - runtime enforcement of Boundary B4 (SSDLC_PLAN.md).

docs/SSDLC_PLAN.md already documents the intended property of this
boundary: "External dependency must execute only pure deterministic
transformations without disk persistence or arbitrary network egress."
supply_chain/verify_and_install.py enforces half of that - it stops an
unapproved build from ever being installed. But it only checks WHAT was
installed, not WHAT IT DOES once it's running. If a compromised build's
digest is ever mistakenly approved (Experiment B's scenario: a supplier
account or build pipeline compromise that gets accepted as a legitimate
update), the hash check no longer helps - the "trusted" build itself is
now malicious.

This module is the second, independent control: every call into the
data_exporter dependency runs in a short-lived child process whose
working directory is an empty, throwaway folder (so a relative file search
from "." cannot reach any real project file, including the Resource
Service's research_vault.db) and whose outbound sockets are disabled
before the dependency's own code ever executes. The dependency's
documented contract is pure, in-memory computation with no need for disk
or network access at all, so this is a least-privilege default for that
boundary - not a workaround aimed at one specific attack signature.

A call that cannot complete under these restrictions (because the
dependency tried to reach a file or the network) raises a RuntimeError,
which the caller must treat as an export failure, not something to
silently ignore.
"""
import json
import os
import subprocess
import sys
import tempfile

_WORKER_SOURCE = r"""
import json, socket, sys

def _blocked(*args, **kwargs):
    raise RuntimeError("network access is disabled inside the dependency sandbox (Boundary B4)")

socket.socket.connect = _blocked
socket.create_connection = _blocked

import data_exporter

call = json.loads(sys.stdin.read())
func, kwargs = call["func"], call["kwargs"]
try:
    if func == "summarize_metrics":
        result = data_exporter.summarize_metrics(kwargs["title"], kwargs["values"])
    elif func == "format_record_to_csv":
        result = data_exporter.format_record_to_csv(kwargs["record"])
    else:
        raise ValueError("unknown function: " + func)
    print(json.dumps({"ok": True, "result": result}))
except Exception as e:
    print(json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}))
"""


def call_sandboxed(func, timeout=10, **kwargs):
    """Run a data_exporter function in an isolated child process: no access
    to any real project file (empty cwd), no outbound network. Raises
    RuntimeError if the call did not complete cleanly inside the sandbox."""
    sandbox_dir = tempfile.mkdtemp(prefix="data_exporter_sandbox_")
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _WORKER_SOURCE],
            input=json.dumps({"func": func, "kwargs": kwargs}),
            capture_output=True, text=True, cwd=sandbox_dir, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Sandboxed dependency call timed out.")
    finally:
        try:
            os.rmdir(sandbox_dir)
        except OSError:
            pass  # non-empty (dependency wrote something it shouldn't have) - leave it for inspection

    if proc.returncode != 0:
        raise RuntimeError(f"Sandboxed dependency call crashed: {proc.stderr.strip()[-500:]}")

    lines = [l for l in proc.stdout.strip().splitlines() if l.strip()]
    if not lines:
        raise RuntimeError(f"Sandboxed dependency call produced no result (stderr: {proc.stderr.strip()[-300:]})")

    try:
        payload = json.loads(lines[-1])
    except ValueError:
        raise RuntimeError(f"Sandboxed dependency call produced malformed output: {lines[-1][:300]}")

    if not payload.get("ok"):
        raise RuntimeError(f"Sandboxed dependency call failed: {payload.get('error')}")
    return payload["result"]

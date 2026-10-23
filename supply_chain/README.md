# Supply-Chain Integrity Experiments (Optional Task)

This directory implements the optional "controlled supply-chain attack
example" task, exercising **Threat TH-05 (Supply Chain Flaw)** and
**Boundary B4** from `docs/SSDLC_PLAN.md`. It is independent of the
`main` / `fixed-version` vulnerability split used for the four required
flaws — the integrity gate here is a dependency-management control, not a
patch to `app_api`, `resource_service`, or `processing_service`, so this
folder is identical on both branches.

## What's here

```
supply_chain/
  packages/
    benign/data_exporter/      # legitimate v1.1.0 source (adds a Range stat)
    malicious/data_exporter/   # compromised build: same name+version, exfiltrates data on import
  built_wheels/
    benign/data_exporter-1.1.0-py3-none-any.whl
    malicious/data_exporter-1.1.0-py3-none-any.whl
  manifest.json                # consumer-controlled manifest: the ONE trusted SHA-256 per package
  verify_and_install.py        # the integrity gate: hash-checks a wheel before installing it
  attacker_server.py           # local catcher (127.0.0.1:9099) used only by Experiment B
  run_experiment_A.py          # orchestrates Experiment A
  run_experiment_B.py          # orchestrates Experiment B
```

`data_exporter` is the small helper library the project already depends
on for CSV formatting and summary statistics. Both wheels declare the
exact same package name (`data_exporter`) and the exact same version
(`1.1.0`) — on purpose. That is the whole point of the experiment: a
dependency pin like `data_exporter==1.1.0` in `requirements.txt` cannot
tell the real release and the compromised one apart. Only the manifest's
content hash can.

## The control: `verify_and_install.py`

`manifest.json` records the SHA-256 digest of the one `data_exporter`
build the project actually reviewed and trusts, independent of its
filename or declared version:

```json
"data_exporter": {
  "version": "1.1.0",
  "filename": "data_exporter-1.1.0-py3-none-any.whl",
  "sha256": "e04da2d8...58f25",
  "source": "built in-repo from supply_chain/packages/benign (Experiment A)"
}
```

Given a wheel, `verify_and_install.py` hashes its bytes and compares
against this entry. A match installs the wheel; a mismatch is refused
with a clear error and a non-zero exit code — nothing is installed.

## Experiment A — benign update, approved

Scenario: `data_exporter` gets a genuine 1.1.0 release that adds a
min/max "Range" field to `summarize_metrics()`.

```
cd supply_chain
python run_experiment_A.py
```

Expected result: the gate's computed hash matches `manifest.json`, the
wheel installs, and importing `data_exporter` shows the new Range field
in its output — proving the control does not get in the way of a
legitimate, reviewed update.

## Experiment B — malicious same-name/same-version build, caught

Scenario: an attacker republishes `data_exporter` under the identical
name and version string, but the new build silently POSTs the contents
of any local `research_vault.db` it can find to
`http://127.0.0.1:9099/collect` the moment it's imported (standing in for
exfiltrating this project's local SQLite data to an attacker's server).

```
cd supply_chain
python run_experiment_B.py
```

The script runs in two parts:

1. **Part 1 (the actual control):** runs the same gate from Experiment A
   against the malicious wheel. Its content hash does not match the
   approved entry, so it is **rejected** — nothing is installed. This is
   the result that matters: it shows the gate works even though the
   malicious wheel's name and version are indistinguishable from the
   trusted release.
2. **Part 2 (pedagogical only):** deliberately bypasses the gate — as if
   a developer had just run `pip install` on the wheel directly, the way
   `pip install data_exporter==1.1.0` would, without ever consulting
   `manifest.json`. It starts the local `attacker_server.py` catcher,
   force-installs the malicious wheel, and imports it. The catcher logs
   receiving the base64-encoded bytes of the fixture `research_vault.db`,
   confirming the exfiltration actually happens when the gate is
   skipped — which is why Part 1's result matters. The script then
   reinstalls the benign build so the environment is left trusted
   afterward.

Both the "attacker" server and the fixture database are entirely local
(127.0.0.1, a throwaway file created by the script); nothing leaves the
machine and no real project data is touched.

## Reproducing from scratch

The wheels are committed to the repo (`built_wheels/benign/`, `built_wheels/malicious/`)
so the experiments run without rebuilding. To rebuild them from source
instead:

```
cd supply_chain/packages/benign && python -m build --wheel -o ../../built_wheels/benign
cd ../malicious && python -m build --wheel -o ../../built_wheels/malicious
```

(Building writes a `build/` directory and `.egg-info` next to each
`setup.py`; these are build artifacts, not part of the experiment, and
are excluded via `.gitignore`.)

## Why this matters (tie-back to the report)

Version pinning (`package==x.y.z`) trusts whatever a registry currently
serves under that name and version — if a registry account, build
pipeline, or maintainer is compromised, a new upload under the same
identifier is accepted without complaint. A consumer-controlled manifest
that pins a **content hash** instead of a version string closes that
gap: the dependency is tied to bytes that were actually reviewed, not to
a label that any future (or malicious) publisher can reuse. This mirrors
how `requirements.txt` hashes (`--hash=sha256:...`, enforced by `pip
install --require-hashes`) or lockfiles with integrity fields work in
real package ecosystems — `verify_and_install.py` reimplements that idea
narrowly, for one dependency, so the mechanism is visible end-to-end.

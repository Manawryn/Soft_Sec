# Supply-Chain Integrity Experiments (Optional Task)

This directory implements the "Controlled supply chain attack," "Experiment
A," and "Experiment B" optional tasks, exercising **Threat TH-05 (Supply
Chain Flaw)** and **Boundary B4** from `docs/SSDLC_PLAN.md`. These are
listed as three separately-optional items in the assignment; this repo
attempts all three.

Most of this directory is identical on both branches (it's a
dependency-management control, not one of the four planted vulnerabilities).
The one thing that *does* differ per branch is how `processing_service`
calls the dependency - see "Experiment B" below.

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
  attacker_server.py           # local catcher (127.0.0.1:9099) used by Experiment B
  run_experiment_A.py          # Experiment A: manifest + hash gate
  run_experiment_B.py          # Experiment B: approved-but-malicious build, run for real
```

`data_exporter` is the small helper library `processing_service` already
depends on for CSV formatting and summary statistics (see
`external_pkg/`, used in `processing_service/app.py`). Both wheels here
declare the exact same package name (`data_exporter`) and the exact same
version (`1.1.0`) - on purpose, per the assignment's "Controlled supply
chain attack" requirement: the malicious code must enter through the
package's install/build path, not by editing `processing_service`'s own
code, and it must preserve the package's normal functionality while also
trying to access something it shouldn't.

The malicious build's payload (`packages/malicious/data_exporter/__init__.py`)
does a recursive search from its current working directory for a file
named `research_vault.db` - which is the Resource Service's actual
database filename (`resource_service/database.py`) - and, if found, POSTs
its bytes, base64-encoded, to `http://127.0.0.1:9099/collect`.

## Experiment A — manifest + content-hash gate

`manifest.json` is the consumer-controlled manifest: it pins the SHA-256
digest of the one `data_exporter` build this project actually trusts,
independent of its declared name/version. `verify_and_install.py` hashes
a wheel and compares it against that entry before installing anything.

```
cd supply_chain
python run_experiment_A.py
```

Two cases, both against the same manifest:
1. The genuinely approved build (`built_wheels/benign/...`) is verified,
   installed, and its new "Range" output is shown working.
2. `built_wheels/malicious/...` declares the *identical* name and version,
   but its bytes (and hash) differ. The gate rejects it outright - proving
   that `data_exporter==1.1.0` as a version pin alone would not have
   caught this, but the manifest's content hash does.

## Experiment B — a compromised update gets approved, and runs for real

This is the harder case the assignment asks for: what if the malicious
digest itself gets approved as a trusted update (a compromised supplier
account or build pipeline whose release is accepted)? At that point the
hash check in Experiment A no longer helps, because the "trusted" entry is
now the malicious one. Experiment B needs a *different* kind of control -
the assignment explicitly says checking only the filename or version
(and, by the same logic, only a hash that has itself been poisoned) is
not a sufficient runtime defence.

```
cd supply_chain
python run_experiment_B.py
```

What it actually does, step by step:
1. Writes a **scratch** manifest (never the real `manifest.json`) that
   approves the malicious wheel's SHA-256 under `data_exporter` - modelling
   "this update got accepted" - and shows the gate now says APPROVED
   under that manifest.
2. Installs the malicious wheel for real.
3. Resets and seeds the real `resource_service/research_vault.db`.
4. Starts all three services exactly as `run_all.sh`/`run_all.bat` do -
   same ports, same working directory.
5. Starts the local attacker listener.
6. Logs in as Alice and makes **one ordinary, fully-authorized** export
   request for her own dataset through the real HTTP API - not a staged
   bypass of anything.
7. Checks whether the attacker's listener received the real database file,
   and whether Alice's export still completed and was retrievable.

**On `main`**: `processing_service/app.py` calls `data_exporter` directly,
in its own process, with its own working directory and network access.
The malicious package's search finds the real `research_vault.db` (its cwd
is the project root, same as `resource_service/`) and exfiltrates it the
moment the service starts - before any request is even made. Verdict:
**COMPROMISED**.

**On `fixed-version`**: every call into `data_exporter` goes through
`processing_service/sandboxed_dependency.py`, which runs the dependency in
a short-lived child process whose working directory is an empty, throwaway
folder and whose outbound sockets are disabled *before the dependency's
own code ever executes*. The malicious code still runs - it just has
nothing to find and nowhere to send it. Alice's legitimate export still
completes normally, because the library's real job (formatting numbers
into text) needs neither disk nor network. Verdict: **CONTAINED**.

This is an actual runtime isolation control, independent of the manifest
hash check - exactly the "actual authorization, isolation, or
output-validation" the assignment asks for, not a second identity check.

## Reproducing the wheels from scratch

The wheels are committed (`built_wheels/benign/`, `built_wheels/malicious/`)
so the experiments run without rebuilding. To rebuild them:

```
cd supply_chain/packages/benign && python -m build --wheel -o ../../built_wheels/benign
cd ../malicious && python -m build --wheel -o ../../built_wheels/malicious
```

## Why this matters (tie-back to the report)

Version pinning (`package==x.y.z`) trusts whatever a registry currently
serves under that name and version. A consumer-controlled manifest that
pins a **content hash** instead closes that gap for a bytes-swapped
artifact (Experiment A) - but it is still only as good as the review
behind each approval. If a malicious release is ever mistakenly approved
(Experiment B), the only thing left standing between it and the data it
wants is what the *consuming* component lets it touch at runtime. That is
why Boundary B4 in `docs/SSDLC_PLAN.md` is enforced twice here: once at
install time (the manifest + hash gate), and once at call time (the
dependency sandbox) - two independent layers, so a failure of one doesn't
mean a failure of both.

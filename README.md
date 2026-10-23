# Soft_Sec: Multi-Tier Research Data Export Workspace

Software Security, Assignment I. A small multi-tier application that protects
private research datasets owned by different users, built to study how
authorization breaks across component boundaries.

| Branch | Purpose | Expected pipeline result |
| :--- | :--- | :--- |
| `main` | Vulnerable baseline with 4 intentionally planted flaws | **Red**: 7/14 tests fail, security gate reports 8 Bandit findings |
| `fixed-version` | Same application with all 4 flaws remediated | **Green**: 14/14 tests pass, gate passes |

> `main` is deliberately insecure. Never deploy it.

## 1. Architecture

Three components run as **separate processes** and talk over HTTP. The helper
package `data_exporter` is installed as a dependency, not copied into a service.

```text
 Client (alice / bob / admin)
        |  HTTP + JWT
        v
 +--------------------+      +----------------------+
 | Application API    |----->| Processing Service   |
 | port 5001          |      | port 5003            |
 | login, JWT, routing|      | export job           |
 +--------------------+      | uses data_exporter   |
        |                    +----------------------+
        |                              |
        v                              v
 +-----------------------------------------------+
 | Resource Service, port 5002                   |
 | owns users, datasets, quota (SQLite)          |
 +-----------------------------------------------+
```

| Component | Folder | Responsibility |
| :--- | :--- | :--- |
| Application API | `app_api/` | Authenticates users, issues JWTs, coordinates requests |
| Resource Service | `resource_service/` | Owns protected records, password hashes and quota |
| Processing Service | `processing_service/` | Runs export jobs using the external package |
| External package | `external_pkg/` | `data_exporter`: CSV formatting and metric summary |

### Operations

| ID | Operation | Components involved |
| :--- | :--- | :--- |
| OP-1 | Login and token issuance | API, Resource |
| OP-2 | Dataset search and retrieval | API, Resource |
| OP-3 | Export quota consumption | API, Resource |
| OP-4 | Export job | API, Processing, Resource (all three) |

Full design documentation is in [`docs/SSDLC_PLAN.md`](docs/SSDLC_PLAN.md):
asset register, trust boundaries, access-control matrix, STRIDE threat model
and the lifecycle gate matrix. It was committed before any feature code.

## 2. Seeded data (synthetic)

| User | Password | Role | Owns |
| :--- | :--- | :--- | :--- |
| `admin` | `AdminSecret!2026` | admin | none |
| `alice` | `AlicePass!123` | researcher | dataset 1 |
| `bob` | `BobPass!456` | researcher | dataset 2 |

Passwords are stored as salted hashes. Seeding drops and recreates the tables,
so IDs always start at 1.

## 3. Planted vulnerabilities (present on `main`, fixed on `fixed-version`)

| ID | Class | Component | CWE | Test |
| :--- | :--- | :--- | :--- | :--- |
| TH-01 | Trust failure: SQL injection | Resource Service `/resources/search` | CWE-89 | `test_th01_sql_injection_neutralised` |
| TH-02 | Authority failure: IDOR | API and Resource dataset read | CWE-639 | `test_th02_idor_blocked` |
| TH-03 | State failure: quota race condition | Resource Service `/resources/quota/consume` | CWE-362 | `test_th03_quota_race_blocked` |
| TH-04 | Composition flaw: confused deputy | Processing Service to Resource Service | CWE-441 | `test_th04_confused_deputy_blocked` |

A hardcoded JWT secret and a hardcoded internal service key (CWE-798) are also
present on `main` and are caught by static analysis.

TH-04 is the composition flaw: each service looks correct alone, but the
Resource Service trusts any call carrying the Processing Service's static
internal key, so Alice can export Bob's dataset through the pipeline.

## 4. Prerequisites

- Python 3 on `PATH` (developed and tested on Windows with Python 3.14)
- Git
- Free local ports **5001, 5002, 5003**

## 5. Build, seed, run, test

All commands run from the repository root.

### Build

Windows (PowerShell):

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install -e external_pkg
```

Linux / macOS (bash):

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install -e external_pkg
```

### Seed the database

Windows: `python resource_service\database.py`
Linux / macOS: `python resource_service/database.py`

### Run the three services

Windows:

```powershell
.\run_all.bat
```

Linux / macOS:

```bash
chmod +x run_all.sh   # only needed if the executable bit was lost
./run_all.sh
```

On Windows this opens three windows (Resource 5002, Processing 5003, API 5001).
On Linux / macOS the three services run as background processes of one
terminal, and Ctrl+C stops all of them. Both launchers also install
dependencies and seed the database.

On `fixed-version` the services require the `JWT_SECRET` environment variable
and refuse to start without it. Both launchers set a local development value
if none is defined. To use your own:

```powershell
$env:JWT_SECRET = "your-secret"      # PowerShell
```

```bash
export JWT_SECRET="your-secret"      # bash
```

Use a different secret for anything beyond local testing.

Quick check that the stack is up (Linux / macOS):

```bash
curl -X POST http://127.0.0.1:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"AlicePass!123"}'
```

### Test

Close any `run_all.bat` windows first. The test suite starts and stops its own
services and aborts if ports 5001-5003 are busy.

```powershell
python -m pytest -v
```

| Branch | Expected result |
| :--- | :--- |
| `main` | 7 passed, 7 failed |
| `fixed-version` | 14 passed |

The suite contains functional tests (login, owner and admin read, owner
export), the four STRIDE/TH-01–TH-04 security tests, three additional
authorization tests (TH-05 authenticated-quota, TH-06 search filtered by
ownership, export retrieval blocked for non-owner), and three
malformed-input tests (missing token, tampered token, missing payload).

### Static analysis and dependency audit

```powershell
mkdir reports
python -m bandit -r app_api resource_service processing_service -f json -o reports\bandit_report.json
python ci\security_gate.py
python -m pip_audit --local
```

| Branch | `security_gate.py` result |
| :--- | :--- |
| `main` | `GATE FAILED: 8 blocking finding(s)` (B608, 4 x B113, 3 x B105) |
| `fixed-version` | `GATE PASSED` |

The gate blocks on any MEDIUM or HIGH finding and on any hardcoded-credential
finding (B105, B106, B107). It does not rely on Bandit's HIGH count, because
Bandit rates these flaws MEDIUM and LOW.

## 6. CI/CD with Jenkins

The pipeline is defined in [`Jenkinsfile`](Jenkinsfile) and is identical on
both branches. Stages:

1. Checkout into a clean workspace
2. Build and install into a fresh virtual environment
3. SAST with Bandit
4. Dependency audit with `pip-audit --local`
5. Functional and authorization tests with pytest
6. Security gate (`ci/security_gate.py`)

Test, audit and scan results are archived as build artifacts
(`reports/*`) and test results are published through JUnit.

### Jenkins setup required to reproduce

The Jenkinsfile alone is not enough. The Jenkins instance needs:

- A **Windows** controller or agent (the pipeline uses `bat`; the Linux launcher is for local use only)
- Python on the `PATH` of the Jenkins service account
- Git installed
- A **Secret text** credential with ID `prod-jwt-secret`
- The standard plugins Pipeline, Git, Credentials Binding and JUnit
- A Pipeline job using *Pipeline script from SCM*, repository URL of this
  repository, script path `Jenkinsfile`, branch specifier `*/main` or
  `*/fixed-version`
- Ports 5001-5003 free on the Jenkins machine while a build runs

### Expected builds

| Branch | Tests | Dependency audit | Gate | Build |
| :--- | :--- | :--- | :--- | :--- |
| `main` | 7 failed, 7 passed | clean | failed | Red |
| `fixed-version` | 14 passed | clean | passed | Green |

Saved results from both builds are in [`evidence/`](evidence/).

### What blocks a release

- Any failing functional, authorization or malformed-input test
- Any Bandit finding of MEDIUM severity or higher, or a hardcoded credential
- Any known vulnerability reported by the dependency audit

## 7. Secure design principles

| Principle | Design decision | Implementation (`fixed-version`) | Evidence |
| :--- | :--- | :--- | :--- |
| Complete mediation | Every resource access is checked at the data owner | Resource Service verifies the caller's token and ownership on each dataset read | `test_th02_idor_blocked`, `test_th04_confused_deputy_blocked` |
| Fail-safe defaults | Missing or invalid credentials are denied | API rejects missing or invalid tokens with 401; services require `JWT_SECRET` and fail at startup without it | `test_missing_token_rejected`, `test_tampered_token_rejected` |
| Least privilege | A downstream service acts only with the caller's authority | Processing Service forwards the caller's token instead of using a privileged internal key | `test_th04_confused_deputy_blocked` |

## 8. Known limitations

- HTTP only, no TLS. Not production-ready (see the report).
- `processing_service/sandboxed_dependency.py` isolates `data_exporter`'s
  working directory and network access (`fixed-version` only — see section
  9), but it is a Python-level restriction, not an OS-level sandbox
  (container, chroot, or seccomp). A dependency with native-extension code
  could bypass it; this is a defense-in-depth measure, not a hard boundary.

On `fixed-version`, job-scoped delegation tokens (short-lived, bound to
`user_id`, `dataset_id`, `action` and `aud`), authenticated/ownership-filtered
search and quota endpoints, and the export save/retrieve flow (export results
are persisted in the Resource Service and fetched back by export ID, matching
the plan in `docs/SSDLC_PLAN.md`) are all implemented — see section 3 above
and the branch diff for `app_api/app.py` / `resource_service/app.py` /
`processing_service/app.py`.

## 9. Optional: controlled supply-chain attack, Experiment A, Experiment B

`supply_chain/` implements and demonstrates the TH-05 / Boundary B4 control
from `docs/SSDLC_PLAN.md` (section 8 there has the full writeup). `data_exporter`
(`external_pkg/`) gets a benign and a malicious fixture build, both declaring
the identical package name and version; the malicious one exfiltrates the
Resource Service's real database on import.

- **Experiment A** (branch-independent) — a consumer-controlled manifest pins
  the approved build's SHA-256. The genuine build installs normally; a
  same-identity build with different bytes is rejected on hash mismatch,
  proving a version pin alone would not have caught it.
- **Experiment B** (where `main` and `fixed-version` diverge) — the malicious
  build's digest gets approved as trusted (a scratch manifest, modelling a
  compromised supplier update that was accepted), installed for real, and run
  through one ordinary, fully-authorized export request. On `main`,
  `processing_service` calls the dependency directly and the real database
  leaks. On `fixed-version`, every call is routed through
  `processing_service/sandboxed_dependency.py` — an isolated child process
  with an empty working directory and no outbound network — so the same
  "approved" malicious build is contained and the legitimate export still
  completes.

```
cd supply_chain
python run_experiment_A.py
python run_experiment_B.py
```

See `supply_chain/README.md` for the full walkthrough and sample output.

## 10. Repository layout

```text
app_api/              Application API (port 5001)
resource_service/     Resource Service and SQLite seeding (port 5002)
processing_service/   Processing Service (port 5003)
external_pkg/         data_exporter helper package (used by the services)
supply_chain/         Optional TH-05 supply-chain integrity experiment
tests/                pytest suite and service-lifecycle fixture
ci/security_gate.py   Release gate over the Bandit report
docs/SSDLC_PLAN.md    Lifecycle plan, threat model, access matrix
evidence/             Saved Jenkins results for each branch
Jenkinsfile           Pipeline definition
run_all.bat           Local launcher for the three services (Windows)
run_all.sh            Local launcher for the three services (Linux / macOS)
```

## 11. AI-use declaration

AI assistants were used for drafting and debugging help. The declaration
required by the course is submitted separately.
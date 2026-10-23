# 🔒 Secure Software Development Lifecycle (SSDLC) Plan
## Research Data Export Workspace — Architecture, Threat Model & Security Gates

**System:** Multi-Tier Research Data Export System  
**Framework Standard:** NIST SP 800-218 (Secure Software Development Framework - SSDF)  
**Lifecycle Approach:** DevSecOps "Shift Left" Engineering  
**Version:** 1.0.0 (Pre-Implementation Baseline)

---

## 1. System Scope & Functional Operations

### 1.1 Purpose
The Research Data Export System provides a distributed workspace where researchers securely manage, analyze, and export scientific datasets. The system strictly isolates proprietary datasets owned by different researchers while providing administrative auditing and automated metric processing via decoupled microservices.

### 1.2 Core Functional Operations
1. **`OP-1: Authentication & Token Issuance`**: Users submit credentials to obtain an identity token (JWT) establishing identity, roles, and validity period.
2. **`OP-2: Dataset Query & Retrieval`**: Authenticated users query dataset records and inspect authorized metadata.
3. **`OP-3: Dataset Version & Quota Management`**: Users perform state-modifying operations (updating metadata or consuming quota allocations).
4. **`OP-4: 3-Tier Asynchronous Export Pipeline`**: A researcher initiates an export job via the Application API. The Processing Service fetches authorized dataset records from the Resource Service, computes summary metrics and tabular exports using an external library dependency, and returns the compiled artifact.

---

## 2. Software Asset Register & Security Objectives

| Asset ID | Asset Name | Description | Sensitivity | Security Objectives (CIA) | Potential Impact of Compromise |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AST-01** | **User Credentials & Password Hashes** | Salted password hashes stored in database. | Restricted | Confidentiality, Integrity | Account takeover, impersonation, unauthorized access. |
| **AST-02** | **Research Datasets** | Raw metrics, sequencing records, and data files owned by researchers. | Confidential | Confidentiality, Integrity | Intellectual property theft, falsification of research data. |
| **AST-03** | **Identity & Authority Tokens (JWT)** | Cryptographically signed bearer tokens carrying claims (`user_id`, `role`, `exp`). | Restricted | Integrity, Confidentiality | Privilege escalation, session hijacking, replay attacks. |
| **AST-04** | **Job Delegation Tokens** | Short-lived, job-scoped authorization tokens binding a specific `dataset_id` and action. | Confidential | Integrity, Non-Repudiation | Confused deputy attacks, unauthorized cross-service reads. |
| **AST-05** | **Audit & Security Event Logs** | Transaction logs recording authentication and export history. | Internal | Integrity, Availability | Repudiation of malicious actions, blind incident response. |

---

## 3. Component Architecture & Trust Boundaries

The system is partitioned into three independent application runtime processes and one external package dependency:

```text
       UNTRUSTED ZONE                │              TRUSTED SERVICE BOUNDARY
                                     │
   ┌───────────────────────┐         │         ┌─────────────────────────────────┐
   │    Client / Actor     │         │         │        Application API          │
   │  (Alice, Bob, Admin)  │──HTTPS──┼────────▶│         (Port 5001)             │
   └───────────────────────┘         │         └─────────────────────────────────┘
                                     │               │                    │
                             [Boundary B1]     [Boundary B2]        [Boundary B3]
                                     │               │                    │
                                     │               ▼                    ▼
                                     │      ┌─────────────────┐  ┌─────────────────┐
                                     │      │Processing Engine│  │Resource Service │
                                     │      │   (Port 5003)   │  │   (Port 5002)   │
                                     │      └─────────────────┘  └─────────────────┘
                                     │               │                    ▲
                                     │         [Boundary B4]              │
                                     │               │──── Job-Scoped ────┘
                                     │               ▼     Auth Flow
                                     │      ┌─────────────────┐
                                     │      │  data_exporter  │
                                     │      │ (External Lib)  │
                                     │      └─────────────────┘
```

### Trust Boundary Definitions

- **Boundary B1 (Internet / Client to Application API):** High-risk ingress. All input from clients is untrusted. Requires complete authentication, rate limiting, and strict input validation.
- **Boundary B2 (Application API to Processing Service):** Internal network call. Application API delegates compute tasks. Must carry job-specific delegation claims rather than ambient authority.
- **Boundary B3 (Application API to Resource Service):** Internal data retrieval boundary. Resource service must verify resource ownership and token signatures independently (Defense in Depth).
- **Boundary B4 (Processing Service to External Package):** Supply chain boundary. External dependency must execute only pure deterministic transformations without disk persistence or arbitrary network egress.

---

## 4. Access Control Matrix (RBAC + ABAC)

The system enforces Role-Based Access Control (RBAC) combined with Attribute-Based Access Control (ABAC) for dataset ownership:

| Subject / Role | auth_login | dataset_search | dataset_read_own | dataset_read_other | dataset_update_quota | export_job_own | export_job_other | view_audit_logs |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Anonymous** | ✅ Permit | ❌ Deny | ❌ Deny | ❌ Deny | ❌ Deny | ❌ Deny | ❌ Deny | ❌ Deny |
| **Researcher (Alice)** | ✅ Permit | ✅ Permit | ✅ Permit (Alice) | ❌ Deny (Bob) | ✅ Permit (Alice) | ✅ Permit (Alice) | ❌ Deny (Bob) | ❌ Deny |
| **Researcher (Bob)** | ✅ Permit | ✅ Permit | ✅ Permit (Bob) | ❌ Deny (Alice) | ✅ Permit (Bob) | ✅ Permit (Bob) | ❌ Deny (Alice) | ❌ Deny |
| **Administrator** | ✅ Permit | ✅ Permit | ✅ Permit | ✅ Permit | ✅ Permit | ✅ Permit | ✅ Permit | ✅ Permit |
| **Processing Service** | ❌ Deny | ❌ Deny | ❌ (Delegated Only) | ❌ Deny | ❌ Deny | ❌ (Job Token Only) | ❌ Deny | ❌ Deny |

---

## 5. Threat Modeling: STRIDE & Attack Surface Analysis

The system attack surface is modeled as $AS = (I \times W)^E$, where interaction entry points ($I$) and weak points ($W$) are mitigated to reduce exploitability ($E$):

| Threat ID | STRIDE Category | Target Component | Threat Description & Attack Scenario | Vulnerability Failure Class | Proposed Mitigation / Security Control |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TH-01** | Tampering / Info Disclosure | Resource Service (`/resources/search`) | Attacker injects SQL fragments into the dataset search parameter to dump all records or bypass filters. | Trust Failure (Input interpreted as code) | Parameterized prepared statements (`sqlite3` `?` placeholders). Prohibit string formatting. |
| **TH-02** | Elevation of Privilege | App API / Resource Service (`/resources/dataset/<id>`) | Authenticated researcher Alice modifies dataset ID in the request path to access Bob's private dataset. | Authority Failure (Authentication implies authorization / IDOR) | Strict ABAC check: verify `dataset.owner_id == caller.user_id` or `caller.role == 'admin'` prior to query return. |
| **TH-03** | Tampering | Resource Service (`/resources/quota/consume`) | Attacker initiates concurrent asynchronous export requests to decrement quota below zero. | State Failure (Unsafe concurrency / Race condition) | Atomic transactions (`BEGIN EXCLUSIVE`) and conditional SQL updates (`WHERE quota >= required`). |
| **TH-04** | Elevation of Privilege | Processing Service ⟷ Resource Service | Confused Deputy: Processing service uses ambient service-to-service trust to read Bob's dataset when executing an export requested by Alice. | Composition Flaw (Cross-boundary authority loss) | Scoped Job Tokens: Application API issues a short-lived token binding `user_id`, `dataset_id`, and `exp`. Resource Service validates token scope before returning records. |
| **TH-05** | Tampering | Processing Service ⟷ Dependency | Supply chain compromise: Malicious package version installed attempting to exfiltrate database records to external hosts. | Supply Chain Flaw (Unverified external artifact) | Consumer-controlled manifest with SHA-256 verification at install time (`supply_chain/verify_and_install.py`), **and** runtime isolation of every dependency call — empty working directory, no outbound network (`processing_service/sandboxed_dependency.py`, `fixed-version` only) — so a mistakenly-approved malicious build is still contained. See section 8. |

---

## 6. DevSecOps SSDLC Lifecycle & Security Gate Matrix

The lifecycle plan implements the sequence:

$$\text{Asset} \longrightarrow \text{Threat} \longrightarrow \text{Control / Requirement} \longrightarrow \text{Lifecycle Activity} \longrightarrow \text{Test / Evidence} \longrightarrow \text{Gate Decision}$$

| SDLC Phase | Required Deliverable | Asset Addressed | Threat Addressed | Security Control / Requirement | Lifecycle Activity | Test / Evidence | Security Gate Policy |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Requirements & Design** | Scope, Asset Register, Trust Boundaries, Access Matrix, STRIDE | AST-01 to AST-05 | All STRIDE threats (TH-01 to TH-05) | Apply Least Privilege, Complete Mediation, and Fail-Safe Defaults across boundaries. | Threat Modeling & Architectural Review | Documented SSDLC Plan committed as root Git commit. | **Gate 1:** Architecture must demonstrate 3 distinct processes, authority delegation model, and controls mapped to all assets. |
| **2. Implementation & Build** | Reproducible builds, pinned dependencies, 3 microservices | AST-01, AST-03 | Hardcoded secrets, known vulnerable third-party packages | Secret isolation via environment variables; hash-locked dependency manifests. | Secure coding, SAST scanning (Bandit), dependency auditing (`pip-audit`) | Automated Bandit scan report (`reports/bandit_report.json`), `pip-audit` manifest | **Gate 2:** Zero High/Critical SAST findings (Bandit CVSS > 5); build fails if undeclared dependencies or known CVEs are detected. |
| **3. Verification & Testing** | Functional test suite, authorization test suite, exploit fixtures | AST-02, AST-04 | TH-01 (SQLi), TH-02 (IDOR), TH-03 (Race), TH-04 (Confused Deputy) | Complete mediation on all inter-service endpoints; isolated test execution. | Dynamic verification (`pytest`), intentional exploit verification scripts | `pytest` test results matrix confirming both vulnerable failure and secure defense | **Gate 3:** 100% functional tests pass; all authorization regression tests pass; security tests demonstrate attack mitigation. |
| **4. Release & Operations** | Jenkins CI/CD pipeline, branch strategy, audit log review | AST-01 to AST-05 | Insecure production deployment, regression injection | Dual-branch strategy (`main` vulnerable vs `fixed`-version hardened); immutable build artifacts. | CI/CD automation, pipeline artifact archiving, release readiness review | Jenkins build execution logs, archived HTML/JSON reports, CVSS matrix | **Gate 4:** Pipeline passes cleanly only on fixed-version. Automated deployment blocked if security gate conditions are not satisfied. |

---

## 7. DevSecOps Toolchain & Automated Gate Criteria

```text
               ┌────────────────────────────────────────────────────────┐
               │                     Jenkins Pipeline                   │
               └────────────────────────────────────────────────────────┘
                                           │
      ┌──────────────────┬─────────────────┴────────────────┬──────────────────┐
      ▼                  ▼                                  ▼                  ▼
┌─────────────┐   ┌─────────────┐                    ┌─────────────┐   ┌─────────────┐
│ 1. Checkout │──▶│ 2. Build &  │───────────────────▶│   3. SAST   │──▶│ 4. Test &   │
│ & Environment   │ Dependencies│                    │  (Bandit)   │   │ Auth Suites │
└─────────────┘   └─────────────┘                    └─────────────┘   └─────────────┘
                                                            │                  │
                                                            ▼                  ▼
                                                  ┌───────────────────────────────┐
                                                  │       5. Security Gate        │
                                                  │ (Bandit High = 0, Tests Pass) │
                                                  └───────────────────────────────┘
                                                              │
                                             ┌────────────────┴────────────────┐
                                             ▼                                 ▼
                                    ❌ FAIL (Branch: main)           ✅ PASS (Branch: fixed)
```

- **SAST Engine:** Bandit (`bandit -r . -x ./venv -f json -o reports/bandit_report.json`)
  - **Gate Rule:** HIGH severity count == 0.
- **SCA Engine:** `pip-audit` / hash check
  - **Gate Rule:** Zero unpinned or vulnerable package dependencies.
- **Test Engine:** `pytest -v tests/`
  - **Gate Rule:** All functional workflows, ABAC boundaries, and race-condition safety assertions must return exit code 0.

---

## 8. TH-05 / Boundary B4 — Controlled Supply-Chain Experiment (Optional Task)

TH-05's control is implemented and demonstrated end-to-end under
`supply_chain/`, in two independent layers, matching the assignment's
"Controlled supply chain attack," "Experiment A," and "Experiment B"
tasks (each separately optional; all three are attempted here).

- **`supply_chain/manifest.json`** is the consumer-controlled manifest: it
  pins the SHA-256 digest of the one `data_exporter` build the project
  actually trusts, rather than trusting its declared name/version string.
  This file and its approved digest are identical on both branches.
- **`supply_chain/verify_and_install.py`** is the install-time gate: it
  refuses to install any wheel whose content hash doesn't match the
  manifest. This part of the control is identical on both branches too.
- **Experiment A** (`run_experiment_A.py`): the genuinely approved
  `data_exporter` 1.1.0 build installs normally; a second build declaring
  the *identical* name and version but different bytes is rejected on
  hash mismatch — proving a version pin alone (`data_exporter==1.1.0`)
  would not have caught it.
- **Experiment B** (`run_experiment_B.py`): the harder case — the
  malicious build's digest gets explicitly approved as trusted (a scratch
  manifest only, never the real one), modelling a compromised supplier
  update that was accepted. The malicious wheel is then installed for
  real and the three services are started exactly as they run normally;
  a single ordinary, fully-authorized export request (Alice exporting her
  own dataset) triggers the real workflow. **This is where the two
  branches diverge**, and it is the one place this optional task touches
  a service's own code:
  - On `main`, `processing_service/app.py` imports and calls
    `data_exporter` directly. The malicious build's search for
    `resource_service/research_vault.db` succeeds (same process, same
    working directory as the real service) and exfiltrates the real
    database to a local attacker listener the moment the service starts.
    **Verdict: COMPROMISED.**
  - On `fixed-version`, `processing_service/app.py` instead routes every
    call through `processing_service/sandboxed_dependency.py`: a second,
    independent control that runs the dependency in a child process with
    an empty working directory and no outbound sockets, *regardless of
    whether its digest was ever approved*. The malicious code still runs,
    but has nothing to find and nowhere to send it; Alice's legitimate
    export still completes normally, because the library's real job
    (formatting numbers into text) needs neither disk nor network access.
    **Verdict: CONTAINED.**

This gives TH-05 the same two mitigations the assignment asks for: a
hash-based gate at install time (defeated once a bad digest is approved,
by design — that is the premise of Experiment B) and a genuine runtime
isolation control that does not depend on the gate having worked. See
`supply_chain/README.md` for full instructions and sample output.
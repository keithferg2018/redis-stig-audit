# redis-stig-audit

**Redis Container Security Audit Tool for Regulated Environments**

[![CI](https://github.com/audit-forge/redis-stig-audit/actions/workflows/test.yml/badge.svg)](https://github.com/audit-forge/redis-stig-audit/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)

Open-source security audit tool for Redis deployed in containerized environments. Implements controls from:

- **CIS Redis Container Benchmark v1.0** (25 controls — see `benchmarks/`)
- **NIST SP 800-53 Revision 5** (FedRAMP High)
- **NIST SP 800-171 Rev 2** / **CMMC 2.0**

This repository is currently positioned as a **validated v1.0 community-draft benchmark + runtime audit prototype**. The v1.0 release boundary is frozen in [`docs/V1_RELEASE_BOUNDARY.md`](docs/V1_RELEASE_BOUNDARY.md).

> **Disclaimer:** This is an independent tool. Not officially certified or endorsed by CIS, DISA, NIST, Redis Ltd., or any other standards body/vendor. The CIS Redis Container Benchmark in this repo is a community draft. See [DISCLAIMER.md](DISCLAIMER.md) for attribution and positioning details.

---

## What It Does

**Audits Redis security configuration** in Docker containers, Kubernetes pods, and direct TCP connections. Checks authentication posture, TLS configuration, ACL hardening, persistence settings, and container runtime security — then maps every finding to NIST, CMMC, and MITRE frameworks.

---

## Installation

### Prerequisites

- Python 3.9+
- Docker (for Docker mode)
- kubectl (for Kubernetes mode)
- Redis CLI (`redis-cli`)

### Install

```bash
git clone https://github.com/audit-forge/redis-stig-audit.git
cd redis-stig-audit
python3 audit.py --version
```

No third-party dependencies — uses Python standard library only.

---

## Quick Start

Fastest docs first:
- [docs/QUICKSTART.md](docs/QUICKSTART.md) — copy/paste commands
- [docs/BEGINNER_GUIDE.md](docs/BEGINNER_GUIDE.md) — plain-English walkthrough

```bash
# Audit a Docker container
python3 audit.py --mode docker --container redis

# Audit a Kubernetes pod
python3 audit.py --mode kubectl --pod redis-0 --namespace default

# Audit via direct TCP
python3 audit.py --mode direct --host 127.0.0.1 --port 6379

# Full output: JSON + SARIF + evidence bundle
python3 audit.py --mode docker --container redis \
  --json results.json \
  --sarif results.sarif \
  --bundle audit-bundle.zip
```

---

## Usage

### Connection Modes

| Flag | Description |
|---|---|
| `--mode docker` | Run checks via `docker exec` |
| `--mode kubectl` | Run checks via `kubectl exec` |
| `--mode direct` | Connect directly over TCP |
| `--container NAME` | Docker container name |
| `--pod NAME` | Kubernetes pod name |
| `--namespace NS` | Kubernetes namespace (default: `default`) |
| `--host HOST` | Host for direct mode (default: `127.0.0.1`) |
| `--port PORT` | Port for direct mode (default: `6379`) |
| `--password PASS` | Redis AUTH password (prefer `REDISCLI_AUTH` env var) |

### Output Flags

| Flag | Description |
|---|---|
| `--json FILE` | Write full JSON findings document |
| `--sarif FILE` | Write SARIF 2.1.0 output |
| `--csv FILE` | Write CSV with all framework columns |
| `--bundle FILE` | Write ZIP evidence bundle |

### Control Flags

| Flag | Description |
|---|---|
| `--skip-cve` | Skip CVE/KEV scanning (faster, air-gapped) |
| `--fail-on SEVERITY` | Exit non-zero if any finding at or above severity |
| `--verbose` | Show extra detail |
| `--quiet` | Suppress terminal report |

---

## CVE/KEV Scanning

The audit tool queries the NIST National Vulnerability Database (NVD) for CVEs affecting the detected Redis version and cross-references the CISA Known Exploited Vulnerabilities (KEV) catalog.

**Features:**
- Automatic Redis version detection via `redis-cli INFO server`
- NVD API v2 query for CVEs matching the running version
- CISA KEV catalog lookup — flags CVEs with active exploitation
- Severity escalation: CRITICAL if KEV hit or CVSS >= 9.0; HIGH if CVSS >= 7.0
- Results cached locally in `data/` for 24 hours (no repeated network calls)
- `--skip-cve` flag to bypass in air-gapped or compliance-only runs
- Optional `NVD_API_KEY` env var for higher rate limits

```bash
# Standard run (includes CVE scan)
python3 audit.py --mode docker --container redis --csv results.csv

# Skip CVE scan
python3 audit.py --mode docker --container redis --skip-cve

# With NVD API key
NVD_API_KEY=your-key python3 audit.py --mode docker --container redis
```

See [docs/CVE_SCANNING.md](docs/CVE_SCANNING.md) for full details.

---

## Repeatable Live Validation

The repo includes a Docker-based fixture set for repeatable live validation:
- `baseline`
- `vulnerable`
- `hardened`

**Validated fixture outcomes for the current v1.0 baseline:**
- `baseline` → `PASS 9 / FAIL 6 / WARN 5`
- `vulnerable` → `PASS 7 / FAIL 7 / WARN 6`
- `hardened` → `PASS 18 / FAIL 0 / WARN 2`

Quick start:

```bash
make fixtures-up
make fixture-audit-all
make fixtures-down
```

Per-fixture artifacts are written to `output/fixtures/`.
See [test/README.md](test/README.md) for the full workflow, [test/FIXTURE-STATUS.md](test/FIXTURE-STATUS.md) for observed outcomes, and [docs/V1_RELEASE_BOUNDARY.md](docs/V1_RELEASE_BOUNDARY.md) for what counts as done for v1.0.

---

## Coverage

### Configuration Checks

- **Protected mode** — validates Redis is not exposed without authentication
- **Bind exposure** — checks Redis is not listening on all interfaces without TLS/auth
- **TLS visibility** — detects whether TLS (`tls-port`) is configured
- **Plaintext listener** — flags unencrypted listeners when TLS is enabled
- **Replication/cluster TLS** — checks transport encryption for replication and cluster traffic
- **Persistence configuration** — verifies RDB/AOF intent and runtime health
- **ACL durability** — detects whether ACL rules survive restarts
- **Logging intent** — checks logging destination configuration

### Authentication and Access Control

- **Default user ACL posture** — verifies the `default` user is restricted or disabled
- **Administrative access** — confirms admin commands require authentication
- **Dangerous command exposure** — heuristic detection of unrestricted dangerous commands
- **ACL file vs CONFIG** — checks ACL durability model

### Container Runtime Checks (Docker and Kubernetes)

- Non-root user enforcement
- Privileged container mode
- Linux capability restrictions
- Read-only root filesystem
- Resource limits (CPU / memory)
- Host namespace isolation (PID, network, IPC)
- AppArmor / seccomp profile presence

### Framework Mappings

Every control maps to:

| Framework | Coverage |
|---|---|
| **NIST SP 800-53 Rev 5** | Full — every control maps to one or more 800-53 controls |
| **NIST SP 800-171 Rev 2** | Full — all 25 benchmark controls mapped |
| **CMMC 2.0** | Level indicators (1 or 2) for every control |
| **MITRE ATT&CK** | Container and Enterprise techniques each control defends against |
| **MITRE D3FEND** | Defensive countermeasure techniques each control implements |

| CMMC Level | Control Count |
|---|---|
| Level 1 | 7 |
| Level 2 | 18 |

The complete mapping data is in `mappings/control-matrix.json` and `mappings/frameworks.py`.

---

## Output Formats

### Terminal Report (default)

```
════════════════════════════════════════════════════════════════════════════════
  Redis Container Security Audit
════════════════════════════════════════════════════════════════════════════════

Target:   docker → redis
Version:  Redis 7.2.4

Total Controls:     <varies by benchmark/runtime support>
✅ Passed:          <example>
❌ Failed:          <example>
⚠️  Warnings:       <example>

Top Findings (by severity):
  🔴 CRITICAL: RD-AUTH-001 — Default user has nopass (no authentication required)
  🟠 HIGH:     RD-CFG-003  — TLS not configured; data in transit is plaintext
  🟡 MEDIUM:   RD-CNT-002  — Container running as root
```

### JSON (machine-readable)

Full findings document including:
- `schema_version`, tool name/version, normalized target metadata
- Executive summary (`status_counts`, `severity_counts`, `risk_posture`)
- Runtime snapshot (`CONFIG GET`, `ACL LIST`, `INFO` sections, container metadata)
- Per-check evidence items with all framework mappings

Schema: `schemas/results.schema.json` (JSON Schema draft 2020-12)

```bash
python3 audit.py --mode docker --container redis --json results.json
```

### SARIF 2.1.0 (GitHub Security, GitLab SAST)

```bash
python3 audit.py --mode docker --container redis --sarif results.sarif
```

Upload to GitHub Code Scanning:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

| Audit status | SARIF level |
|---|---|
| FAIL / ERROR | `error` |
| WARN | `warning` |
| PASS / SKIP | `none` |

### CSV (framework compliance export)

```bash
python3 audit.py --mode docker --container redis --csv results.csv
```

Columns: `Control_ID`, `Title`, `Severity`, `Result`, `Category`, `Actual`, `Expected`, `Description`, `Rationale`, `CIS_Control`, `NIST_800_53`, `NIST_800_171`, `CMMC_Level`, `MITRE_ATTACK`, `MITRE_D3FEND`, `Remediation`, `References`

### Evidence Bundle (compliance audits)

```bash
python3 audit.py --mode docker --container redis --bundle audit-bundle.zip
```

Bundle contents:

| File | Description |
|---|---|
| `manifest.json` | Bundle metadata: tool, target, generated_at, contents list |
| `results.json` | Full JSON findings document |
| `results.sarif` | SARIF 2.1.0 rendition |
| `snapshot.json` | Isolated runtime snapshot |
| `summary.txt` | Human-readable plain-text report |
| `evidence/<check_id>.json` | Per-check evidence with status, actual, expected |

### Combined output

```bash
python3 audit.py --mode docker --container redis \
  --json output/results.json \
  --sarif output/results.sarif \
  --csv output/results.csv \
  --bundle output/audit-bundle.zip
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Redis Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Start Redis container
        run: |
          docker run -d --name test-redis redis:7
          sleep 5

      - name: Run redis-stig-audit
        run: |
          python3 audit.py --mode docker --container test-redis \
            --sarif results.sarif \
            --fail-on high

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
redis_audit:
  stage: test
  image: python:3.11
  services:
    - redis:7
  script:
    - python3 audit.py --mode direct --host redis --sarif gl-sast-report.sarif
  artifacts:
    reports:
      sast: gl-sast-report.sarif
```

---

## Running Tests

```bash
make test
# or without make:
python3 -m unittest discover -s test -p 'test_*.py' -v
```

The test suite uses a `FakeRunner` mock — no live Redis instance required for unit tests. No third-party packages needed.

---

## Validation Status

| Category | Current evidence |
|---|---|
| Unit tests | `make test` |
| Live runtime validation | Docker fixture set via `make fixture-audit-all` |
| Fixture targets | `baseline`, `vulnerable`, `hardened` |
| Redis image used for fixtures | `redis:7.2-alpine` |
| Operator host used for current validation | macOS running Docker |

The tool supports Docker, Kubernetes, and direct modes, but the currently recorded v1.0 validation evidence is centered on the repeatable Docker fixture workflow above. Kubernetes, managed-service, and broader topology coverage remain intentionally conservative for v1.0 positioning.

---

## Repository Layout

```
redis-stig-audit/
├── audit.py              # Main CLI entrypoint
├── runner.py             # Redis interrogation helpers (docker/kubectl/direct)
├── checks/               # Benchmark-aligned audit checks
│   ├── base.py           # Status, Severity enums; CheckResult dataclass
│   ├── config.py         # Protected mode, bind, TLS, persistence
│   ├── runtime.py        # Runtime metadata, replication role
│   ├── auth.py           # ACL and authentication checks
│   └── container.py      # Docker/Kubernetes runtime checks
├── mappings/             # Framework mapping data
│   ├── frameworks.py     # NIST 800-53/171, CMMC, MITRE mappings
│   └── control-matrix.json
├── output/               # Output formatters (terminal, SARIF, JSON, bundle)
├── benchmarks/           # CIS Redis Container Benchmark draft
├── schemas/              # JSON Schema for results format
├── docs/                 # Methodology, assessor guide, evidence model
├── rego/                 # OPA/Rego policy placeholders
└── test/                 # Unit tests with FakeRunner mock
```

---

## Documentation

- [docs/QUICKSTART.md](docs/QUICKSTART.md) — copy/paste quick start for the fastest path
- [docs/BEGINNER_GUIDE.md](docs/BEGINNER_GUIDE.md) — plain-English step-by-step usage guide
- [docs/RUN_BENCHMARK.md](docs/RUN_BENCHMARK.md) — fuller benchmark execution guide
- [docs/PILOT_TESTER_HANDOFF.md](docs/PILOT_TESTER_HANDOFF.md) — reusable pilot tester message
- [docs/RELEASE_SUMMARY.md](docs/RELEASE_SUMMARY.md) — short release-style summary
- [docs/CVE_SCANNING.md](docs/CVE_SCANNING.md) — CVE/KEV scanning details
- [docs/V1_RELEASE_BOUNDARY.md](docs/V1_RELEASE_BOUNDARY.md) — frozen v1.0 scope, validated baseline, and v1.1+ backlog
- [docs/ASSESSOR_GUIDE.md](docs/ASSESSOR_GUIDE.md) — Assessor workflow guide
- [docs/METHODOLOGY.md](docs/METHODOLOGY.md) — Assessment methodology
- [docs/EVIDENCE_MODEL.md](docs/EVIDENCE_MODEL.md) — Evidence collection model
- [test/FIXTURE-STATUS.md](test/FIXTURE-STATUS.md) — observed live fixture outcomes
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to contribute

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding checks, improving framework mappings, and the PR process.

---

## License

Copyright 2026 redis-stig-audit contributors.

Licensed under the [Apache License, Version 2.0](LICENSE).

The CIS Redis Container Benchmark is a community draft. This tool implements the benchmark controls independently and is not affiliated with or endorsed by CIS or Redis Ltd.

---

## Acknowledgements

Built with reference to:
- CIS Redis Container Benchmark v1.0 (community draft)
- NIST SP 800-53 Revision 5
- NIST SP 800-171 Rev 2
- CISA Known Exploited Vulnerabilities Catalog
- Redis Security Documentation


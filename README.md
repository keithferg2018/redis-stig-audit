# redis-stig-audit

**Redis container security benchmark and audit workflow for regulated environments**

`redis-stig-audit` is a benchmark-first project for assessing Redis deployed in containerized environments. It is intended to support internal security reviews, recurring compliance assessments, and FedRAMP-aligned annual audit evidence workflows.

## Status

Early but functional draft.

This repository currently includes:
- a CIS-style benchmark draft for Redis in containers
- an initial machine-readable control matrix
- methodology / assessor / evidence docs
- a working first-pass audit CLI with real Redis interrogation via `redis-cli`
- benchmark-aligned checks for authentication posture, ACL posture, protected mode, bind exposure, TLS visibility, replication transport posture, persistence intent, persistence runtime health, logging intent, and runtime metadata
- container-runtime controls: non-root user, privileged mode, Linux capabilities, read-only rootfs, resource limits, and host namespaces (Docker and Kubernetes)
- structured JSON output with target metadata, summary, evidence items, and runtime snapshot details
- **SARIF 2.1.0 output** for GitHub Code Scanning / GitLab SAST ingestion
- **evidence bundle output** (zip) with JSON findings, SARIF, snapshot, per-check evidence, and human-readable summary

It does **not** yet claim official CIS endorsement or certification.

## Repository layout

- `benchmarks/CIS_Redis_Container_Benchmark_v1.0.md` — benchmark draft
- `audit.py` — audit CLI entrypoint
- `runner.py` — Redis interrogation helpers
- `checks/` — benchmark-aligned audit checks
- `output/` — human-readable reporting, SARIF 2.1.0, and evidence bundle
- `mappings/control-matrix.json` — machine-readable control catalog
- `schemas/results.schema.json` — results schema draft
- `docs/` — methodology, assessor guidance, and evidence model
- `rego/` — future policy integration placeholders
- `test/` — smoke tests and future fixture guidance

## Current coverage

Current automated checks focus on:
- protected mode
- bind exposure
- TLS visibility
- plaintext listener exposure when TLS is enabled
- replication/cluster TLS posture visibility
- default-user ACL posture
- authenticated administrative access posture
- dangerous-command exposure heuristics
- persistence configuration intent
- persistence runtime health visibility
- ACL durability visibility
- logging destination / intent visibility
- runtime metadata / replication role visibility

## Usage

### Direct mode

```bash
python3 audit.py --mode direct --host 127.0.0.1 --port 6379 --json results.json
```

### Docker mode

```bash
python3 audit.py --mode docker --container redis --json results.json
python3 audit.py --mode docker --container redis --sarif results.sarif
python3 audit.py --mode docker --container redis --bundle audit-bundle.zip
```

### Kubernetes mode

```bash
python3 audit.py --mode kubectl --pod redis-0 --namespace default --json results.json
python3 audit.py --mode kubectl --pod redis-0 --namespace default --bundle audit-bundle.zip
```

## Output model

### JSON (`--json FILE`)

Full findings document including:
- `schema_version`, tool name/version, normalized target metadata
- executive summary (`status_counts`, `severity_counts`, `risk_posture`)
- runtime snapshot (`CONFIG GET`, `ACL LIST`, `INFO` sections, command log tail, container_meta)
- benchmark-aligned findings with per-check evidence items and NIST/FedRAMP mappings

Schema: `schemas/results.schema.json` (JSON Schema draft 2020-12)

### SARIF 2.1.0 (`--sarif FILE`)

Static-analysis results interchange format suitable for:
- **GitHub Code Scanning** — upload via `github/codeql-action/upload-sarif`
- **GitLab SAST** — ingest as a SARIF artifact
- Any SARIF-compatible viewer or pipeline

Mapping:
| Audit status | SARIF level |
|---|---|
| FAIL / ERROR | `error` |
| WARN | `warning` |
| PASS / SKIP | `none` |

Each rule carries NIST 800-53 control tags, FedRAMP control tag, benchmark control ID, and remediation guidance.

### Evidence bundle (`--bundle FILE`)

A zip archive containing all outputs in one package:

| File | Description |
|---|---|
| `manifest.json` | Bundle metadata: tool, target, generated_at, contents list |
| `results.json` | Full JSON findings document |
| `results.sarif` | SARIF 2.1.0 rendition |
| `snapshot.json` | Isolated runtime snapshot |
| `summary.txt` | Human-readable plain-text report |
| `evidence/<check_id>.json` | Per-check evidence: status, actual, expected, evidence items |

### Combined output

All three formats can be produced in one invocation:

```bash
python3 audit.py --mode docker --container redis \
  --json output/results.json \
  --sarif output/results.sarif \
  --bundle output/audit-bundle.zip
```

Or via Make:

```bash
make all-outputs
```

### Terminal report

- executive summary with risk posture
- top findings (up to 5, sorted by severity)
- detailed findings with control mappings and evidence counts

## Validation

Run the current smoke tests:

```bash
python3 -m unittest discover -s test -p 'test_*.py'
```

## Design principles

- benchmark-first, scanner-second
- vendor-neutral language
- deterministic audit evidence where possible
- FedRAMP / NIST traceability
- public-review-friendly structure

## Near-term roadmap

1. expand the benchmark draft into fuller control coverage
2. add Docker/Kubernetes fixture environments for repeatable live validation
3. Redis Sentinel / Cluster topology-aware checks
4. Rego/OPA policy bundle for rule evaluation
5. FedRAMP evidence bundle packaging
6. prepare for public review and GitHub release

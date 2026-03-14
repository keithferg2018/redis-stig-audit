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
- early runtime checks for authentication posture, ACL posture, protected mode, bind exposure, TLS visibility, persistence posture, and runtime metadata

It does **not** yet claim official CIS endorsement or certification.

## Repository layout

- `benchmarks/CIS_Redis_Container_Benchmark_v1.0.md` — benchmark draft
- `audit.py` — audit CLI entrypoint
- `runner.py` — Redis interrogation helpers
- `checks/` — benchmark-aligned audit checks
- `output/` — human-readable reporting
- `mappings/control-matrix.json` — machine-readable control catalog
- `schemas/results.schema.json` — results schema draft
- `docs/` — methodology, assessor guidance, and evidence model
- `rego/` — future policy integration placeholders
- `test/` — future fixture/test guidance

## Current coverage

First-pass automated checks currently focus on:
- protected mode
- bind exposure
- TLS visibility
- default-user ACL posture
- authenticated administrative access posture
- dangerous-command exposure heuristics
- persistence configuration visibility
- ACL durability visibility
- runtime metadata / replication role visibility

## Usage

### Direct mode

```bash
python3 audit.py --mode direct --host 127.0.0.1 --port 6379 --json results.json
```

### Docker mode

```bash
python3 audit.py --mode docker --container redis --json results.json
```

### Kubernetes mode

```bash
python3 audit.py --mode kubectl --pod redis-0 --namespace default --json results.json
```

## Output model

Current JSON output includes:
- target metadata
- runtime snapshot
- benchmark-aligned findings

Planned outputs:
- richer terminal reports
- SARIF
- control trace matrix
- evidence summary
- optional enterprise output adapters

## Design principles

- benchmark-first, scanner-second
- vendor-neutral language
- deterministic audit evidence where possible
- FedRAMP / NIST traceability
- public-review-friendly structure

## Near-term roadmap

1. expand the benchmark draft into fuller control coverage
2. add more Redis checks (replication, TLS detail, persistence and operational hardening)
3. add test fixtures for Docker and Kubernetes
4. add stronger output formats and evidence packaging
5. prepare for public review and GitHub release

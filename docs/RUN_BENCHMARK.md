# How to Run the Redis Container Benchmark

This document is the explicit operator guide for running `redis-stig-audit` as a **standalone benchmark/audit tool**.

Use this when you want to assess a Redis target directly from your laptop, CI runner, or audit host without involving Wiz.

---

## What this tool does

`redis-stig-audit` evaluates Redis running in containerized environments and produces:

- terminal findings
- JSON results
- SARIF 2.1.0 output
- an evidence bundle zip

It does **not** need to be installed inside the Redis container.
Run it from a host that can reach the target and, when applicable, can call `docker` or `kubectl`.

---

## Requirements

- Python 3.10+
- Redis target reachable in one of these modes:
  - direct TCP (`--mode direct`)
  - Docker (`--mode docker`)
  - Kubernetes (`--mode kubectl`)
- For direct mode: network access to Redis
- For Docker mode: local Docker access plus `docker` CLI
- For Kubernetes mode: cluster access plus `kubectl`
- For authenticated Redis: credentials that allow read-only benchmark interrogation (`CONFIG GET`, `ACL LIST`, `INFO`, optional command introspection)

---

## Repo location

From the workspace:

```bash
cd /Users/neepai/.openclaw/workspace/redis-stig-audit
```

---

## Quick start

### 1) Terminal-only run

#### Direct mode

```bash
python3 audit.py --mode direct --host 127.0.0.1 --port 6379
```

#### Docker mode

```bash
python3 audit.py --mode docker --container redis
```

#### Kubernetes mode

```bash
python3 audit.py --mode kubectl --pod redis-0 --namespace default
```

---

## Generate explicit artifacts

### JSON output

```bash
python3 audit.py --mode docker --container redis --json output/results.json
```

### SARIF output

```bash
python3 audit.py --mode docker --container redis --sarif output/results.sarif
```

### Evidence bundle

```bash
python3 audit.py --mode docker --container redis --bundle output/audit-bundle.zip
```

### CSV output (with NIST 800-171, CMMC, and MITRE columns)

```bash
python3 audit.py --mode docker --container redis --csv output/results.csv
```

The CSV includes these compliance columns for each control:
- `NIST_800_171` — NIST SP 800-171 Rev 2 control IDs (e.g. `3.13.1; 3.13.8`)
- `CMMC_Level` — CMMC 2.0 level (1 or 2)
- `MITRE_ATTACK` — ATT&CK technique IDs (e.g. `T1040; T1133`)
- `MITRE_D3FEND` — D3FEND technique IDs (e.g. `D3-ET; D3-NI`)

The CSV is compatible with Excel, Google Sheets, and any standard spreadsheet tool.

### Conditional CSV fields

Some CSV columns only apply to certain finding types:
- `CVE_ID`, `KEV_Score`, and `CVE_Remediation`
  - `not_scanned` when `--skip-cve` is used
  - `not_applicable` for non-vulnerability findings
  - populated values for the version/CVE finding when CVE scanning runs
- `Local_Path`
  - populated with a real binary/path when available (for example the Redis server binary in CVE findings)
  - otherwise set to a scope hint such as `runtime-config` or `container-inspect` instead of being left blank

### All outputs in one run

```bash
python3 audit.py --mode docker --container redis \
  --json output/results.json \
  --sarif output/results.sarif \
  --bundle output/audit-bundle.zip \
  --csv output/results.csv
```

You can also use the Makefile shortcut:

```bash
make all-outputs
```

---

## Authentication examples

If Redis requires authentication, export credentials before running.

### Password-based auth

```bash
export REDISCLI_AUTH='your-password'
python3 audit.py --mode direct --host 10.0.0.15 --port 6379 --json results.json
```

### ACL username + password

If your environment requires a username, pass it the same way you normally would to `redis-cli` in the environment you execute from. If your local wrapper or shell profile already supports that, use the same auth context before invoking `audit.py`.

If needed, test manually first:

```bash
redis-cli -h 10.0.0.15 -p 6379 ping
redis-cli -h 10.0.0.15 -p 6379 info server
```

Then run the benchmark.

---

## Mode-by-mode examples

## Direct mode

Use this when Redis is reachable by host/port.

```bash
python3 audit.py --mode direct \
  --host 127.0.0.1 \
  --port 6379 \
  --json output/direct-results.json \
  --sarif output/direct-results.sarif \
  --bundle output/direct-bundle.zip
```

Good for:
- local development
- bastion/assessment hosts
- externally reachable internal Redis services

---

## Docker mode

Use this when Redis is running in a local Docker container and you want both Redis runtime checks and container-hardening checks.

### Verify container name first

```bash
docker ps --format '{{.Names}}'
```

### Run audit

```bash
python3 audit.py --mode docker \
  --container redis \
  --json output/docker-results.json \
  --sarif output/docker-results.sarif \
  --bundle output/docker-bundle.zip
```

Good for:
- local validation
- pre-release checks
- container hardening evidence collection

---

## Kubernetes mode

Use this when Redis runs in a cluster and you want pod-level/container-level checks.

### Verify pod name first

```bash
kubectl get pods -n default
```

### Run audit

```bash
python3 audit.py --mode kubectl \
  --pod redis-0 \
  --namespace default \
  --json output/k8s-results.json \
  --sarif output/k8s-results.sarif \
  --bundle output/k8s-bundle.zip
```

Good for:
- cluster audits
- evidence collection for regulated environments
- comparing baseline vs hardened manifests

---

## What the outputs mean

### Terminal report
Human-readable assessment summary.

### JSON
Full machine-readable document containing:
- target metadata
- summary counts
- risk posture
- runtime snapshot
- findings and evidence

### SARIF
Best for pipeline ingestion and code/security platforms that understand SARIF.

### Evidence bundle zip
Best for audit packages and reviewer handoff.
Contains:
- `manifest.json`
- `results.json`
- `results.sarif`
- `snapshot.json`
- `summary.txt`
- `evidence/<check_id>.json`

---

## Recommended operator flow

### Simple standalone review

```bash
python3 audit.py --mode docker --container redis
```

### Reviewer-ready package

```bash
python3 audit.py --mode docker --container redis \
  --json output/results.json \
  --sarif output/results.sarif \
  --bundle output/audit-bundle.zip
```

### CI/CD-friendly pattern

```bash
mkdir -p output
python3 audit.py --mode docker --container redis \
  --json output/results.json \
  --sarif output/results.sarif \
  --bundle output/audit-bundle.zip
```

Then archive `output/` as a build artifact.

---

## Validation

Run the current unit test suite:

```bash
python3 -m unittest discover -s test -p 'test_*.py' -v
```

---

## Troubleshooting

### `redis-cli` auth or connectivity fails
- Confirm the target is reachable
- Confirm your auth environment is correct
- Test with `redis-cli` manually before running the benchmark

### Docker mode returns inspect/runtime issues
- Confirm the container exists
- Confirm your user can run Docker commands
- Check `docker inspect <container>` manually

### Kubernetes mode fails
- Confirm kube context/namespace
- Confirm pod name is correct
- Check `kubectl get pod -n <namespace> <pod> -o json`

### No JSON/SARIF/bundle files appear
- Confirm the output directory exists if you are writing into a nested path
- Use `mkdir -p output` before running

---

## Related docs

- `README.md`
- `docs/ASSESSOR_GUIDE.md`
- `docs/EVIDENCE_MODEL.md`
- `docs/WIZ_SETUP.md`

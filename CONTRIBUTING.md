# Contributing to redis-stig-audit

Thank you for your interest in contributing! This document covers how to get involved.

---

## Ways to Contribute

- **Bug reports** — open a GitHub Issue with steps to reproduce
- **New checks** — implement additional CIS/NIST controls (see below)
- **Framework mappings** — improve NIST/CMMC/MITRE coverage
- **Documentation** — clarify usage, add examples
- **Test coverage** — add test cases for edge conditions
- **Redis topology** — Sentinel / Cluster topology-aware checks

---

## Development Setup

```bash
git clone https://github.com/audit-forge/redis-stig-audit.git
cd redis-stig-audit
python -m pytest test/ -v
```

No dependencies beyond Python 3.9+ standard library.

---

## Code Style

- Python 3.9+ compatible — no walrus operators, no 3.10+ match statements
- Follow existing patterns in `checks/` — each checker is a class inheriting `BaseChecker`
- Use `list[CheckResult]` return types (not `List[CheckResult]`)
- Prefer explicit over clever — this is audit tooling, clarity matters more than brevity
- Run `python -m py_compile <file>` to catch syntax errors before committing

---

## Adding a New Check

1. Open the relevant checker module in `checks/` (or create a new one)
2. Add a new `CheckResult` entry following the existing pattern:

```python
CheckResult(
    check_id="RD-XYZ-001",                  # Unique ID — prefix matches category
    title="Descriptive title",
    status=Status.PASS,                      # or FAIL, WARN, SKIP, ERROR
    severity=Severity.HIGH,                  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description="What this checks and why it matters.",
    rationale="Why this control reduces risk.",
    actual=str(observed_value),
    expected="expected value",
    remediation="Steps to fix the finding.",
    evidence_type="config",                  # config, runtime, container, acl
    evidence=[
        {"source": "CONFIG GET <param>", "value": str(raw_value)}
    ],
    references=["https://..."],
)
```

3. Add framework mappings in `mappings/frameworks.py` for your new `check_id`
4. Add a test case in `test/test_checks.py` using `FakeRunner`
5. Update the coverage section in the README

---

## Using FakeRunner in Tests

The test suite uses `FakeRunner` to mock Redis CLI output without a live Redis instance:

```python
from test.test_checks import FakeRunner  # or define locally
from checks.config import RedisConfigChecker

runner = FakeRunner({
    "config_get_protected_mode": "protected-mode\nyes\n",
    "config_get_bind": "bind\n127.0.0.1\n",
    # ... other keys your checker needs
})
checker = RedisConfigChecker(runner)
results = checker.run()
assert results[0].status == Status.PASS
```

See `test/test_checks.py` for the full `FakeRunner` implementation and existing test patterns.

---

## Adding Framework Mappings

All framework mappings are in `mappings/frameworks.py`. The `enrich_all()` function applies them automatically to every `CheckResult`.

To add or update a mapping:

```python
# In mappings/frameworks.py, find the CONTROL_MAP dict
"RD-XYZ-001": {
    "nist_800_53": ["AC-3", "SC-8"],
    "nist_800_171": ["3.1.1", "3.13.8"],
    "cmmc_level": 2,
    "mitre_attack": ["T1040", "T1078"],
    "mitre_d3fend": ["D3-ET", "D3-NI"],
},
```

Also update `mappings/control-matrix.json` to keep the machine-readable catalog in sync.

---

## Testing Requirements

All PRs must pass the test suite:

```bash
python -m pytest test/ -v
```

For new checks, include at least one test case demonstrating:
- A PASS result when the control is satisfied
- A FAIL or WARN result when it is not

The test suite uses a `FakeRunner` mock — do not add tests that require a live Redis instance in the unit test suite.

---

## Pull Request Process

1. Fork the repo and create a branch: `git checkout -b feature/my-check`
2. Make your changes with clear, focused commits
3. Ensure `python -m pytest test/ -v` passes
4. Ensure `python -m py_compile audit.py checks/*.py` has no errors
5. Open a PR with a clear description of what you changed and why
6. Reference any relevant CIS/NIST control IDs in the PR description

---

## Benchmark Accuracy

This tool implements controls from the CIS Redis Container Benchmark (community draft) and NIST frameworks. If you believe a control implementation is incorrect:

- Cite the specific benchmark version and section
- Describe the correct expected behavior
- Include a reference to the official source

**Note:** CIS benchmarks are copyrighted by Center for Internet Security. Contributions must implement controls independently — do not reproduce benchmark text verbatim.

---

## Security Issues

If you discover a security vulnerability in this tool itself (not in Redis), please open a GitHub Issue marked `[SECURITY]`. Do not include exploit details in the public issue — describe the class of vulnerability and we will coordinate disclosure.

---

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

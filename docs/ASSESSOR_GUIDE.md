# Assessor Guide — redis-stig-audit

## Intended Use

This project is intended to support security reviewers, compliance engineers, and internal audit teams assessing Redis deployed in containerized environments.

## Assessment Model

Use the benchmark and scanner together:

1. Read the benchmark control language
2. Identify which controls are automatable versus manual-review only
3. Run the scanner for automatable checks
4. Review raw evidence and findings
5. Complete manual-review controls separately

## Evidence Expectations

For each finding, preserve:
- target metadata
- timestamp of execution
- benchmark control ID
- actual state observed
- expected state
- remediation guidance
- reference source(s)

## Profiles

- **Level 1**: baseline production controls with low-to-moderate operational impact
- **Level 2**: defense-in-depth controls suitable for sensitive and regulated environments

## Current Limitation

The current project is still in early scaffold stage. Until more checks are implemented, results should be treated as developmental and not as a final security assessment.

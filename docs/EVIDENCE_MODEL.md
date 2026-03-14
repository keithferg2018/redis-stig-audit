# Evidence Model — redis-stig-audit

## Goal

Produce outputs that can support recurring assessment workflows, including annual security reviews in regulated environments.

## Required Finding Fields

Each finding should eventually include:
- `check_id`
- `benchmark_control_id`
- `title`
- `status`
- `severity`
- `category`
- `fedramp_control` / `nist_800_53_controls`
- `description`
- `actual`
- `expected`
- `remediation`
- `references`
- `evidence_type`
- `target`
- `timestamp`

## Evidence Types

- `runtime-config`
- `container-runtime`
- `network-exposure`
- `manual-review`
- `deployment-manifest`
- `image-supply-chain`

## Output Targets

Planned:
- human-readable report
- raw JSON
- SARIF
- control trace matrix
- optional enterprise integrations (Wiz, SCC)

## Assessment Warning

Absence of an automated finding must not be interpreted as control satisfaction unless the relevant benchmark control explicitly defines the automated evidence as sufficient.

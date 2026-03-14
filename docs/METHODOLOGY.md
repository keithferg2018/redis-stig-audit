# Methodology — redis-stig-audit

## Purpose

This project is designed to support a future Redis-in-containers security benchmark and corresponding audit workflow for regulated environments.

The benchmark artifact is primary.
The scanner exists to provide deterministic evidence against benchmark controls.

## Design Principles

1. **Benchmark-first**
   - Every automated check should map to a documented benchmark control.
   - The benchmark must stand on its own without the scanner.

2. **Vendor-neutral language**
   - Avoid product marketing language and private/internal branding.
   - Describe this project as a draft/community benchmark effort unless and until external governance changes that status.

3. **Deterministic evidence**
   - Prefer controls that can be audited via configuration, runtime state, or clearly documented manual review.
   - Avoid vague guidance that cannot be assessed consistently.

4. **FedRAMP/NIST traceability**
   - Track mappings to relevant NIST SP 800-53 Rev 5 control families.
   - Preserve evidence that can support annual assessment workflows.

5. **Separation of concerns**
   - Benchmark document: human-readable normative guidance
   - Control matrix: machine-readable control catalog
   - Scanner: implementation of automatable checks
   - Evidence outputs: assessor-usable findings and trace artifacts

## Source Hierarchy

Primary sources should include:
- Redis official security documentation
- Redis ACL / TLS / runtime configuration documentation
- CIS Docker Benchmark / CIS Kubernetes Benchmark logic where container-specific controls apply
- NIST SP 800-53 Rev 5
- NIST SP 800-190 (Application Container Security Guide)
- FedRAMP assessment and evidence expectations where relevant

## Benchmark Structure Target

Each benchmark control should eventually include:
- Control ID
- Title
- Profile (Level 1 or Level 2)
- Scored / Not Scored
- Description
- Rationale
- Impact
- Audit
- Remediation
- Default Value
- References
- Framework mappings

## Scanner Design Target

Each automated check should eventually include:
- `check_id`
- `benchmark_control_id`
- severity
- category
- evidence source (config, runtime, network, manual)
- actual vs expected
- remediation guidance

## Initial Scope Assumptions

- Redis OSS 6.x and 7.x first
- Containerized deployments first (Docker / Kubernetes / OCI runtimes)
- Managed cloud Redis services are out of scope for v1 unless explicitly modeled later
- Valkey compatibility may be considered later, but the initial benchmark should stay Redis-focused

## Success Criteria

A strong v1 should produce:
- a credible benchmark document
- a control matrix with traceable IDs
- a deterministic first-pass scanner
- evidence outputs usable in annual audit workflows

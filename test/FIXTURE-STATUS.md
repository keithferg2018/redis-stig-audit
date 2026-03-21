# Redis Live Fixture Status

Added fixture set for repeatable manual validation:

- `baseline` — mostly default-ish Redis with protected mode on but broad network bind and no ACL hardening
- `vulnerable` — intentionally weak posture for negative testing
- `hardened` — non-root, read-only rootfs, caps dropped, resource limits set, ACL-based auth and intentional persistence

Primary entrypoints:

- `test/fixtures/docker-compose.yml`
- `test/run_fixtures.sh`
- `test/README.md`

Expected use:

1. Bring fixtures up
2. Run one or all audits
3. Compare output artifacts under `output/fixtures/`
4. Tear fixtures down

Current observed outcomes from live validation on 2026-03-21:
- `baseline` → `PASS 9 / FAIL 6 / WARN 5`
- `vulnerable` → `PASS 7 / FAIL 7 / WARN 6`
- `hardened` → `PASS 18 / WARN 2`

Notes:
- The hardened fixture is intentionally much stronger, but still leaves TLS-related controls in warning state because TLS is not enabled in the lightweight fixture.
- This fixture set is designed to prove repeatability and expected differences between security postures, not to claim full production deployment coverage.

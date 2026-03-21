# redis-stig-audit test plan

## Live Docker fixtures

Implemented fixture set under `test/fixtures/`:
- `baseline` — protected mode on, but broad bind and no ACL hardening
- `vulnerable` — intentionally weak configuration for negative testing
- `hardened` — ACL-authenticated, intentional persistence, non-root, read-only rootfs, caps dropped, resource limits set

Primary files:
- `test/fixtures/docker-compose.yml`
- `test/run_fixtures.sh`
- `test/FIXTURE-STATUS.md`

## Quick usage

```bash
# Start all fixtures
bash test/run_fixtures.sh up

# Audit one fixture
bash test/run_fixtures.sh audit baseline
bash test/run_fixtures.sh audit vulnerable
bash test/run_fixtures.sh audit hardened

# Or run all audits in sequence
bash test/run_fixtures.sh audit-all

# Tear down when finished
bash test/run_fixtures.sh down
```

Artifacts are written to `output/fixtures/`.

## Expected validation themes
- auth enabled vs disabled
- protected mode on vs off
- broad bind vs loopback-only
- intentional persistence vs little/no persistence
- container hardening checks (non-root, read-only rootfs, caps drop, limits)

## Unit tests

```bash
make test
```

The live fixtures complement unit tests; they do not replace them.

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURE_DIR="$ROOT/test/fixtures"
OUTDIR="$ROOT/output/fixtures"
PYTHON_BIN="${PYTHON:-python3}"

usage() {
  cat <<'EOF'
Usage:
  test/run_fixtures.sh up
  test/run_fixtures.sh down
  test/run_fixtures.sh audit <baseline|vulnerable|hardened>
  test/run_fixtures.sh audit-all

Environment overrides:
  PYTHON   Python interpreter to use for audit.py (default: python3)
EOF
}

fixture_port() {
  case "$1" in
    baseline) echo 6380 ;;
    vulnerable) echo 6381 ;;
    hardened) echo 6382 ;;
    *) echo "Unknown fixture: $1" >&2; exit 1 ;;
  esac
}

fixture_container() {
  case "$1" in
    baseline) echo redis-baseline ;;
    vulnerable) echo redis-vulnerable ;;
    hardened) echo redis-hardened ;;
    *) echo "Unknown fixture: $1" >&2; exit 1 ;;
  esac
}

fixture_password_args() {
  case "$1" in
    hardened) echo --password Str0ngRedisPass!2026 ;;
    *) echo ;;
  esac
}

ensure_removed() {
  local container="$1"
  docker rm -f "$container" >/dev/null 2>&1 || true
}

start_fixture() {
  local fixture="$1"
  local container port
  container="$(fixture_container "$fixture")"
  port="$(fixture_port "$fixture")"
  ensure_removed "$container"

  case "$fixture" in
    baseline)
      docker run -d \
        --name "$container" \
        -p "$port:6379" \
        -v "$FIXTURE_DIR/baseline/redis.conf:/usr/local/etc/redis/redis.conf:ro" \
        redis:7.2-alpine \
        redis-server /usr/local/etc/redis/redis.conf >/dev/null
      ;;
    vulnerable)
      docker run -d \
        --name "$container" \
        -p "$port:6379" \
        -v "$FIXTURE_DIR/vulnerable/redis.conf:/usr/local/etc/redis/redis.conf:ro" \
        redis:7.2-alpine \
        redis-server /usr/local/etc/redis/redis.conf >/dev/null
      ;;
    hardened)
      docker run -d \
        --name "$container" \
        --user 999:999 \
        --read-only \
        --cap-drop ALL \
        --security-opt no-new-privileges:true \
        --memory 512m \
        --cpus 1.0 \
        --tmpfs /data:uid=999,gid=999,mode=770 \
        --tmpfs /tmp:uid=999,gid=999,mode=1777 \
        -p "$port:6379" \
        -v "$FIXTURE_DIR/hardened/redis.conf:/usr/local/etc/redis/redis.conf:ro" \
        -v "$FIXTURE_DIR/hardened/users.acl:/usr/local/etc/redis/users.acl:ro" \
        redis:7.2-alpine \
        redis-server /usr/local/etc/redis/redis.conf >/dev/null
      ;;
  esac
}

wait_for_fixture() {
  local fixture="$1"
  local container
  container="$(fixture_container "$fixture")"
  echo "[wait] waiting for $container"
  for _ in $(seq 1 30); do
    if docker exec "$container" redis-cli $(fixture_password_args "$fixture") PING >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Timed out waiting for $container" >&2
  docker logs "$container" || true
  exit 1
}

audit_fixture() {
  local fixture="$1"
  local container outbase
  container="$(fixture_container "$fixture")"
  outbase="$OUTDIR/$fixture"
  mkdir -p "$OUTDIR"
  wait_for_fixture "$fixture"
  # shellcheck disable=SC2086
  "$PYTHON_BIN" "$ROOT/audit.py" \
    --mode docker \
    --container "$container" \
    $(fixture_password_args "$fixture") \
    --skip-cve \
    --json "$outbase.json" \
    --sarif "$outbase.sarif" \
    --bundle "$outbase-bundle.zip" \
    --csv "$outbase.csv"
}

cmd="${1:-}"
case "$cmd" in
  up)
    start_fixture baseline
    start_fixture vulnerable
    start_fixture hardened
    ;;
  down)
    ensure_removed redis-baseline
    ensure_removed redis-vulnerable
    ensure_removed redis-hardened
    ;;
  audit)
    [[ $# -eq 2 ]] || { usage; exit 1; }
    audit_fixture "$2"
    ;;
  audit-all)
    start_fixture baseline
    start_fixture vulnerable
    start_fixture hardened
    audit_fixture baseline
    audit_fixture vulnerable
    audit_fixture hardened
    ;;
  *)
    usage
    exit 1
    ;;
esac

#!/usr/bin/env bash
# Phase 10.1B — Gate 2: Linux Docker Image Build & Web/Worker/Redis Integration Smoke Test.
# Builds the existing production Dockerfile, launches Redis 7 (noeviction), RQ worker, and
# Gunicorn web container on an isolated Docker network, verifies readiness/healthchecks/roles
# and logs without enqueueing any real scraping jobs, and always cleans up on exit.

set -euo pipefail

IMAGE_TAG="${IMAGE_TAG:-leadhunter-studio:ci-smoke}"
NETWORK_NAME="leadhunter-smoke-net"
REDIS_CONTAINER="leadhunter-smoke-redis"
WORKER_CONTAINER="leadhunter-smoke-worker"
WEB_CONTAINER="leadhunter-smoke-web"
WEB_PORT="15000"

SMOKE_API_KEY="$(python3 -c 'import secrets; print("smoke-" + secrets.token_hex(16))')"
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
  echo "::add-mask::${SMOKE_API_KEY}"
fi

FAILED=1

dump_diagnostics() {
  echo "=== Sanitized Failure Diagnostics ==="
  for c in "${REDIS_CONTAINER}" "${WORKER_CONTAINER}" "${WEB_CONTAINER}"; do
    if docker ps -a --format '{{.Names}}' | grep -qx "${c}"; then
      echo "--- Container state: ${c} ---"
      docker inspect --format 'Status={{.State.Status}} RestartCount={{.RestartCount}} Health={{if .State.Health}}{{.State.Health.Status}} FailingStreak={{.State.Health.FailingStreak}}{{else}}none{{end}}' "${c}" || true
      echo "--- Tail logs (sanitized): ${c} ---"
      docker logs --tail 60 "${c}" 2>&1 | sed "s/${SMOKE_API_KEY}/[REDACTED]/g; s|redis://[^[:space:]\"]*|redis://[REDACTED]|g" || true
    fi
  done
}

cleanup() {
  local exit_code=$?
  if [[ "${FAILED}" -ne 0 || "${exit_code}" -ne 0 ]]; then
    dump_diagnostics
  fi
  echo "=== Cleaning up Docker smoke resources ==="
  docker rm -f "${WEB_CONTAINER}" "${WORKER_CONTAINER}" "${REDIS_CONTAINER}" >/dev/null 2>&1 || true
  docker network rm "${NETWORK_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Pre-clean any stale resources from interrupted runs
docker rm -f "${WEB_CONTAINER}" "${WORKER_CONTAINER}" "${REDIS_CONTAINER}" >/dev/null 2>&1 || true
docker network rm "${NETWORK_NAME}" >/dev/null 2>&1 || true

echo "=== Step 1: Build existing production Dockerfile ==="
docker build -t "${IMAGE_TAG}" .

echo "=== Step 2: Create isolated Docker network ==="
docker network create "${NETWORK_NAME}" >/dev/null

echo "=== Step 3: Start Redis 7 container (noeviction) ==="
docker run -d \
  --name "${REDIS_CONTAINER}" \
  --network "${NETWORK_NAME}" \
  redis:7-alpine \
  redis-server --maxmemory 128mb --maxmemory-policy noeviction --save "" --appendonly no >/dev/null

for i in $(seq 1 30); do
  if [[ "$(docker exec "${REDIS_CONTAINER}" redis-cli ping 2>/dev/null || true)" == "PONG" ]]; then
    break
  fi
  if [[ "${i}" -eq 30 ]]; then
    echo "FAIL: Redis container did not become ready within 30s" >&2
    exit 1
  fi
  sleep 1
done

REDIS_VERSION="$(docker exec "${REDIS_CONTAINER}" redis-cli INFO server | awk -F: '/^redis_version:/ {gsub(/\r/, "", $2); print $2}')"
MAXMEMORY_POLICY="$(docker exec "${REDIS_CONTAINER}" redis-cli CONFIG GET maxmemory-policy | tail -n 1 | tr -d '\r')"
echo "Redis version=${REDIS_VERSION} maxmemory-policy=${MAXMEMORY_POLICY}"
if [[ "${REDIS_VERSION}" != 7.* ]]; then
  echo "FAIL: Expected Redis 7.x, got ${REDIS_VERSION}" >&2
  exit 1
fi
if [[ "${MAXMEMORY_POLICY}" != "noeviction" ]]; then
  echo "FAIL: Expected maxmemory-policy=noeviction, got ${MAXMEMORY_POLICY}" >&2
  exit 1
fi

echo "=== Step 4: Start RQ worker container (shared image, python worker.py) ==="
docker run -d \
  --name "${WORKER_CONTAINER}" \
  --network "${NETWORK_NAME}" \
  --health-interval=5s \
  --health-start-period=5s \
  --health-timeout=5s \
  --health-retries=3 \
  -e SERVICE_ROLE=worker \
  -e LEADHUNTER_ENV=production \
  -e LOG_LEVEL=INFO \
  -e LOG_FORMAT=json \
  -e BROWSER_MAX_CONCURRENCY=1 \
  -e JOB_TIMEOUT_SECONDS=900 \
  -e JOB_RESULT_TTL_SECONDS=3600 \
  -e JOB_FAILURE_TTL_SECONDS=3600 \
  -e JOB_MAX_RETRIES=2 \
  -e RQ_QUEUE_NAME=leadhunter \
  -e REDIS_URL="redis://${REDIS_CONTAINER}:6379/0" \
  "${IMAGE_TAG}" \
  python worker.py >/dev/null

echo "Polling worker registration & heartbeat (--healthcheck)..."
for i in $(seq 1 45); do
  if docker exec "${WORKER_CONTAINER}" python worker.py --healthcheck >/dev/null 2>&1; then
    break
  fi
  if [[ "${i}" -eq 45 ]]; then
    echo "FAIL: Worker --healthcheck did not pass within 45s" >&2
    exit 1
  fi
  sleep 1
done

echo "Polling worker Docker HEALTHCHECK status..."
for i in $(seq 1 45); do
  WORKER_HEALTH="$(docker inspect --format '{{.State.Health.Status}}' "${WORKER_CONTAINER}")"
  if [[ "${WORKER_HEALTH}" == "healthy" ]]; then
    break
  fi
  if [[ "${i}" -eq 45 ]]; then
    echo "FAIL: Worker Docker healthcheck did not reach healthy (status=${WORKER_HEALTH})" >&2
    exit 1
  fi
  sleep 1
done

WORKER_HEALTH_JSON="$(docker exec "${WORKER_CONTAINER}" python -c 'import json, worker; ok, d = worker.run_worker_healthcheck(); print(json.dumps({"healthy": ok, **d}))')"
echo "Worker healthcheck payload: ${WORKER_HEALTH_JSON}"
WORKER_USER="$(docker exec "${WORKER_CONTAINER}" id -un)"
if [[ "${WORKER_USER}" != "appuser" ]]; then
  echo "FAIL: Expected worker to run as non-root appuser, got ${WORKER_USER}" >&2
  exit 1
fi
# Confirm worker service role does NOT serve HTTP on port 5000
if docker exec "${WORKER_CONTAINER}" python -c 'import socket, sys; s = socket.socket(); s.settimeout(1); rc = s.connect_ex(("127.0.0.1", 5000)); s.close(); sys.exit(0 if rc == 0 else 1)'; then
  echo "FAIL: Worker container unexpectedly listening on HTTP port 5000" >&2
  exit 1
fi

echo "=== Step 5: Start Gunicorn web container (shared image, default entrypoint) ==="
docker run -d \
  --name "${WEB_CONTAINER}" \
  --network "${NETWORK_NAME}" \
  -p "127.0.0.1:${WEB_PORT}:5000" \
  --health-interval=5s \
  --health-start-period=5s \
  --health-timeout=5s \
  --health-retries=3 \
  -e SERVICE_ROLE=web \
  -e LEADHUNTER_ENV=production \
  -e PORT=5000 \
  -e LOG_LEVEL=INFO \
  -e LOG_FORMAT=json \
  -e TRUSTED_PROXY_HOPS=1 \
  -e WEB_CONCURRENCY=2 \
  -e GUNICORN_THREADS=4 \
  -e BROWSER_MAX_CONCURRENCY=1 \
  -e REQUIRE_ACTIVE_WORKER=true \
  -e RATE_LIMIT_MAX_REQUESTS=30 \
  -e RATE_LIMIT_WINDOW_SECONDS=60 \
  -e RATE_LIMIT_FAIL_CLOSED=true \
  -e REDIS_URL="redis://${REDIS_CONTAINER}:6379/0" \
  -e LEADHUNTER_API_KEY="${SMOKE_API_KEY}" \
  "${IMAGE_TAG}" >/dev/null

echo "Polling web Docker HEALTHCHECK status..."
for i in $(seq 1 60); do
  WEB_HEALTH="$(docker inspect --format '{{.State.Health.Status}}' "${WEB_CONTAINER}")"
  if [[ "${WEB_HEALTH}" == "healthy" ]]; then
    break
  fi
  if [[ "${i}" -eq 60 ]]; then
    echo "FAIL: Web Docker healthcheck did not reach healthy (status=${WEB_HEALTH})" >&2
    exit 1
  fi
  sleep 1
done

WEB_USER="$(docker exec "${WEB_CONTAINER}" id -un)"
if [[ "${WEB_USER}" != "appuser" ]]; then
  echo "FAIL: Expected web container to run as non-root appuser, got ${WEB_USER}" >&2
  exit 1
fi

echo "=== Step 6: Verify /healthz, /readyz, auth fail-closed, and Redis-backed status lookup ==="
HEALTHZ_BODY="$(curl -fsS "http://127.0.0.1:${WEB_PORT}/healthz")"
echo "/healthz response: ${HEALTHZ_BODY}"
python3 - "${HEALTHZ_BODY}" <<'PY'
import json, sys
data = json.loads(sys.argv[1])
assert data.get("status") == "ok", f"Unexpected /healthz status: {data}"
assert data.get("service") == "leadhunter-studio", f"Unexpected /healthz service: {data}"
PY

READYZ_BODY="$(curl -fsS "http://127.0.0.1:${WEB_PORT}/readyz")"
echo "/readyz response: ${READYZ_BODY}"
python3 - "${READYZ_BODY}" <<'PY'
import json, sys
data = json.loads(sys.argv[1])
assert data.get("status") == "ready", f"Expected ready status: {data}"
checks = data.get("checks", {})
assert checks.get("api_key_configured") is True, f"api_key_configured failed: {checks}"
assert checks.get("redis", {}).get("ok") is True, f"redis check failed: {checks}"
assert checks.get("workers", {}).get("ok") is True, f"workers check failed: {checks}"
assert int(checks.get("workers", {}).get("online", 0)) >= 1, f"expected >=1 online worker: {checks}"
assert checks.get("workers", {}).get("required") is True, f"expected workers.required=true: {checks}"
assert checks.get("chromium", {}).get("ok") is True, f"chromium check failed: {checks}"
PY

# Verify auth enforcement without enqueueing any scraping job
UNAUTH_CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"url":"https://example.com"}' "http://127.0.0.1:${WEB_PORT}/api/jobs")"
if [[ "${UNAUTH_CODE}" != "401" ]]; then
  echo "FAIL: Expected unauthenticated POST /api/jobs -> 401, got ${UNAUTH_CODE}" >&2
  exit 1
fi

# Verify authenticated Redis-backed lookup + live Redis Lua rate limiter without enqueueing any job
JOB_LOOKUP_CODE="$(curl -s -o /dev/null -w '%{http_code}' -H "X-API-Key: ${SMOKE_API_KEY}" "http://127.0.0.1:${WEB_PORT}/api/jobs/nonexistent-smoke-check")"
if [[ "${JOB_LOOKUP_CODE}" != "404" ]]; then
  echo "FAIL: Expected authenticated GET /api/jobs/nonexistent-smoke-check -> 404, got ${JOB_LOOKUP_CODE}" >&2
  exit 1
fi

echo "=== Step 7: Inspect container restart counts, healthcheck streaks, and logs ==="
for c in "${REDIS_CONTAINER}" "${WORKER_CONTAINER}" "${WEB_CONTAINER}"; do
  RESTARTS="$(docker inspect --format '{{.RestartCount}}' "${c}")"
  if [[ "${RESTARTS}" != "0" ]]; then
    echo "FAIL: Container ${c} had RestartCount=${RESTARTS}" >&2
    exit 1
  fi
done

for c in "${WORKER_CONTAINER}" "${WEB_CONTAINER}"; do
  STREAK="$(docker inspect --format '{{.State.Health.FailingStreak}}' "${c}")"
  if [[ "${STREAK}" != "0" ]]; then
    echo "FAIL: Container ${c} had healthcheck FailingStreak=${STREAK}" >&2
    exit 1
  fi
done

for c in "${WEB_CONTAINER}" "${WORKER_CONTAINER}" "${REDIS_CONTAINER}"; do
  LOGS="$(docker logs "${c}" 2>&1 || true)"
  if printf '%s' "${LOGS}" | grep -q "Traceback (most recent call last):"; then
    echo "FAIL: Traceback detected in ${c} container logs" >&2
    exit 1
  fi
  if printf '%s' "${LOGS}" | grep -Fq "${SMOKE_API_KEY}"; then
    echo "FAIL: API key leaked in ${c} container logs" >&2
    exit 1
  fi
  if printf '%s' "${LOGS}" | grep -q "redis://"; then
    echo "FAIL: Raw redis:// URL leaked in ${c} container logs" >&2
    exit 1
  fi
done

FAILED=0
echo "=== Gate 2 PASS: Docker build and web/worker/Redis integration verified ==="

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## Gate 2 — Linux Docker Build & Web/Worker/Redis Smoke Test: PASS"
    echo ""
    echo "- **Docker image:** \`${IMAGE_TAG}\` (built from production \`Dockerfile\`)"
    echo "- **Redis container:** \`redis:7-alpine\` (version \`${REDIS_VERSION}\`, \`maxmemory-policy=${MAXMEMORY_POLICY}\`)"
    echo "- **Worker container:** \`SERVICE_ROLE=worker\`, user=\`${WORKER_USER}\`, Docker health=\`${WORKER_HEALTH}\`, \`--healthcheck\` passed, no HTTP port 5000 listener"
    echo "- **Web container:** \`SERVICE_ROLE=web\`, user=\`${WEB_USER}\`, Docker health=\`${WEB_HEALTH}\`, \`/healthz\`=200, \`/readyz\`=200 (\`REQUIRE_ACTIVE_WORKER=true\`)"
    echo "- **Auth & Redis API smoke (no job enqueued):** unauthenticated \`POST /api/jobs\`=\`${UNAUTH_CODE}\`, authenticated \`GET /api/jobs/nonexistent-smoke-check\`=\`${JOB_LOOKUP_CODE}\`"
    echo "- **Log & stability checks:** 0 restarts, 0 healthcheck failing streaks, 0 tracebacks, 0 leaked secrets/URLs"
    echo ""
  } >> "${GITHUB_STEP_SUMMARY}"
fi

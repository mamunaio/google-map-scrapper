# LeadHunter Studio

**Lead Intelligence & Business Opportunity Detection Platform** built with **Python 3.12+**, **Flask**, **Playwright Chromium**, **Redis 7**, and **RQ**.

LeadHunter Studio extracts Google Maps business leads, performs technical/SEO/feature/opportunity audits with SSRF and DNS-rebinding protection, verifies contact emails, and exports standardized 3-sheet Excel workbooks (`16 / 15 / 7` columns) and 16-column Lead Tracker CSVs.

---

## Requirements

- **Python 3.12+** (Docker production baseline: `python:3.12-slim-bookworm`)
- **Playwright Chromium** (`playwright==1.65.1`)
- **Redis 7** with `maxmemory-policy noeviction` (for async `/api/jobs` RQ queue and shared atomic Lua sliding-window rate limiting)
- **Docker** (for production container builds and local Redis/container smoke tests)

---

## Local Development Setup

1. **Clone and create a virtual environment:**
   ```bash
   git clone https://github.com/mamunaio/google-map-scrapper.git
   cd google-map-scrapper
   python -m venv .venv
   # Windows PowerShell: .\.venv\Scripts\Activate.ps1
   # Linux/macOS:        source .venv/bin/activate
   ```

2. **Install dependencies and Playwright Chromium:**
   ```bash
   pip install -r requirements.txt
   python -m playwright install chromium
   ```
   *(For running tests locally, also install `pip install -r requirements-dev.txt`.)*

3. **Configure local environment variables (`.env`):**
   Copy `.env.example` to `.env` (`.env` is gitignored and never committed) and set a strong random `LEADHUNTER_API_KEY`:
   ```bash
   cp .env.example .env
   ```
   Key local `.env` settings:
   - `LEADHUNTER_API_KEY` — **Required** in all environments. Requests fail closed with HTTP `503` when unset.
   - `LEADHUNTER_ENV=development`
   - `REDIS_URL=redis://127.0.0.1:6379/0`
   - `REQUIRE_ACTIVE_WORKER=false` (set `true` in production)
   - `GOOGLE_PAGESPEED_API_KEY` — Optional external API key for Google PageSpeed Insights.

   `app.py` and `worker.py` automatically load `<project_root>/.env` in local development (without overriding existing shell environment variables, and skipped automatically in production and under `pytest`).

4. **Start Redis 7 (production-like `noeviction` policy):**
   ```bash
   docker run -d --name leadhunter-redis7 -p 127.0.0.1:6379:6379 \
     redis:7-alpine redis-server --maxmemory 128mb --maxmemory-policy noeviction
   ```

5. **Run the web server and RQ background worker:**
   ```bash
   # Terminal 1 — Web UI & API (binds strictly to 127.0.0.1:5000 by default)
   python app.py

   # Terminal 2 — Dedicated RQ Background Worker
   python worker.py
   ```
   Open `http://127.0.0.1:5000` in your browser.

---

## Authentication & Security Architecture

LeadHunter Studio enforces **fail-closed dual-mode authentication** on all protected `/api/*` endpoints:

1. **Programmatic / External API Clients (all environments):**
   Send `X-API-Key: <LEADHUNTER_API_KEY>` or `Authorization: Bearer <LEADHUNTER_API_KEY>`.
   - Missing server `LEADHUNTER_API_KEY` → HTTP `503` (fail-closed).
   - Missing or invalid client credentials → HTTP `401`.

2. **Built-in Web UI Automatic Session (`UI_AUTO_SESSION`):**
   - **Verified loopback-only local development (default enabled):** When not in production, not in a container, `TRUSTED_PROXY_HOPS=0`, and bound/accessed strictly over loopback (`127.0.0.1` / `localhost` / `::1`), `GET /` issues an `HttpOnly; SameSite=Strict` HMAC-SHA256 signed session cookie (`lh_ui_session`) paired with a domain-separated `X-CSRF-Token` `<meta>` token. `LEADHUNTER_API_KEY` is never exposed in HTML, JavaScript, browser storage, or cookies.
   - **Non-loopback & production deployments (default disabled):** `UI_AUTO_SESSION` is disabled by default whenever `LEADHUNTER_ENV=production`, `FLASK_ENV=production`, `RENDER=true`, `CONTAINER=true`, `TRUSTED_PROXY_HOPS > 0`, or a non-loopback bind/client/host is detected. The UI displays an **Access Key** input instead.
   - **Authenticated reverse-proxy opt-in (advanced):** Enabling UI auto-sessions behind an upstream authenticating proxy requires **all** of:
     1. Network-level origin isolation blocking direct backend access outside the proxy.
     2. `UI_AUTO_SESSION=true`
     3. `UI_AUTO_SESSION_BEHIND_TRUSTED_AUTH_PROXY=true`
     4. `TRUSTED_PROXY_HOPS > 0`
     5. A distinct `TRUSTED_AUTH_PROXY_SECRET` (never equal to `LEADHUNTER_API_KEY`), injected per-request by the proxy in `X-Trusted-Auth-Proxy-Secret` (configurable via `TRUSTED_AUTH_PROXY_HEADER`) after stripping any client-supplied value.
   - Every UI cookie-authenticated request validates the HMAC session signature, bounded TTL (`UI_SESSION_TTL_SECONDS`, default 8h), constant-time `X-CSRF-Token`, and strict same-origin headers (`Origin`, `Referer`, `Sec-Fetch-Site: same-origin`).

3. **Additional Hardening Controls:**
   - Outbound SSRF & DNS-rebinding protection (`SafeBrowserProxy`, Playwright route interception blocking private/loopback/metadata IPs and `data:` navigations, pinned public-IP SSL/SMTP sockets).
   - Atomic Redis Lua sliding-window rate limiting (fails closed in production when Redis is unavailable).
   - DOM XSS remediation (zero `.innerHTML`, strict URL sanitization).

---

## Background Jobs & Operational Endpoints

- **Async Job Lifecycle (Redis 7 + RQ):**
  - `POST /api/jobs` — Enqueues a scrape/audit job with atomic deduplication reservation, lease renewal, bounded retries, and timeout enforcement.
  - `GET /api/jobs/<job_id>` — Returns normalized job status and progress metadata.
  - `GET /api/jobs/<job_id>/result` — Returns completed job results.
- **Health & Readiness Probes:**
  - `GET /healthz` — Lightweight unauthenticated liveness check (`{"status": "ok", "service": "leadhunter-studio"}`).
  - `GET /readyz` — Readiness probe checking `LEADHUNTER_API_KEY` presence, Redis connectivity, active RQ worker heartbeat freshness (when `REQUIRE_ACTIVE_WORKER=true`), and Playwright Chromium availability.
  - `python worker.py --healthcheck` — CLI worker healthcheck used by Docker `HEALTHCHECK` when `SERVICE_ROLE=worker`.

---

## Docker & Render Production Deployment

The repository ships a shared production `Dockerfile` (`python:3.12-slim-bookworm` + `libatomic1` + Playwright Chromium, non-root `appuser`, role-aware `HEALTHCHECK`) and a Render Blueprint (`render.yaml`):

- **Web service (`SERVICE_ROLE=web`):** Runs `gunicorn -c gunicorn.conf.py app:app` (`gthread`, fails fast on invalid startup config, `UI_AUTO_SESSION=false`).
- **Worker service (`SERVICE_ROLE=worker`):** Uses the same image with command `python worker.py` (`BROWSER_MAX_CONCURRENCY=1`).
- **Redis service:** Managed Redis 7 with `maxmemoryPolicy: noeviction`.

Build locally with Docker:
```bash
docker build -t leadhunter-studio:local .
```

---

## Testing & Verification

```bash
# Install dev/test dependencies
pip install -r requirements-dev.txt

# Run the complete automated test suite
pytest -v

# Run live Redis 7 Lua EVAL verification (requires running Redis 7)
REDIS_URL=redis://127.0.0.1:6379/0 python scripts/verify_live_redis_lua.py

# Run Linux Docker build & web/worker/Redis integration smoke test
bash scripts/verify_docker_smoke.sh
```

---

## Repository Structure

```text
app.py                  # Flask API gateway, dual-mode auth, health/readiness probes
worker.py               # Dedicated RQ background worker & --healthcheck CLI
gunicorn.conf.py        # Production Gunicorn WSGI configuration
Dockerfile              # Shared production Docker image (web + worker + Playwright Chromium)
render.yaml             # Render Docker Blueprint (web + worker + Redis 7 noeviction)
services/               # Modular scraping, auditing, security, scoring, queue & export services
templates/              # Web UI template (zero innerHTML, CSRF/session aware)
static/                 # Local static assets (Tailwind CSS bundle)
tests/                  # Automated unit, security, runtime & export-schema parity tests
scripts/                # Live Redis 7 Lua EVAL & Docker integration verification scripts
docs/reports/           # Archived phase audits, hardening & verification reports
docs/pilots/            # Archived Dallas HVAC pilot verification exports (CSV/JSON/XLSX)
```

# LeadHunter Studio — Production Docker Image (Web & RQ Worker Shared Image)
# Target baseline: Python 3.12 on Debian Bookworm with Playwright Chromium OS dependencies.

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    CONTAINER=true \
    SERVICE_ROLE=web \
    PORT=5000

WORKDIR /app

# Create non-root runtime user
RUN groupadd --system appgroup && useradd --system --gid appgroup --create-home appuser

# Install pinned Python dependencies first for Docker layer caching
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Install Playwright Chromium and required Debian system libraries as root,
# then grant read/execute access to non-root runtime user
RUN apt-get update \
    && apt-get install -y --no-install-recommends libatomic1 \
    && playwright install --with-deps chromium \
    && chmod -R a+rX /ms-playwright \
    && rm -rf /var/lib/apt/lists/*

# Copy application source files (strictly filtered by .dockerignore)
COPY app.py worker.py gunicorn.conf.py /app/
COPY services /app/services
COPY templates /app/templates
COPY static /app/static

RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 5000

# Role-aware healthcheck:
# - Web container (SERVICE_ROLE=web): HTTP liveness probe against /healthz
# - Worker container (SERVICE_ROLE=worker): Redis connectivity & RQ worker heartbeat probe (no HTTP server)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os, sys, urllib.request; role = os.getenv('SERVICE_ROLE', 'web').strip().lower(); sys.exit(0 if (__import__('worker').run_worker_healthcheck()[0]) else 1) if role == 'worker' else urllib.request.urlopen(f'http://127.0.0.1:{os.getenv(\"PORT\", \"5000\")}/healthz', timeout=3)" || exit 1

# Default command starts the production Gunicorn web server.
# The Render background worker overrides this with: python worker.py
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]

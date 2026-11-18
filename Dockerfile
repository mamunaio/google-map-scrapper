# LeadHunter Studio — Production Docker Image (Web & RQ Worker Shared Image)
# Target baseline: Python 3.12 on Debian Bookworm with Playwright Chromium OS dependencies.

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    CONTAINER=true \
    PORT=5000

WORKDIR /app

# Create non-root runtime user
RUN groupadd --system appgroup && useradd --system --gid appgroup --create-home appuser

# Install pinned Python dependencies first for Docker layer caching
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Install Playwright Chromium and required Debian system libraries as root,
# then grant read/execute access to non-root runtime user
RUN playwright install --with-deps chromium \
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

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os, urllib.request; port = os.getenv('PORT', '5000'); urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=3)" || exit 1

# Default command starts the production Gunicorn web server.
# The Render background worker overrides this with: python worker.py
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]

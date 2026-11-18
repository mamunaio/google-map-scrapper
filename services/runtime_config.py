"""
LeadHunter Runtime Configuration, Startup Validation & Structured Logging Module.
Provides safe environment variable parsing, correlation ID context, PII-safe log redaction,
and Gunicorn-compatible structured stdout logging.
"""

import contextvars
import json
import logging
import os
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

# Request and background job correlation context variables
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
job_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("job_id", default="-")


class RuntimeConfigError(ValueError):
    """Raised when required runtime configuration is missing or invalid."""


def is_production_env() -> bool:
    """Detects production execution mode from standard environment variables."""
    leadhunter_env = os.getenv("LEADHUNTER_ENV", "").strip().lower()
    flask_env = os.getenv("FLASK_ENV", "").strip().lower()
    render_flag = os.getenv("RENDER", "").strip().lower()
    return (
        leadhunter_env in ("prod", "production")
        or flask_env in ("prod", "production")
        or render_flag in ("1", "true", "yes")
    )


def should_enable_debug() -> bool:
    """
    Flask debug mode is disabled by default and strictly forbidden in production.
    Can only be enabled locally via FLASK_DEBUG=true when not in production.
    """
    if is_production_env():
        return False
    return os.getenv("FLASK_DEBUG", "").strip().lower() in ("1", "true", "yes")


def get_configured_api_key() -> str:
    """Reads the API key strictly from environment configuration (never hardcoded)."""
    return os.getenv("LEADHUNTER_API_KEY", "").strip()


def get_int_env(
    name: str,
    default: int,
    *,
    min_value: int | None = None,
    max_value: int | None = None,
    strict: bool = False,
) -> int:
    """
    Safely parses an integer environment variable with optional bounds.
    When `strict=True`, invalid or out-of-range values raise `RuntimeConfigError`.
    When `strict=False`, falls back to `default` (clamped to bounds) while logging a warning.
    """
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        val = int(raw.strip())
    except ValueError as exc:
        if strict:
            raise RuntimeConfigError(f"Environment variable '{name}' must be a valid integer.") from exc
        logging.getLogger("leadhunter.config").warning(
            "Invalid integer for env var %s; falling back to default=%d", name, default
        )
        return default

    if min_value is not None and val < min_value:
        if strict:
            raise RuntimeConfigError(f"Environment variable '{name}' must be >= {min_value}.")
        logging.getLogger("leadhunter.config").warning(
            "Env var %s below minimum (%d); using %d", name, min_value, min_value
        )
        return min_value

    if max_value is not None and val > max_value:
        if strict:
            raise RuntimeConfigError(f"Environment variable '{name}' must be <= {max_value}.")
        logging.getLogger("leadhunter.config").warning(
            "Env var %s above maximum (%d); using %d", name, max_value, max_value
        )
        return max_value

    return val


def get_bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def get_trusted_proxy_hops(strict: bool = False) -> int:
    """
    Returns validated TRUSTED_PROXY_HOPS (0..10).
    Defaults strictly to 0 so unproxied deployments ignore spoofable X-Forwarded-* headers.
    """
    return get_int_env("TRUSTED_PROXY_HOPS", 0, min_value=0, max_value=10, strict=strict)


def get_redis_url() -> str:
    return os.getenv("REDIS_URL", "").strip()


def validate_startup_config(
    *,
    require_api_key_in_prod: bool = True,
    require_redis_in_prod: bool = False,
) -> dict:
    """
    Validates runtime configuration safely at startup without ever exposing secret values.
    Raises `RuntimeConfigError` if validation fails.
    """
    prod = is_production_env()
    errors: list[str] = []

    try:
        max_content = get_int_env("MAX_CONTENT_LENGTH", 5 * 1024 * 1024, min_value=1024, max_value=50 * 1024 * 1024, strict=True)
    except RuntimeConfigError as e:
        errors.append(str(e))
        max_content = 5 * 1024 * 1024

    try:
        proxy_hops = get_trusted_proxy_hops(strict=True)
    except RuntimeConfigError as e:
        errors.append(str(e))
        proxy_hops = 0

    try:
        browser_concurrency = get_int_env("BROWSER_MAX_CONCURRENCY", 2, min_value=1, max_value=8, strict=True)
    except RuntimeConfigError as e:
        errors.append(str(e))
        browser_concurrency = 2

    try:
        job_timeout = get_int_env("JOB_TIMEOUT_SECONDS", 900, min_value=30, max_value=3600, strict=True)
    except RuntimeConfigError as e:
        errors.append(str(e))
        job_timeout = 900

    api_key_present = bool(get_configured_api_key())
    redis_url_present = bool(get_redis_url())

    if prod and require_api_key_in_prod and not api_key_present:
        errors.append("Required production secret 'LEADHUNTER_API_KEY' is not set.")

    if prod and require_redis_in_prod and not redis_url_present:
        errors.append("Required production setting 'REDIS_URL' is not set.")

    if errors:
        raise RuntimeConfigError("Startup configuration validation failed: " + " | ".join(errors))

    return {
        "production": prod,
        "api_key_configured": api_key_present,
        "redis_configured": redis_url_present,
        "max_content_length": max_content,
        "trusted_proxy_hops": proxy_hops,
        "browser_max_concurrency": browser_concurrency,
        "job_timeout_seconds": job_timeout,
    }


def redact_url_for_log(url: str) -> str:
    """Strips query parameters, fragments, and embedded credentials from URLs before logging."""
    if not url or not isinstance(url, str):
        return "-"
    try:
        parsed = urlparse(url.strip())
        if not parsed.scheme or not parsed.hostname:
            return "<invalid-url>"
        port_part = f":{parsed.port}" if parsed.port else ""
        path_part = parsed.path or "/"
        return f"{parsed.scheme}://{parsed.hostname}{port_part}{path_part}"
    except Exception:
        return "<unparseable-url>"


def redact_email_for_log(email: str) -> str:
    """Avoids logging raw personal/business email addresses (PII) in operational INFO logs."""
    return "present" if (email and "@" in str(email)) else "none"


class _CorrelationFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        record.job_id = job_id_var.get()
        return True


class _JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "request_id": getattr(record, "request_id", "-"),
            "job_id": getattr(record, "job_id", "-"),
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging() -> logging.Logger:
    """
    Configures Gunicorn-safe structured stdout logging under the `leadhunter` logger namespace.
    Uses JSON formatting in production (or when LOG_FORMAT=json) and human-readable text locally.
    """
    level_name = os.getenv("LOG_LEVEL", "INFO").strip().upper()
    level = getattr(logging, level_name, logging.INFO)

    log_format = os.getenv("LOG_FORMAT", "").strip().lower()
    use_json = (log_format == "json") or (not log_format and is_production_env())

    root_lh = logging.getLogger("leadhunter")
    root_lh.setLevel(level)
    root_lh.propagate = False

    # Replace existing handlers cleanly to avoid duplicates across reloads/tests
    for existing in list(root_lh.handlers):
        root_lh.removeHandler(existing)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    handler.addFilter(_CorrelationFilter())
    if use_json:
        handler.setFormatter(_JsonLogFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s [req=%(request_id)s job=%(job_id)s]: %(message)s"
            )
        )

    root_lh.addHandler(handler)
    return root_lh

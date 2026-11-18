"""
LeadHunter Runtime Configuration, Startup Validation & Structured Logging Module.
Provides safe environment variable parsing, correlation ID context, PII-safe log redaction,
and Gunicorn-compatible structured stdout logging.
"""

import contextvars
import hmac
import ipaddress
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Request and background job correlation context variables
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
job_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("job_id", default="-")


class RuntimeConfigError(ValueError):
    """Raised when required runtime configuration is missing or invalid."""


def _parse_dotenv_line(line: str) -> tuple[str, str] | None:
    """Parses a single `.env` assignment line safely without evaluating code."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("export "):
        stripped = stripped[7:].strip()
    if "=" not in stripped:
        return None
    key, raw_val = stripped.split("=", 1)
    key = key.strip()
    if not key or not (key[0].isalpha() or key[0] == "_") or not all(ch.isalnum() or ch == "_" for ch in key):
        return None

    val = raw_val.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
        val = val[1:-1]
    else:
        # Strip inline comment on unquoted values (e.g. `PORT=5000 # local port`)
        hash_idx = val.find(" #")
        if hash_idx != -1:
            val = val[:hash_idx].rstrip()
    return key, val


def load_local_dotenv(env_path: str | os.PathLike | None = None, *, override: bool = False) -> bool:
    """
    Loads local development environment variables from `<project_root>/.env` without
    requiring third-party packages.

    Safety guarantees:
    - Resolves `.env` relative to the repository root (`PROJECT_ROOT`), independent of CWD.
    - Never runs automatically in production (`is_production_env()`) or under `pytest`
      unless `env_path` is explicitly provided.
    - Never overrides already-set environment variables when `override=False`.
    - Never logs or prints secret values.
    """
    if env_path is None:
        if is_production_env():
            return False
        if "pytest" in sys.modules or "PYTEST_CURRENT_TEST" in os.environ:
            return False
        target = PROJECT_ROOT / ".env"
    else:
        target = Path(env_path)

    if not target.is_file():
        return False

    try:
        content = target.read_text(encoding="utf-8-sig")
    except OSError:
        return False

    loaded_any = False
    for line in content.splitlines():
        parsed = _parse_dotenv_line(line)
        if not parsed:
            continue
        key, value = parsed
        if override or key not in os.environ:
            os.environ[key] = value
            loaded_any = True
    return loaded_any


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


def is_loopback_address(addr: str | None) -> bool:
    """
    Returns True ONLY for strict loopback hostnames/IPs (`localhost`, `127.0.0.0/8`, `::1`,
    or IPv4-mapped loopback `::ffff:127.0.0.0/8`). Rejects `0.0.0.0`, `::`, LAN IPs, and public hosts.
    """
    if not addr or not isinstance(addr, str):
        return False
    cleaned = addr.strip().lower()
    if not cleaned:
        return False
    # Strip optional IPv6 brackets and scope identifier
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    if "%" in cleaned:
        cleaned = cleaned.split("%", 1)[0]
    if cleaned == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(cleaned)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped.is_loopback
    return ip.is_loopback


def _extract_hostname_from_host_header(host_header: str | None) -> str:
    """Extracts the bare hostname from an HTTP Host header (`host[:port]` or `[ipv6][:port]`)."""
    if not host_header or not isinstance(host_header, str):
        return ""
    raw = host_header.strip()
    if not raw:
        return ""
    if raw.startswith("["):
        end_bracket = raw.find("]")
        if end_bracket == -1:
            return ""
        return raw[1:end_bracket]
    if raw.count(":") == 1:
        return raw.split(":", 1)[0]
    return raw


def get_local_bind_host() -> str:
    """Returns the configured local bind host, defaulting strictly to loopback `127.0.0.1`."""
    raw = (os.getenv("HOST") or os.getenv("FLASK_RUN_HOST") or "").strip()
    return raw if raw else "127.0.0.1"


def is_loopback_only_local_deployment() -> bool:
    """
    Verifies that the server configuration is a strictly loopback-only local development deployment:
    - Not in production (`LEADHUNTER_ENV`, `FLASK_ENV`, `RENDER`)
    - Not running inside a container (`CONTAINER=true` or `/.dockerenv`)
    - No trusted reverse proxy hops configured (`TRUSTED_PROXY_HOPS == 0`)
    - Configured bind host (`HOST` / `FLASK_RUN_HOST`, default `127.0.0.1`) is strictly loopback
    """
    if is_production_env():
        return False
    if get_bool_env("CONTAINER", False) or os.path.exists("/.dockerenv"):
        return False
    if get_trusted_proxy_hops(strict=False) > 0:
        return False
    return is_loopback_address(get_local_bind_host())


def get_trusted_auth_proxy_secret() -> str:
    """Reads the shared secret injected by an upstream authenticating reverse proxy."""
    return os.getenv("TRUSTED_AUTH_PROXY_SECRET", "").strip()


def get_trusted_auth_proxy_header_name() -> str:
    """Returns the HTTP header name carrying the authenticating proxy shared secret."""
    raw = os.getenv("TRUSTED_AUTH_PROXY_HEADER", "").strip()
    return raw if raw else "X-Trusted-Auth-Proxy-Secret"


def is_trusted_auth_proxy_ui_session_enabled(
    *,
    proxy_secret_header: str | None = None,
) -> bool:
    """
    Verifies BOTH explicit operator configuration AND per-request cryptographic proxy proof:
    - `UI_AUTO_SESSION_BEHIND_TRUSTED_AUTH_PROXY=true`
    - `TRUSTED_PROXY_HOPS > 0`
    - `TRUSTED_AUTH_PROXY_SECRET` is configured and distinct from `LEADHUNTER_API_KEY`
    - Incoming request carries the exact matching shared secret in `TRUSTED_AUTH_PROXY_HEADER`
      (default `X-Trusted-Auth-Proxy-Secret`), verified via `hmac.compare_digest()`.

    Environment flags and `TRUSTED_PROXY_HOPS` alone NEVER prove that a request traversed
    an authenticating proxy; direct backend requests bypassing the proxy are always rejected.
    """
    if not get_bool_env("UI_AUTO_SESSION_BEHIND_TRUSTED_AUTH_PROXY", False):
        return False
    if get_trusted_proxy_hops(strict=False) <= 0:
        return False
    expected_proxy_secret = get_trusted_auth_proxy_secret()
    if not expected_proxy_secret:
        return False
    api_key = get_configured_api_key()
    if api_key and hmac.compare_digest(expected_proxy_secret, api_key):
        return False
    provided = (proxy_secret_header or "").strip()
    if not provided:
        return False
    return hmac.compare_digest(provided, expected_proxy_secret)


def _is_verified_loopback_request(
    *,
    remote_addr: str | None = None,
    host_header: str | None = None,
) -> bool:
    if not is_loopback_only_local_deployment():
        return False
    if remote_addr is not None and not is_loopback_address(remote_addr):
        return False
    if host_header is not None and not is_loopback_address(_extract_hostname_from_host_header(host_header)):
        return False
    return True


def is_ui_auto_session_enabled(
    *,
    remote_addr: str | None = None,
    host_header: str | None = None,
    proxy_secret_header: str | None = None,
) -> bool:
    """
    Controls automatic same-origin UI session authentication (HttpOnly signed cookie + CSRF token).
    - Explicit `UI_AUTO_SESSION=false` always disables automatic UI sessions.
    - Explicit `UI_AUTO_SESSION=true` NEVER bypasses network safety restrictions: it is permitted
      ONLY for either:
        1. A verified loopback-only local deployment (loopback bind, no container, no proxy hops,
           and loopback peer IP + Host header), OR
        2. An explicitly opted-in authenticating reverse-proxy deployment
           (`UI_AUTO_SESSION_BEHIND_TRUSTED_AUTH_PROXY=true` AND `TRUSTED_PROXY_HOPS > 0` AND
           a valid per-request `TRUSTED_AUTH_PROXY_SECRET` header verified in constant time).
    - When `UI_AUTO_SESSION` is unset (default): enabled ONLY for a verified loopback-only local
      deployment; disabled by default for all non-loopback, proxy, container, and production setups.
    """
    explicit = os.getenv("UI_AUTO_SESSION")
    if explicit is not None and explicit.strip():
        if explicit.strip().lower() not in ("1", "true", "yes", "on"):
            return False
        if _is_verified_loopback_request(remote_addr=remote_addr, host_header=host_header):
            return True
        return is_trusted_auth_proxy_ui_session_enabled(proxy_secret_header=proxy_secret_header)

    return _is_verified_loopback_request(remote_addr=remote_addr, host_header=host_header)


def get_ui_session_ttl_seconds() -> int:
    """Returns bounded lifetime (seconds) for signed UI session cookies (default: 8 hours)."""
    return get_int_env("UI_SESSION_TTL_SECONDS", 28800, min_value=60, max_value=86400)


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

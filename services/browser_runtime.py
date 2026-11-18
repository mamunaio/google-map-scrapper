"""
LeadHunter Browser Runtime & Concurrency Control Module.
Provides container-safe Chromium launch configuration, bounded concurrent browser/page
execution slots, deterministic teardown on failure/timeout/shutdown, and readiness checks.
"""

import logging
import os
import sys
import threading
from contextlib import contextmanager

from services.runtime_config import get_bool_env, get_int_env

logger = logging.getLogger("leadhunter.browser")


class BrowserConcurrencyError(RuntimeError):
    """Raised when browser concurrency slots are exhausted beyond the configured acquire timeout."""


_sem_lock = threading.Lock()
_browser_semaphore: threading.BoundedSemaphore | None = None
_browser_semaphore_limit: int = 0
_active_browsers_count: int = 0


def _ensure_semaphore() -> threading.BoundedSemaphore:
    global _browser_semaphore, _browser_semaphore_limit
    configured_limit = get_int_env("BROWSER_MAX_CONCURRENCY", 2, min_value=1, max_value=8)
    with _sem_lock:
        if _browser_semaphore is None or _browser_semaphore_limit != configured_limit:
            _browser_semaphore = threading.BoundedSemaphore(configured_limit)
            _browser_semaphore_limit = configured_limit
        return _browser_semaphore


def reset_browser_concurrency_state():
    """Resets the module semaphore (intended for unit tests)."""
    global _browser_semaphore, _browser_semaphore_limit, _active_browsers_count
    with _sem_lock:
        _browser_semaphore = None
        _browser_semaphore_limit = 0
        _active_browsers_count = 0


def get_active_browser_count() -> int:
    with _sem_lock:
        return _active_browsers_count


def is_running_in_container() -> bool:
    """Detects standard Linux Docker/Render container environments."""
    return (
        sys.platform.startswith("linux")
        and (
            os.path.exists("/.dockerenv")
            or get_bool_env("RENDER", False)
            or get_bool_env("CONTAINER", False)
        )
    )


def get_chromium_launch_args() -> list[str]:
    """
    Returns container-appropriate Chromium flags:
    - Always passes `--disable-dev-shm-usage` (prevents 64MB /dev/shm crashes in containers)
      and `--disable-gpu` for headless stability.
    - Enables `--no-sandbox` / `--disable-setuid-sandbox` only on Linux container runtimes
      or when explicitly requested via `CHROMIUM_NO_SANDBOX=true`.
    """
    args = [
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--disable-background-networking",
        "--disable-default-apps",
        "--no-first-run",
    ]
    if is_running_in_container() or get_bool_env("CHROMIUM_NO_SANDBOX", False):
        args.extend(["--no-sandbox", "--disable-setuid-sandbox"])
    return args


def get_chromium_launch_options() -> dict:
    """Returns keyword arguments passed to `playwright.chromium.launch(...)`."""
    return {
        "headless": True,
        "args": get_chromium_launch_args(),
    }


@contextmanager
def acquire_browser_slot(timeout: float | None = None):
    """
    Acquires one bounded browser execution slot, releasing it deterministically on exit.
    Raises `BrowserConcurrencyError` if no slot becomes available within `timeout` seconds.
    """
    global _active_browsers_count
    sem = _ensure_semaphore()
    acquire_timeout = (
        timeout
        if timeout is not None
        else float(get_int_env("BROWSER_ACQUIRE_TIMEOUT_SECONDS", 30, min_value=1, max_value=300))
    )
    acquired = sem.acquire(timeout=acquire_timeout)
    if not acquired:
        raise BrowserConcurrencyError(
            f"Browser concurrency limit ({_browser_semaphore_limit}) reached; timed out waiting {acquire_timeout}s."
        )
    with _sem_lock:
        _active_browsers_count += 1
    try:
        yield
    finally:
        with _sem_lock:
            _active_browsers_count = max(0, _active_browsers_count - 1)
        sem.release()


def safe_close_playwright_resources(page=None, context=None, browser=None):
    """Deterministically closes Playwright page, context, and browser without masking original exceptions."""
    for label, resource in (("page", page), ("context", context), ("browser", browser)):
        if resource is not None:
            try:
                resource.close()
            except Exception as exc:
                logger.debug("Error closing Playwright %s during cleanup: %s", label, exc)


def check_chromium_available() -> tuple[bool, str]:
    """
    Lightweight readiness check verifying that Playwright Chromium binary is installed on disk
    without launching a browser subprocess.
    """
    try:
        from playwright._impl._driver import compute_driver_executable
        driver_exec = compute_driver_executable()
        if isinstance(driver_exec, tuple):
            driver_path = driver_exec[0]
        else:
            driver_path = driver_exec
        if not driver_path or not os.path.exists(driver_path):
            return False, "Playwright driver executable not found"
    except Exception as exc:
        return False, f"Playwright driver check failed: {exc}"

    # Check common Playwright browser cache locations
    candidates: list[str] = []
    env_browsers_path = os.getenv("PLAYWRIGHT_BROWSERS_PATH", "").strip()
    if env_browsers_path and env_browsers_path != "0":
        candidates.append(env_browsers_path)
    if sys.platform == "win32":
        local_app = os.getenv("LOCALAPPDATA", "")
        if local_app:
            candidates.append(os.path.join(local_app, "ms-playwright"))
    else:
        candidates.extend([
            "/ms-playwright",
            os.path.expanduser("~/.cache/ms-playwright"),
        ])

    for base in candidates:
        if os.path.isdir(base):
            try:
                entries = os.listdir(base)
                if any(e.startswith("chromium") for e in entries):
                    return True, "Chromium installation detected"
            except OSError:
                continue

    return False, "Playwright Chromium browser directory not found"

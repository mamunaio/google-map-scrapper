"""
LeadHunter Studio — Provider-Independent Email Verification Engine.

Implements a pluggable provider architecture so the built-in free verification engine
(`FreeEmailVerificationProvider`) can later be swapped or extended with paid providers
(e.g. ZeroBounce, NeverBounce) without changing API routes, RQ workers, or frontend code.

Strict safety & honesty guarantees:
- Never sends actual emails (`SMTP.data()` / `sendmail()` are never invoked).
- Never bypasses mail-server security or anti-abuse protections.
- Enforces SSRF & DNS-rebinding pinning (`resolve_and_validate_public_ips`) on MX hosts.
- Never classifies MX-only, catch-all, role-based, disposable, blocked, or uncertain checks as `Valid`.
"""

from __future__ import annotations

import logging
import os
import secrets
import smtplib
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Protocol, runtime_checkable

import dns.exception
import dns.resolver
from email_validator import EmailNotValidError, validate_email

from services.email_service import GENERIC_PREFIXES
from services.runtime_config import get_bool_env, get_int_env, redact_email_for_log
from services.security import SecurityError, resolve_and_validate_public_ips

logger = logging.getLogger("leadhunter.email_verifier")

STATUS_VALID = "Valid"
STATUS_RISKY = "Risky"
STATUS_INVALID = "Invalid"
STATUS_UNKNOWN = "Unknown"

ALLOWED_VERIFICATION_STATUSES = (
    STATUS_VALID,
    STATUS_RISKY,
    STATUS_INVALID,
    STATUS_UNKNOWN,
)

# Curated set of well-known disposable / temporary mailbox domains
DISPOSABLE_EMAIL_DOMAINS: frozenset[str] = frozenset({
    "10minutemail.com",
    "10minutemail.net",
    "10minutemail.org",
    "20minutemail.com",
    "anonbox.net",
    "binkmail.com",
    "burnermail.io",
    "crazymailing.com",
    "deadaddress.com",
    "discard.email",
    "discardmail.com",
    "disposable.email",
    "disposableaddress.com",
    "disposablemail.com",
    "dispostable.com",
    "dodgeit.com",
    "dodgit.com",
    "dropmail.me",
    "emailondeck.com",
    "fakeinbox.com",
    "fakemail.net",
    "fakemailgenerator.com",
    "getairmail.com",
    "getnada.com",
    "grr.la",
    "guerrillamail.biz",
    "guerrillamail.com",
    "guerrillamail.de",
    "guerrillamail.info",
    "guerrillamail.net",
    "guerrillamail.org",
    "guerrillamailblock.com",
    "harakirimail.com",
    "incognitomail.org",
    "inboxbear.com",
    "jetable.org",
    "mailcatch.com",
    "maildrop.cc",
    "mailexpire.com",
    "mailforspam.com",
    "mailinator.com",
    "mailinator.net",
    "mailinator.org",
    "mailinator2.com",
    "mailnesia.com",
    "mailnull.com",
    "mailsac.com",
    "mintemail.com",
    "mohmal.com",
    "moakt.com",
    "mt2015.com",
    "mytrashmail.com",
    "nada.email",
    "nada.ltd",
    "no-spam.ws",
    "nowmymail.com",
    "owlpic.com",
    "pokemail.net",
    "put2.net",
    "sharklasers.com",
    "spam4.me",
    "spamavert.com",
    "spambog.com",
    "spambox.us",
    "spamcorptastic.com",
    "spamdecoy.net",
    "spamex.com",
    "spamfree24.org",
    "spamgourmet.com",
    "spamherelots.com",
    "spamhole.com",
    "spaml.com",
    "temp-mail.io",
    "temp-mail.org",
    "tempail.com",
    "tempinbox.com",
    "tempmail.com",
    "tempmail.net",
    "tempmailaddress.com",
    "tempmailo.com",
    "tempr.email",
    "throwaway.email",
    "throwawaymail.com",
    "tmpmail.net",
    "tmpmail.org",
    "trashmail.at",
    "trashmail.com",
    "trashmail.de",
    "trashmail.me",
    "trashmail.net",
    "trashmail.org",
    "wegwerfmail.de",
    "yopmail.com",
    "yopmail.fr",
    "yopmail.net",
})

ROLE_BASED_LOCAL_PARTS: frozenset[str] = frozenset(GENERIC_PREFIXES) | frozenset({
    "abuse",
    "accounts",
    "administrator",
    "alerts",
    "all",
    "billing",
    "bookings",
    "booking",
    "care",
    "compliance",
    "customerservice",
    "do-not-reply",
    "donotreply",
    "enquiries",
    "enquiry",
    "events",
    "finance",
    "helpdesk",
    "hostmaster",
    "hr",
    "it",
    "legal",
    "mail",
    "mailer-daemon",
    "media",
    "newsletter",
    "no-reply",
    "noreply",
    "notifications",
    "partners",
    "postmaster",
    "pr",
    "privacy",
    "recruiting",
    "recruitment",
    "returns",
    "security",
    "shipping",
    "staff",
    "subscribe",
    "tech",
    "unsubscribe",
    "webmaster",
})


@dataclass
class EmailVerificationResult:
    """Standardized provider-independent email verification outcome."""

    email: str
    normalized_email: str
    status: str
    method: str
    verified_at: str
    details: str
    provider: str = "free_dns_smtp"
    checks: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in ALLOWED_VERIFICATION_STATUSES:
            raise ValueError(f"Unsupported verification status: {self.status!r}")

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "normalized_email": self.normalized_email,
            "status": self.status,
            "method": self.method,
            "verified_at": self.verified_at,
            "details": self.details,
            "provider": self.provider,
            "checks": dict(self.checks),
        }


@runtime_checkable
class EmailVerificationProvider(Protocol):
    """Pluggable verification provider contract (free engine or paid API adapters)."""

    name: str

    def verify(self, email: str, *, context: dict | None = None) -> EmailVerificationResult:
        ...


def is_disposable_domain(domain: str) -> bool:
    """Checks whether a domain (or parent domain) is a known disposable mail provider."""
    d = (domain or "").strip().lower().rstrip(".")
    if not d:
        return False
    if d in DISPOSABLE_EMAIL_DOMAINS:
        return True
    parts = d.split(".")
    for idx in range(1, len(parts) - 1):
        parent = ".".join(parts[idx:])
        if parent in DISPOSABLE_EMAIL_DOMAINS:
            return True
    return False


def is_role_based_local_part(local_part: str) -> bool:
    """Detects shared/role-based email local parts (e.g. info@, support@, admin@)."""
    lp = (local_part or "").strip().lower()
    if not lp:
        return False
    # Strip RFC 5233 plus-addressing tag before checking role prefix (e.g. info+sales@)
    base = lp.split("+", 1)[0].strip()
    if base in ROLE_BASED_LOCAL_PARTS:
        return True
    # Match separator-prefixed role variants (e.g. support.team, sales-desk, info_us)
    head = base.replace(".", "_").replace("-", "_").split("_", 1)[0]
    return head in ROLE_BASED_LOCAL_PARTS


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class FreeEmailVerificationProvider:
    """
    Zero-cost verification provider using syntax validation, DNS resolution, MX inspection,
    disposable/role heuristics, and polite optional SMTP RCPT TO / catch-all probing.
    Never sends email content (`DATA` is never called) and pins MX hosts to public IPs.
    """

    name = "free_dns_smtp"

    def __init__(
        self,
        *,
        dns_timeout: int | None = None,
        smtp_timeout: int | None = None,
        max_retries: int | None = None,
        domain_delay_ms: int | None = None,
        enable_smtp_probe: bool | None = None,
        helo_domain: str = "verify-engine.org",
        probe_sender: str = "check@verify-engine.org",
    ):
        self._dns_timeout = dns_timeout
        self._smtp_timeout = smtp_timeout
        self._max_retries = max_retries
        self._domain_delay_ms = domain_delay_ms
        self._enable_smtp_probe = enable_smtp_probe
        self.helo_domain = helo_domain
        self.probe_sender = probe_sender

    def _get_dns_timeout(self) -> int:
        if self._dns_timeout is not None:
            return max(1, int(self._dns_timeout))
        return get_int_env("EMAIL_VERIFY_DNS_TIMEOUT_SECONDS", 5, min_value=1, max_value=30)

    def _get_smtp_timeout(self) -> int:
        if self._smtp_timeout is not None:
            return max(1, int(self._smtp_timeout))
        return get_int_env("EMAIL_VERIFY_SMTP_TIMEOUT_SECONDS", 5, min_value=1, max_value=30)

    def _get_max_retries(self) -> int:
        if self._max_retries is not None:
            return max(0, int(self._max_retries))
        return get_int_env("EMAIL_VERIFY_MAX_RETRIES", 1, min_value=0, max_value=3)

    def _get_domain_delay_seconds(self) -> float:
        if self._domain_delay_ms is not None:
            return max(0, int(self._domain_delay_ms)) / 1000.0
        return get_int_env("EMAIL_VERIFY_DOMAIN_DELAY_MS", 250, min_value=0, max_value=5000) / 1000.0

    def _is_smtp_probe_enabled(self) -> bool:
        if self._enable_smtp_probe is not None:
            return bool(self._enable_smtp_probe)
        return get_bool_env("EMAIL_VERIFY_ENABLE_SMTP_PROBE", True)

    def _throttle_domain(self, domain: str, context: dict | None) -> None:
        delay = self._get_domain_delay_seconds()
        if delay <= 0 or context is None:
            return
        last_map = context.setdefault("domain_last_probe_ts", {})
        now = time.monotonic()
        last_ts = last_map.get(domain)
        if last_ts is not None:
            remaining = delay - (now - last_ts)
            if remaining > 0:
                time.sleep(remaining)
        last_map[domain] = time.monotonic()

    def _resolve_domain_mail_records(self, domain: str, context: dict | None) -> dict:
        """
        Resolves MX (and fallback domain existence via A/AAAA) with bounded transient retry
        and per-batch caching. Returns a structured dict describing DNS state.
        """
        cache = context.setdefault("domain_dns_cache", {}) if context is not None else None
        if cache is not None and domain in cache:
            return dict(cache[domain])

        timeout = self._get_dns_timeout()
        max_retries = self._get_max_retries()

        info = {
            "domain_exists": False,
            "has_mx": False,
            "null_mx": False,
            "mx_host": "",
            "pinned_mx_ip": "",
            "dns_error": None,  # None | 'nxdomain' | 'no_mx' | 'transient' | 'ssrf_blocked'
            "detail": "",
        }

        for attempt in range(max_retries + 1):
            try:
                answers = sorted(
                    dns.resolver.resolve(domain, "MX", lifetime=timeout),
                    key=lambda rec: getattr(rec, "preference", 0),
                )
                if not answers:
                    info["domain_exists"] = True
                    info["dns_error"] = "no_mx"
                    info["detail"] = "Domain has no MX mail servers configured."
                    break

                # RFC 7505 null MX: single record with empty/root exchange "."
                non_null_mx = [str(a.exchange).rstrip(".") for a in answers if str(a.exchange).rstrip(".")]
                if not non_null_mx:
                    info["domain_exists"] = True
                    info["null_mx"] = True
                    info["dns_error"] = "no_mx"
                    info["detail"] = "Domain explicitly declares no mail service (RFC 7505 null MX)."
                    break

                mx_host = non_null_mx[0].lower()
                info["domain_exists"] = True
                info["has_mx"] = True
                info["mx_host"] = mx_host

                # SSRF / DNS-rebinding guard: resolve MX host once and pin to validated public IP
                try:
                    public_ips = resolve_and_validate_public_ips(mx_host, port=25, allow_ip_literal=False)
                    info["pinned_mx_ip"] = public_ips[0]
                except SecurityError as se:
                    info["dns_error"] = "ssrf_blocked"
                    info["detail"] = f"Mail server host rejected by network safety policy: {se}"
                break

            except dns.resolver.NXDOMAIN:
                info["domain_exists"] = False
                info["dns_error"] = "nxdomain"
                info["detail"] = "Domain does not exist (DNS NXDOMAIN)."
                break

            except dns.resolver.NoAnswer:
                # Check if domain itself exists (A/AAAA) so we report accurate reason
                domain_found = False
                for rtype in ("A", "AAAA"):
                    try:
                        if dns.resolver.resolve(domain, rtype, lifetime=timeout):
                            domain_found = True
                            break
                    except dns.resolver.NXDOMAIN:
                        info["domain_exists"] = False
                        info["dns_error"] = "nxdomain"
                        info["detail"] = "Domain does not exist (DNS NXDOMAIN)."
                        break
                    except Exception:
                        continue
                if info["dns_error"] != "nxdomain":
                    info["domain_exists"] = domain_found
                    info["dns_error"] = "no_mx"
                    info["detail"] = (
                        "Domain resolves but has no MX mail servers configured."
                        if domain_found
                        else "Domain has no MX or address records (no mail service)."
                    )
                break

            except (dns.resolver.LifetimeTimeout, dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
                if attempt < max_retries:
                    time.sleep(0.25 * (attempt + 1))
                    continue
                info["dns_error"] = "transient"
                info["detail"] = f"DNS lookup timed out or nameservers unavailable ({exc.__class__.__name__})."
                break

            except Exception as exc:
                info["dns_error"] = "transient"
                info["detail"] = f"DNS verification inconclusive ({exc.__class__.__name__})."
                break

        if cache is not None and info["dns_error"] != "transient":
            cache[domain] = dict(info)
        return info

    def _probe_smtp_mailbox(
        self,
        normalized_email: str,
        domain: str,
        pinned_mx_ip: str,
        context: dict | None,
    ) -> dict:
        """
        Performs a polite, non-sending SMTP RCPT TO & catch-all probe directly against
        `pinned_mx_ip` on port 25. Never calls `DATA` or sends an email.
        """
        smtp_timeout = self._get_smtp_timeout()
        max_retries = self._get_max_retries()
        catchall_cache = context.setdefault("domain_catchall_cache", {}) if context is not None else None

        outcome = {
            "smtp_checked": False,
            "is_catch_all": False,
            "smtp_code": None,
            "state": "blocked",  # 'accepted' | 'rejected' | 'catch_all' | 'tempfail' | 'blocked'
            "detail": "",
        }

        for attempt in range(max_retries + 1):
            self._throttle_domain(domain, context)
            server = None
            try:
                server = smtplib.SMTP(pinned_mx_ip, 25, timeout=smtp_timeout)
                try:
                    code_ehlo, _ = server.ehlo(self.helo_domain)
                    if code_ehlo < 200 or code_ehlo >= 400:
                        server.helo(self.helo_domain)
                except Exception:
                    server.helo(self.helo_domain)

                mail_code, _ = server.mail(self.probe_sender)
                if mail_code >= 400:
                    outcome["smtp_checked"] = True
                    outcome["smtp_code"] = mail_code
                    if 400 <= mail_code < 500 and attempt < max_retries:
                        time.sleep(0.4 * (attempt + 1))
                        continue
                    outcome["state"] = "tempfail" if 400 <= mail_code < 500 else "blocked"
                    outcome["detail"] = (
                        f"Mail server declined SMTP probe session (SMTP {mail_code}); "
                        "mailbox existence cannot be confirmed."
                    )
                    return outcome

                # Catch-all probe (cached per domain within batch)
                catchall_conclusive = True
                if catchall_cache is not None and domain in catchall_cache:
                    is_catchall = bool(catchall_cache[domain])
                else:
                    random_probe = f"lh_probe_{secrets.token_hex(6)}@{domain}"
                    probe_code, _ = server.rcpt(random_probe)
                    is_catchall = probe_code in (250, 251)
                    catchall_conclusive = probe_code in (250, 251, 550, 551, 552, 553, 554)
                    if catchall_cache is not None and catchall_conclusive:
                        catchall_cache[domain] = is_catchall

                if is_catchall:
                    outcome["smtp_checked"] = True
                    outcome["is_catch_all"] = True
                    outcome["smtp_code"] = 250
                    outcome["state"] = "catch_all"
                    outcome["detail"] = (
                        "Mail server accepts random non-existent addresses (catch-all); "
                        "individual mailbox existence cannot be confirmed."
                    )
                    return outcome

                # Target recipient probe (NO DATA ever sent)
                target_code, _ = server.rcpt(normalized_email)
                outcome["smtp_checked"] = True
                outcome["smtp_code"] = target_code

                if target_code in (250, 251):
                    if not catchall_conclusive:
                        outcome["state"] = "tempfail"
                        outcome["detail"] = (
                            "Mail server accepted recipient, but catch-all probe was inconclusive; "
                            "mailbox validity cannot be confirmed."
                        )
                        return outcome
                    outcome["state"] = "accepted"
                    outcome["detail"] = "Mail server accepted recipient on a verified non-catch-all MX server."
                    return outcome
                if target_code in (550, 551, 552, 553, 554):
                    outcome["state"] = "rejected"
                    outcome["detail"] = f"Mail server permanently rejected recipient (SMTP {target_code})."
                    return outcome
                if 400 <= target_code < 500:
                    if attempt < max_retries:
                        time.sleep(0.4 * (attempt + 1))
                        continue
                    outcome["state"] = "tempfail"
                    outcome["detail"] = (
                        f"Mail server returned temporary response (SMTP {target_code}); "
                        "mailbox existence is inconclusive."
                    )
                    return outcome

                outcome["state"] = "tempfail"
                outcome["detail"] = (
                    f"Mail server returned inconclusive response (SMTP {target_code}); "
                    "mailbox existence cannot be confirmed."
                )
                return outcome

            except (socket.timeout, TimeoutError) as exc:
                if attempt < max_retries:
                    time.sleep(0.3 * (attempt + 1))
                    continue
                outcome["state"] = "blocked"
                outcome["detail"] = (
                    f"Valid MX records exist, but SMTP verification timed out ({exc.__class__.__name__}); "
                    "MX validation alone does not prove mailbox existence."
                )
                return outcome

            except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, smtplib.SMTPException, OSError) as exc:
                outcome["state"] = "blocked"
                outcome["detail"] = (
                    f"Valid MX records exist, but SMTP check was blocked or refused ({exc.__class__.__name__}); "
                    "MX validation alone does not prove mailbox existence."
                )
                return outcome

            finally:
                if server is not None:
                    try:
                        server.quit()
                    except Exception:
                        try:
                            server.close()
                        except Exception:
                            pass

        return outcome

    def verify(self, email: str, *, context: dict | None = None) -> EmailVerificationResult:
        raw_email = str(email or "").strip()
        ts = _utc_now_iso()
        checks = {
            "syntax_valid": False,
            "domain_exists": False,
            "has_mx": False,
            "mx_host": "",
            "is_disposable": False,
            "is_role_based": False,
            "is_catch_all": False,
            "smtp_checked": False,
            "smtp_code": None,
        }

        # 1. Email syntax validation
        if not raw_email or "@" not in raw_email or len(raw_email) > 320:
            return EmailVerificationResult(
                email=raw_email,
                normalized_email="",
                status=STATUS_INVALID,
                method="syntax",
                verified_at=ts,
                details="Invalid or empty email address syntax.",
                provider=self.name,
                checks=checks,
            )

        try:
            validated = validate_email(raw_email, check_deliverability=False)
            normalized = validated.normalized.lower()
        except EmailNotValidError as exc:
            return EmailVerificationResult(
                email=raw_email,
                normalized_email="",
                status=STATUS_INVALID,
                method="syntax",
                verified_at=ts,
                details=f"Invalid email syntax: {exc}",
                provider=self.name,
                checks=checks,
            )

        local_part, domain = normalized.rsplit("@", 1)
        checks["syntax_valid"] = True
        checks["is_disposable"] = is_disposable_domain(domain)
        checks["is_role_based"] = is_role_based_local_part(local_part)

        # 2. DNS domain & MX resolution (+ SSRF/DNS pinning on MX host)
        dns_info = self._resolve_domain_mail_records(domain, context)
        checks["domain_exists"] = bool(dns_info["domain_exists"])
        checks["has_mx"] = bool(dns_info["has_mx"])
        checks["mx_host"] = dns_info["mx_host"]

        if dns_info["dns_error"] == "nxdomain":
            return EmailVerificationResult(
                email=raw_email,
                normalized_email=normalized,
                status=STATUS_INVALID,
                method="dns_domain",
                verified_at=ts,
                details=dns_info["detail"],
                provider=self.name,
                checks=checks,
            )

        if dns_info["dns_error"] == "no_mx":
            return EmailVerificationResult(
                email=raw_email,
                normalized_email=normalized,
                status=STATUS_INVALID,
                method="dns_mx",
                verified_at=ts,
                details=dns_info["detail"],
                provider=self.name,
                checks=checks,
            )

        if dns_info["dns_error"] == "ssrf_blocked":
            return EmailVerificationResult(
                email=raw_email,
                normalized_email=normalized,
                status=STATUS_INVALID,
                method="dns_mx_security",
                verified_at=ts,
                details=dns_info["detail"],
                provider=self.name,
                checks=checks,
            )

        if dns_info["dns_error"] == "transient" or not dns_info["pinned_mx_ip"]:
            return EmailVerificationResult(
                email=raw_email,
                normalized_email=normalized,
                status=STATUS_UNKNOWN,
                method="dns_mx",
                verified_at=ts,
                details=dns_info["detail"] or "DNS lookup inconclusive.",
                provider=self.name,
                checks=checks,
            )

        # 3. Disposable domain classification (never Valid)
        if checks["is_disposable"]:
            return EmailVerificationResult(
                email=raw_email,
                normalized_email=normalized,
                status=STATUS_RISKY,
                method="disposable_domain",
                verified_at=ts,
                details="Disposable or temporary email domain detected.",
                provider=self.name,
                checks=checks,
            )

        # 4. SMTP catch-all & recipient probe (if enabled; MX-only is NEVER Valid)
        if not self._is_smtp_probe_enabled():
            if checks["is_role_based"]:
                return EmailVerificationResult(
                    email=raw_email,
                    normalized_email=normalized,
                    status=STATUS_RISKY,
                    method="dns_mx_role",
                    verified_at=ts,
                    details=(
                        "Role-based address with valid MX records; SMTP probe disabled, "
                        "so mailbox existence is unconfirmed."
                    ),
                    provider=self.name,
                    checks=checks,
                )
            return EmailVerificationResult(
                email=raw_email,
                normalized_email=normalized,
                status=STATUS_UNKNOWN,
                method="dns_mx_only",
                verified_at=ts,
                details=(
                    "Syntax, DNS, and MX records are valid, but SMTP mailbox check is disabled; "
                    "MX validation alone does not prove mailbox existence."
                ),
                provider=self.name,
                checks=checks,
            )

        smtp_info = self._probe_smtp_mailbox(normalized, domain, dns_info["pinned_mx_ip"], context)
        checks["smtp_checked"] = bool(smtp_info["smtp_checked"])
        checks["is_catch_all"] = bool(smtp_info["is_catch_all"])
        checks["smtp_code"] = smtp_info["smtp_code"]

        state = smtp_info["state"]
        if state == "catch_all":
            return EmailVerificationResult(
                email=raw_email,
                normalized_email=normalized,
                status=STATUS_RISKY,
                method="dns_mx_smtp_catchall",
                verified_at=ts,
                details=smtp_info["detail"],
                provider=self.name,
                checks=checks,
            )

        if state == "rejected":
            return EmailVerificationResult(
                email=raw_email,
                normalized_email=normalized,
                status=STATUS_INVALID,
                method="dns_mx_smtp",
                verified_at=ts,
                details=smtp_info["detail"],
                provider=self.name,
                checks=checks,
            )

        if state == "accepted":
            if checks["is_role_based"]:
                return EmailVerificationResult(
                    email=raw_email,
                    normalized_email=normalized,
                    status=STATUS_RISKY,
                    method="dns_mx_smtp_role",
                    verified_at=ts,
                    details=(
                        "Role-based mailbox accepted by mail server; role addresses carry higher "
                        "bounce or low-engagement risk."
                    ),
                    provider=self.name,
                    checks=checks,
                )
            return EmailVerificationResult(
                email=raw_email,
                normalized_email=normalized,
                status=STATUS_VALID,
                method="dns_mx_smtp",
                verified_at=ts,
                details=smtp_info["detail"],
                provider=self.name,
                checks=checks,
            )

        # Blocked, timed out, greylisted, or temporary failure -> NEVER Valid
        return EmailVerificationResult(
            email=raw_email,
            normalized_email=normalized,
            status=STATUS_UNKNOWN,
            method="dns_mx_smtp_inconclusive",
            verified_at=ts,
            details=smtp_info["detail"] or "SMTP verification inconclusive; MX alone does not prove mailbox existence.",
            provider=self.name,
            checks=checks,
        )


_PROVIDER_REGISTRY: dict[str, Callable[[], EmailVerificationProvider]] = {
    FreeEmailVerificationProvider.name: FreeEmailVerificationProvider,
}


def register_email_verification_provider(
    name: str,
    factory: Callable[[], EmailVerificationProvider],
) -> None:
    """Registers a custom or paid verification provider (e.g. ZeroBounce, NeverBounce)."""
    key = (name or "").strip().lower()
    if not key:
        raise ValueError("Provider name must be a non-empty string.")
    _PROVIDER_REGISTRY[key] = factory


def get_email_verification_provider(provider_name: str | None = None) -> EmailVerificationProvider:
    """Returns an instance of the requested or configured email verification provider."""
    chosen = (provider_name or os.getenv("EMAIL_VERIFIER_PROVIDER") or FreeEmailVerificationProvider.name).strip().lower()
    factory = _PROVIDER_REGISTRY.get(chosen)
    if factory is None:
        supported = ", ".join(sorted(_PROVIDER_REGISTRY.keys()))
        raise ValueError(f"Unsupported email verification provider '{chosen}'. Supported: {supported}")
    return factory()


def verify_email_address(
    email: str,
    *,
    provider: EmailVerificationProvider | None = None,
    provider_name: str | None = None,
    context: dict | None = None,
) -> EmailVerificationResult:
    """Verifies a single email address through the configured verification provider."""
    engine = provider if provider is not None else get_email_verification_provider(provider_name)
    result = engine.verify(email, context=context)
    logger.debug(
        "Verified email=%s status=%s method=%s provider=%s",
        redact_email_for_log(email),
        result.status,
        result.method,
        result.provider,
    )
    return result


def verify_email_batch(
    items: list[dict],
    *,
    provider: EmailVerificationProvider | None = None,
    provider_name: str | None = None,
    progress_callback: Callable[[int, int, dict[str, int]], None] | None = None,
) -> dict:
    """
    Verifies a batch of `{row_index, email}` items with duplicate email suppression.
    - Each distinct normalized email is verified once; results are mapped to every matching row.
    - Reports accurate `processed`, `remaining`, `total`, `unique_checked`, and per-status counts.
    """
    engine = provider if provider is not None else get_email_verification_provider(provider_name)
    total = len(items)
    counts: dict[str, int] = {
        STATUS_VALID: 0,
        STATUS_RISKY: 0,
        STATUS_INVALID: 0,
        STATUS_UNKNOWN: 0,
    }
    results: list[dict] = []
    dedup_cache: dict[str, EmailVerificationResult] = {}
    batch_context: dict = {}
    unique_checked = 0

    for idx, item in enumerate(items, 1):
        row_index = item.get("row_index")
        raw_email = str(item.get("email") or "").strip()
        dedup_key = raw_email.lower()

        if dedup_key in dedup_cache:
            cached = dedup_cache[dedup_key]
            res_dict = cached.to_dict()
            res_dict["email"] = raw_email
            res_dict["deduplicated"] = True
        else:
            verified = verify_email_address(raw_email, provider=engine, context=batch_context)
            dedup_cache[dedup_key] = verified
            unique_checked += 1
            res_dict = verified.to_dict()
            res_dict["deduplicated"] = False

        res_dict["row_index"] = row_index
        counts[res_dict["status"]] = counts.get(res_dict["status"], 0) + 1
        results.append(res_dict)

        if progress_callback is not None:
            progress_callback(idx, total, dict(counts))

    return {
        "total": total,
        "processed": total,
        "remaining": 0,
        "unique_checked": unique_checked,
        "duplicates_suppressed": max(0, total - unique_checked),
        "counts": counts,
        "provider": engine.name,
        "results": results,
    }

"""
LeadHunter Security & Validation Module
Provides robust SSRF protection, DNS rebinding (TOCTOU) defense,
strict SSL verification, and safe HTTP request handling.
"""

import socket
import ipaddress
from urllib.parse import urlparse, urljoin
import requests
from urllib3.util import connection as urllib3_connection

# Blocked IP ranges: Private, Loopback, Link-Local (Cloud Metadata), Carrier NAT, Multicast, Reserved
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),        # IPv4 Loopback
    ipaddress.ip_network('10.0.0.0/8'),         # Private Class A
    ipaddress.ip_network('172.16.0.0/12'),      # Private Class B
    ipaddress.ip_network('192.168.0.0/16'),     # Private Class C
    ipaddress.ip_network('169.254.0.0/16'),     # Link-Local / Cloud Metadata (AWS/GCP/Azure: 169.254.169.254)
    ipaddress.ip_network('0.0.0.0/8'),          # Current network
    ipaddress.ip_network('100.64.0.0/10'),      # Shared Address Space (CGNAT)
    ipaddress.ip_network('192.0.0.0/24'),       # IETF Protocol Assignments
    ipaddress.ip_network('192.0.2.0/24'),       # TEST-NET-1
    ipaddress.ip_network('198.51.100.0/24'),    # TEST-NET-2
    ipaddress.ip_network('203.0.113.0/24'),     # TEST-NET-3
    ipaddress.ip_network('224.0.0.0/4'),        # Multicast
    ipaddress.ip_network('240.0.0.0/4'),        # Reserved / Future use
    ipaddress.ip_network('::1/128'),            # IPv6 Loopback
    ipaddress.ip_network('fc00::/7'),           # IPv6 Unique Local Address
    ipaddress.ip_network('fe80::/10'),          # IPv6 Link-Local
]

DEFAULT_TIMEOUT = (4, 10)  # (connect_timeout, read_timeout)
MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB max response body to prevent memory exhaustion

class SecurityError(Exception):
    """Raised when a security validation, SSRF check, or DNS rebinding attempt fails."""
    pass

def is_ip_allowed(ip_str: str) -> bool:
    """Checks whether an IP address is a safe public address."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if (ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or
            ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified):
            return False
        for net in BLOCKED_IP_NETWORKS:
            if ip_obj in net:
                return False
        return True
    except ValueError:
        return False

def validate_and_sanitize_url(url: str) -> str:
    """
    Validates URL scheme, resolves hostname to IP, and guarantees it does NOT point
    to localhost, internal networks, or cloud metadata endpoints.
    """
    if not url or not isinstance(url, str):
        raise SecurityError("Invalid URL provided")

    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise SecurityError(f"Unsupported URL scheme: {parsed.scheme}. Only HTTP and HTTPS are allowed.")

    hostname = parsed.hostname
    if not hostname:
        raise SecurityError("URL does not contain a valid hostname.")

    hostname_lower = hostname.lower()
    # Explicit domain blacklist
    if hostname_lower in ('localhost', '127.0.0.1', '::1', '0.0.0.0') or hostname_lower.endswith(('.local', '.internal', '.localhost')):
        raise SecurityError(f"Access to local or private destination '{hostname}' is forbidden.")

    # Check if hostname itself is an IP literal
    try:
        ip_candidate = ipaddress.ip_address(hostname)
        if not is_ip_allowed(str(ip_candidate)):
            raise SecurityError(f"Destination IP {hostname} is in a restricted or private range.")
        return url
    except ValueError:
        pass  # Hostname is a domain name, verify DNS resolution

    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved_ips = {item[4][0] for item in addr_info}
        if not resolved_ips:
            raise SecurityError(f"Could not resolve host: {hostname}")

        for ip in resolved_ips:
            if not is_ip_allowed(ip):
                raise SecurityError(f"Domain {hostname} resolves to restricted IP: {ip}")
    except socket.gaierror as e:
        raise SecurityError(f"DNS resolution error for {hostname}: {e}")
    except Exception as e:
        if isinstance(e, SecurityError):
            raise
        raise SecurityError(f"Security validation failed for {hostname}: {e}")

    return url

# Hook urllib3 connection factory to guarantee DNS Rebinding (TOCTOU) defense at socket creation time
_orig_create_connection = urllib3_connection.create_connection

def _safe_create_connection(address, *args, **kwargs):
    """
    Intercepts urllib3 socket creation to ensure every connection target IP
    is validated and pinned, completely preventing DNS rebinding TOCTOU attacks.
    """
    host, port = address
    try:
        # Check if already an IP
        ipaddress.ip_address(host)
        resolved_ips = [host]
    except ValueError:
        # Resolve hostname
        addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved_ips = [item[4][0] for item in addr_info]

    if not resolved_ips:
        raise SecurityError(f"Failed to resolve host for socket connection: {host}")

    for ip in resolved_ips:
        if not is_ip_allowed(ip):
            raise SecurityError(f"DNS Rebinding / SSRF blocked: connection target {host} resolved to restricted IP: {ip}")

    # Connect directly to the validated IP, eliminating secondary DNS resolution window
    pinned_ip = resolved_ips[0]
    return _orig_create_connection((pinned_ip, port), *args, **kwargs)

# Install socket-level hook
urllib3_connection.create_connection = _safe_create_connection

def safe_http_get(url: str, headers: dict = None, max_bytes: int = MAX_RESPONSE_BYTES, timeout=DEFAULT_TIMEOUT):
    """
    Performs a safe HTTP GET request with SSRF validation, DNS rebinding protection,
    strict SSL verification (no insecure fallback), and manual redirect verification.
    """
    validated_url = validate_and_sanitize_url(url)
    
    default_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
    }
    if headers:
        default_headers.update(headers)

    session = requests.Session()
    current_url = validated_url
    redirect_count = 0
    max_redirects = 5

    while True:
        # Strict SSL verification: never automatically fall back to verify=False
        response = session.get(
            current_url,
            headers=default_headers,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
            verify=True
        )

        # Handle redirects with per-hop SSRF validation
        if response.is_redirect and 'location' in response.headers:
            redirect_count += 1
            if redirect_count > max_redirects:
                raise SecurityError(f"Too many redirects (exceeded limit of {max_redirects})")
            
            next_url = urljoin(current_url, response.headers['location'])
            # CRITICAL: Validate redirect destination before next request
            current_url = validate_and_sanitize_url(next_url)
            continue

        # Enforce response content length limit
        content = bytearray()
        for chunk in response.iter_content(chunk_size=16384):
            content.extend(chunk)
            if len(content) > max_bytes:
                response.close()
                raise SecurityError(f"Response size exceeded safety limit of {max_bytes / (1024*1024):.1f} MB")

        response._content = bytes(content)
        response.ssl_verified = True
        return response

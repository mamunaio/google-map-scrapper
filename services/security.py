"""
LeadHunter Security & Validation Module
Provides robust SSRF protection, URL validation, and safe HTTP request handling.
"""

import socket
import ipaddress
from urllib.parse import urlparse, urljoin
import requests

# Private and cloud metadata IP ranges to strictly block
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),        # IPv4 Loopback
    ipaddress.ip_network('10.0.0.0/8'),         # Private Class A
    ipaddress.ip_network('172.16.0.0/12'),      # Private Class B
    ipaddress.ip_network('192.168.0.0/16'),     # Private Class C
    ipaddress.ip_network('169.254.0.0/16'),     # Link-local / Cloud Metadata (AWS/GCP/Azure)
    ipaddress.ip_network('0.0.0.0/8'),          # Current network
    ipaddress.ip_network('100.64.0.0/10'),      # Shared Address Space (Carrier Grade NAT)
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

DEFAULT_TIMEOUT = (5, 12)  # (connect_timeout, read_timeout)
MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB max response body to prevent memory exhaustion

class SecurityError(Exception):
    """Raised when a security validation or SSRF check fails."""
    pass

def is_ip_allowed(ip_str: str) -> bool:
    """Checks whether an IP address is a safe public address."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
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
    Returns normalized URL if safe, otherwise raises SecurityError.
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
    if hostname_lower in ('localhost', '127.0.0.1', '::1', '0.0.0.0') or hostname_lower.endswith('.local') or hostname_lower.endswith('.internal'):
        raise SecurityError(f"Access to local or private destination '{hostname}' is forbidden.")

    # Check if hostname itself is an IP literal
    try:
        ip_candidate = ipaddress.ip_address(hostname)
        if not is_ip_allowed(str(ip_candidate)):
            raise SecurityError(f"Destination IP {hostname} is in a restricted or private range.")
        return url
    except ValueError:
        pass  # Hostname is a domain name, proceed to DNS resolution check

    # Resolve domain to IP addresses and ensure none resolve to private space
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

def safe_http_get(url: str, headers: dict = None, max_bytes: int = MAX_RESPONSE_BYTES, timeout=DEFAULT_TIMEOUT, allow_redirects: bool = True):
    """
    Performs a safe HTTP GET request with SSRF validation, size limits, and safe redirect following.
    Default headers mimic a real desktop browser.
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
    ssl_warning = False

    while True:
        try:
            # Try with strict SSL verification
            response = session.get(current_url, headers=default_headers, timeout=timeout, allow_redirects=False, stream=True, verify=True)
        except requests.exceptions.SSLError:
            # If standard SSL verification fails (e.g. self-signed or missing intermediate cert), retry with verify=False
            # but record the SSL warning so audit services can report the security risk!
            ssl_warning = True
            response = session.get(current_url, headers=default_headers, timeout=timeout, allow_redirects=False, stream=True, verify=False)

        # Check for redirects
        if allow_redirects and response.is_redirect and 'location' in response.headers:
            redirect_count += 1
            if redirect_count > max_redirects:
                raise SecurityError(f"Too many redirects (exceeded limit of {max_redirects})")
            
            next_url = urljoin(current_url, response.headers['location'])
            # CRITICAL: Validate every redirect target against SSRF!
            current_url = validate_and_sanitize_url(next_url)
            continue

        # Enforce response content length limit
        content = bytearray()
        for chunk in response.iter_content(chunk_size=16384):
            content.extend(chunk)
            if len(content) > max_bytes:
                response.close()
                raise SecurityError(f"Response size exceeded safety limit of {max_bytes / (1024*1024):.1f} MB")

        # Attach custom properties for callers
        response._content = bytes(content)
        response.ssl_verified = not ssl_warning
        return response

"""
LeadHunter Security & Validation Module
Provides robust SSRF protection, DNS rebinding (TOCTOU) defense,
strict SSL verification, and safe HTTP request handling.
"""

import socket
import ipaddress
import re
import threading
import select
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
        clean_ip = ip_str.strip('[]') if isinstance(ip_str, str) else str(ip_str)
        ip_obj = ipaddress.ip_address(clean_ip)
        
        # Check IPv4-mapped IPv6 address (e.g. ::ffff:127.0.0.1)
        if getattr(ip_obj, 'ipv4_mapped', None) is not None:
            ip_obj = ip_obj.ipv4_mapped

        if (ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or
            ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified):
            return False
            
        for net in BLOCKED_IP_NETWORKS:
            if ip_obj.version == net.version and ip_obj in net:
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

def _safe_create_connection(address, timeout=urllib3_connection._DEFAULT_TIMEOUT, source_address=None, socket_options=None):
    """
    Intercepts urllib3 socket creation to ensure every connection target IP
    (both IPv4 and IPv6) is validated and connected directly without secondary
    DNS resolution, completely preventing DNS rebinding TOCTOU attacks.
    """
    host, port = address
    clean_host = host.strip("[]") if isinstance(host, str) else host

    family = urllib3_connection.allowed_gai_family()
    try:
        clean_host.encode("idna")
    except UnicodeError:
        raise SecurityError(f"Invalid host label: '{clean_host}'")

    try:
        # Check if clean_host is an explicit IP literal
        ip_obj = ipaddress.ip_address(clean_host)
        if not is_ip_allowed(str(ip_obj)):
            raise SecurityError(f"DNS Rebinding / SSRF blocked: connection target is restricted IP '{clean_host}'")
        addr_info = socket.getaddrinfo(clean_host, port, family, socket.SOCK_STREAM)
    except ValueError:
        # Domain name: resolve DNS
        try:
            addr_info = socket.getaddrinfo(clean_host, port, family, socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise SecurityError(f"DNS resolution failed for {clean_host}: {e}")

    if not addr_info:
        raise SecurityError(f"DNS resolution returned no addresses for {clean_host}")

    # Validate EVERY resolved IP address (IPv4 and IPv6) before opening any socket
    for res in addr_info:
        ip = res[4][0]
        if not is_ip_allowed(ip):
            raise SecurityError(
                f"DNS Rebinding / SSRF blocked: connection target '{clean_host}' resolved to restricted IP: {ip}"
            )

    # Establish socket connection using verified address tuples directly (no secondary DNS lookup)
    err = None
    for res in addr_info:
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            urllib3_connection._set_socket_options(sock, socket_options)
            if timeout is not urllib3_connection._DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sa)
            err = None
            return sock
        except OSError as e:
            err = e
            if sock is not None:
                sock.close()

    if err is not None:
        raise err
    raise OSError(f"Failed to establish connection to {clean_host}")

# Install socket-level hook on urllib3 connection modules
urllib3_connection.create_connection = _safe_create_connection
try:
    import urllib3.connection
    if hasattr(urllib3.connection, "connection"):
        urllib3.connection.connection.create_connection = _safe_create_connection
except Exception:
    pass

class SafeHTTPAdapter(requests.adapters.HTTPAdapter):
    """
    Custom HTTPAdapter ensuring that every request dispatched by Requests
    undergoes pre-flight URL and destination validation before reaching the
    connection pool, complementing the socket-level DNS rebinding defense.
    """
    def send(self, request, *args, **kwargs):
        validate_and_sanitize_url(request.url)
        return super().send(request, *args, **kwargs)

def safe_http_get(url: str, headers: dict = None, max_bytes: int = MAX_RESPONSE_BYTES, timeout=DEFAULT_TIMEOUT):
    """
    Performs a safe HTTP GET request with SSRF validation, DNS rebinding protection,
    strict SSL verification (no insecure fallback), manual redirect verification,
    disabled environment proxy inheritance (trust_env=False), and guaranteed resource cleanup.
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
    # Explicitly disable environment proxy inheritance to prevent proxy bypass attacks
    session.trust_env = False

    safe_adapter = SafeHTTPAdapter()
    session.mount("https://", safe_adapter)
    session.mount("http://", safe_adapter)

    current_url = validated_url
    redirect_count = 0
    max_redirects = 5

    try:
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
                    response.close()
                    raise SecurityError(f"Too many redirects (exceeded limit of {max_redirects})")
                
                next_url = urljoin(current_url, response.headers['location'])
                # Ensure redirect response socket is closed before following next hop
                response.close()
                current_url = validate_and_sanitize_url(next_url)
                continue

            # Enforce response content length limit and guarantee socket closure
            content = bytearray()
            try:
                for chunk in response.iter_content(chunk_size=16384):
                    content.extend(chunk)
                    if len(content) > max_bytes:
                        raise SecurityError(f"Response size exceeded safety limit of {max_bytes / (1024*1024):.1f} MB")
            finally:
                response.close()

            response._content = bytes(content)
            response.ssl_verified = True
            return response
    finally:
        session.close()

# ---------------------------------------------------------------------------
# Google Maps Playwright Security & SSRF Protection
# ---------------------------------------------------------------------------

GOOGLE_MAPS_DOMAIN_REGEX = re.compile(
    r'^(?:[a-z0-9-]+\.)*(google\.(?:com|(?:com|co|org|net|gov|edu)\.[a-z]{2}|[a-z]{2})|goo\.gl)$',
    re.IGNORECASE
)

AUTHORIZED_SUBRESOURCE_DOMAIN_REGEX = re.compile(
    r'^(?:[a-z0-9-]+\.)*(google\.(?:com|(?:com|co|org|net|gov|edu)\.[a-z]{2}|[a-z]{2})|goo\.gl|gstatic\.com|googleapis\.com|googleusercontent\.com|ggpht\.com|googletagmanager\.com|google-analytics\.com)$',
    re.IGNORECASE
)

def is_google_maps_domain(hostname: str) -> bool:
    """
    Checks whether a hostname belongs to an authorized Google Maps domain or shortlink.
    Strictly forbids attacker variations (e.g. attacker-google.com, google.com.attacker.com).
    """
    if not hostname or not isinstance(hostname, str):
        return False
    clean_h = hostname.lower().strip('.')
    if not GOOGLE_MAPS_DOMAIN_REGEX.match(clean_h):
        return False
    parts = clean_h.split('.')
    return ('google' in parts or 'goo' in parts)

def is_authorized_maps_subresource_host(hostname: str) -> bool:
    """
    Checks whether a hostname is an authorized Google subresource host (CDN, fonts, static assets, telemetry).
    """
    if not hostname or not isinstance(hostname, str):
        return False
    clean_h = hostname.lower().strip('.')
    return bool(AUTHORIZED_SUBRESOURCE_DOMAIN_REGEX.match(clean_h))

def is_valid_google_maps_pattern(url_or_path: str) -> bool:
    """
    Verifies that a URL path or query pattern matches a legitimate Google Maps feature.
    """
    if not url_or_path or not isinstance(url_or_path, str):
        return False
    u = url_or_path.lower()
    return ("/maps" in u or
            "/search" in u or
            "/place" in u or
            "?q=" in u or
            "&q=" in u or
            "goo.gl" in u)

def resolve_and_validate_hostname(hostname: str, port: int = 443) -> tuple[bool, str, list[str]]:
    """
    Resolves hostname to IP addresses at call time (no stale cache) and verifies
    that every resolved IP address is a safe public address.
    Defeats public-to-private DNS rebinding attacks.
    Returns (is_safe, reason, resolved_ips).
    """
    if not hostname or not isinstance(hostname, str):
        return False, "Invalid hostname", []

    clean_host = hostname.strip("[]").lower()

    # Blacklist explicit local and private domain names
    if clean_host in ('localhost', '127.0.0.1', '::1', '0.0.0.0') or clean_host.endswith(('.local', '.internal', '.localhost')):
        return False, f"Access to local or private destination '{clean_host}' is forbidden", []

    # Check if host is an explicit IP literal
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        if not is_ip_allowed(str(ip_obj)):
            return False, f"Destination IP '{clean_host}' is in a restricted or private range", []
        return False, f"Direct IP destination '{clean_host}' is not permitted", []
    except ValueError:
        pass

    try:
        addr_info = socket.getaddrinfo(clean_host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved_ips = [item[4][0] for item in addr_info]
        if not resolved_ips:
            return False, f"Could not resolve host: {clean_host}", []

        for ip in resolved_ips:
            if not is_ip_allowed(ip):
                return False, f"Domain '{clean_host}' resolves to restricted IP: {ip}", []

        return True, "OK", resolved_ips
    except socket.gaierror as e:
        return False, f"DNS resolution failed for '{clean_host}': {e}", []
    except Exception as e:
        return False, f"DNS validation error for '{clean_host}': {e}", []

def validate_google_maps_url(url: str) -> str:
    """
    Validates that a URL is a legitimate Google Maps destination.
    Enforces SSRF prevention (no localhost, private IPs, cloud metadata, link-local),
    verifies that the host is a permitted Google Maps domain,
    and checks that the URL path/query matches supported Google Maps patterns.
    """
    sanitized = validate_and_sanitize_url(url)
    parsed = urlparse(sanitized)
    hostname = (parsed.hostname or "").lower()

    if not is_google_maps_domain(hostname):
        raise SecurityError(f"Host '{hostname}' is not a permitted Google Maps domain.")

    path = parsed.path.lower()
    query = parsed.query.lower()

    is_shortlink = (hostname == 'goo.gl' or hostname.endswith('.goo.gl'))
    is_search = ("/maps/search" in path or path.startswith("/search") or query.startswith("q=") or "&q=" in query)
    is_place = ('/maps/place' in path or '/place/' in path or '/maps/@' in path or '/maps/dir' in path)
    is_maps_root = (path in ('/maps', '/maps/', '')) or ('maps.google.' in hostname)

    if not (is_shortlink or is_search or is_place or is_maps_root):
        raise SecurityError(f"URL path '{parsed.path}' is not a recognized Google Maps pattern.")

    return sanitized

def is_safe_browser_url(url: str, is_main_document: bool = False) -> tuple[bool, str]:
    """
    Validates destination URLs for browser requests in Playwright (both main document navigations
    and subresources) to prevent SSRF, unauthorized redirects, and access to internal services.
    Enforces real-time DNS resolution with zero stale cache to detect DNS rebinding.
    """
    if not url or not isinstance(url, str):
        return False, "Empty or invalid URL"

    url_str = url.strip()

    # Allow about:blank for browser internal initialization
    if url_str == 'about:blank':
        return True, "Browser internal"

    # Allow data: URLs ONLY for subresources (e.g. inline base64 images/canvas)
    if url_str.startswith('data:'):
        if is_main_document:
            return False, "Data URLs are not permitted for main document navigation"
        return True, "Inline data resource"

    # Block all other non-http/https schemes
    if not url_str.startswith(('http://', 'https://')):
        scheme = url_str.split(':', 1)[0]
        return False, f"Unsupported scheme: '{scheme}'"

    parsed = urlparse(url_str)
    hostname = parsed.hostname
    if not hostname:
        return False, "URL missing hostname"

    clean_host = hostname.strip("[]").lower()

    # Domain authorization check
    if is_main_document:
        if not is_google_maps_domain(clean_host):
            return False, f"Main document destination '{clean_host}' is not an authorized Google Maps host"
    else:
        if not (is_google_maps_domain(clean_host) or is_authorized_maps_subresource_host(clean_host)):
            return False, f"Subresource destination '{clean_host}' is not an authorized Google subresource host"

    # Real-time DNS resolution verification (defeats public-to-private DNS rebinding)
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    is_safe, reason, _ = resolve_and_validate_hostname(clean_host, port=port)
    if not is_safe:
        return False, reason

    return True, "OK"

class SafeBrowserProxy:
    """
    Local TCP tunneling proxy for Playwright browser contexts.
    Enforces network-level destination pinning and SSRF defense:
    - Intercepts all Chromium outbound connection attempts.
    - Validates target hostnames against Google Maps & subresource authorization rules.
    - Resolves hostnames in Python, verifies every IP with is_ip_allowed(),
      and connects the upstream socket directly to the pinned public IP.
    - Aborts connections immediately if a hostname resolves to a private IP,
      localhost, cloud metadata, or link-local address (preventing DNS rebinding).
    """
    def __init__(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.bind(('127.0.0.1', 0))
        self.port = self.server_sock.getsockname()[1]
        self.server_sock.listen(50)
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        try:
            self.server_sock.close()
        except Exception:
            pass
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def _run(self):
        self.server_sock.settimeout(0.5)
        while self.running:
            try:
                client_sock, _ = self.server_sock.accept()
                t = threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle_client(self, client_sock):
        upstream_sock = None
        try:
            client_sock.settimeout(15.0)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            if not data:
                client_sock.close()
                return

            req_line = data.split(b"\r\n")[0].decode('latin1', errors='replace')
            parts = req_line.split()
            if len(parts) < 2:
                client_sock.close()
                return

            method, target = parts[0].upper(), parts[1]

            if method == 'CONNECT':
                if ':' in target:
                    host, port_str = target.split(':', 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        port = 443
                else:
                    host, port = target, 443
            else:
                parsed = urlparse(target)
                host = parsed.hostname or ''
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)

            clean_host = host.strip("[]").lower()

            # 1. Domain Authorization Filter
            if not (is_google_maps_domain(clean_host) or is_authorized_maps_subresource_host(clean_host)):
                client_sock.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nForbidden: Unauthorized destination\r\n")
                client_sock.close()
                return

            # 2. DNS Resolution & Rebinding Check
            is_safe, reason, resolved_ips = resolve_and_validate_hostname(clean_host, port=port)
            if not is_safe or not resolved_ips:
                client_sock.sendall(f"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nForbidden: {reason}\r\n".encode())
                client_sock.close()
                return

            pinned_ip = resolved_ips[0]

            # 3. Connect Upstream Socket Directly to Pinned Public IP
            family = socket.AF_INET6 if ':' in pinned_ip else socket.AF_INET
            upstream_sock = socket.socket(family, socket.SOCK_STREAM)
            upstream_sock.settimeout(10.0)
            try:
                upstream_sock.connect((pinned_ip, port))
            except Exception:
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nBad Gateway\r\n")
                client_sock.close()
                upstream_sock.close()
                return

            # 4. Stream Relay
            if method == 'CONNECT':
                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                sockets = [client_sock, upstream_sock]
                while self.running:
                    try:
                        readable, _, exceptional = select.select(sockets, [], sockets, 3.0)
                    except Exception:
                        break
                    if exceptional:
                        break
                    for s in readable:
                        other = upstream_sock if s is client_sock else client_sock
                        try:
                            buf = s.recv(16384)
                            if not buf:
                                return
                            other.sendall(buf)
                        except Exception:
                            return
            else:
                upstream_sock.sendall(data)
                while self.running:
                    try:
                        readable, _, _ = select.select([upstream_sock], [], [upstream_sock], 5.0)
                        if not readable:
                            break
                        chunk = upstream_sock.recv(16384)
                        if not chunk:
                            break
                        client_sock.sendall(chunk)
                    except Exception:
                        break

        except Exception:
            pass
        finally:
            if upstream_sock:
                try:
                    upstream_sock.close()
                except Exception:
                    pass
            try:
                client_sock.close()
            except Exception:
                pass


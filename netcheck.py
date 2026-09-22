# netcheck.py
# The only module that touches the network, and it is off by default.
#
# SAFETY CONTRACT — this is the part of the project that deliberately contacts
# infrastructure chosen by an attacker, so the rules are absolute:
#
#   1. Nothing is ever RENDERED or EXECUTED. requests only. No browser, no
#      JavaScript engine, no HTML parsing of fetched content. Fetching a
#      phishing page's headers is safe; running its script is not.
#   2. Redirects are stepped MANUALLY with allow_redirects=False, so every hop
#      is inspected before the next request is made. Handing the chain to
#      requests would follow it blindly, including into private address space.
#   3. Every hop is SSRF-checked before it is requested. A link in an email can
#      point at 127.0.0.1, 169.254.169.254 or 10.0.0.5 just as easily as at a
#      public host, and a server that follows it becomes the attacker's proxy
#      into its own network. This is the single most important check here.
#   4. Bounded: hop count, timeout, response size. A redirect loop or a
#      multi-gigabyte response must not take the analyser with it.
#   5. HEAD first, and only text/html is ever partially read.

import ipaddress
import socket
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

import requests

from config import config

# Address space that must never be reachable from a URL in an email.
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),        # "this" network
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918
    ipaddress.ip_network("100.64.0.0/10"),    # carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("169.254.0.0/16"),   # link-local — cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),    # RFC 1918
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),   # RFC 1918
    ipaddress.ip_network("198.18.0.0/15"),    # benchmarking
    ipaddress.ip_network("224.0.0.0/4"),      # multicast
    ipaddress.ip_network("240.0.0.0/4"),      # reserved
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),         # unique local
    ipaddress.ip_network("fe80::/10"),        # link-local
]

# A neutral identifier. Not a browser string — this tool does not pretend to
# be a victim's browser, and honest identification is the correct default for
# a defensive tool making outbound requests.
USER_AGENT = "PhishingEmailAnalyzer/1.0 (+security-research; no-js; headers-only)"

MAX_RESPONSE_BYTES = 64 * 1024


def is_blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable means we do not reach it
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        return True
    return any(ip in network for network in BLOCKED_NETWORKS)


def resolve_safely(hostname: str) -> Tuple[bool, str]:
    """Resolve a hostname and reject it if ANY answer is internal.

    Every returned address is checked, not just the first. A DNS name that
    resolves to several addresses where only one is public is a known way to
    slip an internal target past a naive check.
    """
    if not hostname:
        return False, "no hostname"
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, socket.herror, UnicodeError, OSError) as exc:
        return False, f"DNS resolution failed ({type(exc).__name__})"
    if not infos:
        return False, "no DNS answer"
    for info in infos:
        ip = info[4][0]
        if is_blocked_ip(ip):
            return False, f"resolves to non-public address {ip}"
    return True, infos[0][4][0]


def expand_redirects(url: str, max_hops: Optional[int] = None) -> Tuple[List[str], str]:
    """Walk a redirect chain one hop at a time. Returns (chain, status note).

    Each hop is resolved and SSRF-checked before the request is issued, so the
    guard cannot be bypassed by a public URL that redirects inward — the
    classic bypass against code that only validates the first URL.
    """
    if not config.ENABLE_URL_EXPANSION:
        return [], "URL expansion disabled"

    max_hops = max_hops or config.URL_EXPANSION_MAX_HOPS
    chain: List[str] = []
    current = url
    session = requests.Session()
    session.max_redirects = 1  # we do the following ourselves
    try:
        for hop in range(max_hops):
            parts = urlsplit(current)
            if parts.scheme not in ("http", "https"):
                return chain, f"stopped: unsupported scheme '{parts.scheme}'"

            ok, detail = resolve_safely(parts.hostname or "")
            if not ok:
                return chain, f"blocked at hop {hop + 1}: {detail}"

            try:
                response = session.head(
                    current, allow_redirects=False,
                    timeout=config.URL_EXPANSION_TIMEOUT,
                    headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
                )
                # Some hosts refuse HEAD. Fall back to a GET whose body we
                # never read past the header block and never parse.
                if response.status_code in (405, 501):
                    response = session.get(
                        current, allow_redirects=False, stream=True,
                        timeout=config.URL_EXPANSION_TIMEOUT,
                        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
                    )
                    response.close()
            except requests.RequestException as exc:
                return chain, f"request failed at hop {hop + 1}: {type(exc).__name__}"

            if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location", "")
                if not location:
                    return chain, f"redirect with no Location at hop {hop + 1}"
                current = requests.compat.urljoin(current, location)
                if current in chain:
                    return chain, "stopped: redirect loop"
                chain.append(current)
                continue

            return chain, f"final status {response.status_code}"
        return chain, f"stopped: hop limit ({max_hops}) reached"
    finally:
        session.close()


def domain_records(domain: str) -> dict:
    """SPF/DMARC/MX presence for a domain. Read-only DNS, no fetching."""
    out = {"spf": None, "dmarc": None, "mx": None, "error": None}
    if not config.ENABLE_DNS_CHECKS or not domain:
        out["error"] = "DNS checks disabled"
        return out
    try:
        import dns.resolver
    except ImportError:
        out["error"] = "dnspython not installed"
        return out

    resolver = dns.resolver.Resolver()
    resolver.timeout = config.DNS_TIMEOUT
    resolver.lifetime = config.DNS_TIMEOUT

    try:
        answers = resolver.resolve(domain, "TXT")
        for record in answers:
            text = b"".join(record.strings).decode("utf-8", "replace")
            if text.lower().startswith("v=spf1"):
                out["spf"] = text[:300]
                break
    except Exception:
        pass

    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for record in answers:
            text = b"".join(record.strings).decode("utf-8", "replace")
            if text.lower().startswith("v=dmarc1"):
                out["dmarc"] = text[:300]
                break
    except Exception:
        pass

    try:
        answers = resolver.resolve(domain, "MX")
        out["mx"] = [str(r.exchange).rstrip(".") for r in answers][:5]
    except Exception:
        pass

    return out

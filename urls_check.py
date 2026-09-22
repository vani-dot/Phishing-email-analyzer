# urls_check.py
# Signals derived from the links in the message. Entirely offline — nothing
# here resolves, fetches or contacts anything. Network-based enrichment lives
# in netcheck.py behind an explicit opt-in.
#
# Reasoning model: a phishing email has a goal, and almost always that goal is
# a click. Everything else in the message — the branding, the urgency, the
# spoofed sender — exists to move the reader to the link. So the link is where
# the attacker's real infrastructure is exposed, and it is the one element
# they cannot fake: the href has to point at somewhere they actually control.
#
# The strongest checks here compare two things the attacker must keep
# different: what the link CLAIMS (anchor text, brand words, subdomains) and
# where it GOES (registered domain). Every gap between those is intent.

import ipaddress
import re
from collections import Counter
from typing import List
from urllib.parse import parse_qs, unquote, urlsplit

import intel
from models import Category, ParsedEmail, Severity, Signal
from parser import domain_of

# Paths that exist to collect credentials or confirm identity.
CREDENTIAL_PATHS = re.compile(
    r"(?i)/(login|signin|sign-in|log-in|account|verify|verification|validate|"
    r"secure|security|update|confirm|auth|authenticate|session|password|"
    r"recover|reset|unlock|billing|payment|invoice|wallet|webscr|portal)\b"
)

# Direct links to things that execute.
EXECUTABLE_LINK = re.compile(
    r"(?i)\.(exe|scr|msi|bat|cmd|vbs|js|jar|apk|dmg|pkg|ps1|hta|iso|img|zip|rar|7z)(\?|$|#)"
)

# Parameters that carry another URL — the shape of an open redirect, which
# lets an attacker borrow a trusted domain's reputation for their own link.
REDIRECT_PARAMS = {"url", "redirect", "redirect_uri", "redirect_url", "next",
                   "target", "dest", "destination", "continue", "return",
                   "returnurl", "return_to", "goto", "link", "out", "r", "u"}


def _sig(code, title, severity, detail, evidence=None) -> Signal:
    return Signal(code=code, title=title, category=Category.URL,
                  severity=severity, detail=detail, evidence=evidence)


def _is_ip_literal(host: str):
    """Return an ip_address if the host is a literal address in any notation.

    Covers dotted-quad, IPv6, and the decimal/octal/hex encodings that exist
    purely to make an address unreadable to a human (http://2130706433/ is
    127.0.0.1).
    """
    host = host.strip("[]")
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    if re.fullmatch(r"\d{8,10}", host):
        try:
            return ipaddress.ip_address(int(host))
        except (ValueError, ipaddress.AddressValueError):
            return None
    if re.fullmatch(r"(?i)0x[0-9a-f]{8}", host):
        try:
            return ipaddress.ip_address(int(host, 16))
        except (ValueError, ipaddress.AddressValueError):
            return None
    return None


def analyse_urls(email: ParsedEmail, authenticated: bool = False) -> List[Signal]:
    """URL signals.

    When `authenticated` is true and a link points at a known click-tracking
    host, the anchor-mismatch and redirect rules contribute zero for that URL.
    A tracking wrapper looks identical to cloaking — anchor text says one
    domain, href points at another — and treating analytics as an attack is
    what made this flag legitimate mail from Mandrill, SendGrid and SES.
    """
    signals: List[Signal] = []
    links = email.links
    sender_domain = domain_of(email.from_address)

    if not links:
        return signals

    seen_codes = set()

    def add(code, title, severity, detail, evidence=None, once=True):
        """Fire each URL rule at most once per message.

        Ten lookalike links are one finding with ten instances, not ten
        findings — otherwise a message with a repeated footer link would
        out-score a message with a genuinely broader set of problems.
        """
        if once and code in seen_codes:
            return
        seen_codes.add(code)
        signals.append(_sig(code, title, severity, detail, evidence))

    domains = Counter()
    tracking_wrapped: List[str] = []

    for link in links:
        host = link.domain
        registered = link.registered_domain
        if registered:
            domains[registered] += 1

        try:
            parts = urlsplit(link.url)
        except ValueError:
            continue

        # ---- 1. anchor text vs destination ------------------------------
        # The single most direct expression of deceptive intent: the message
        # shows the reader one domain and sends them to another.
        wrapped = authenticated and intel.is_tracking_wrapper(host)
        if wrapped:
            tracking_wrapped.append(link.url)

        if link.display_text and not wrapped:
            text = link.display_text.strip()
            text_urls = re.findall(r"(?i)\b(?:https?://|www\.)[^\s<>\"']{1,300}", text)
            if text_urls:
                claimed = domain_of("x@" + urlsplit(
                    text_urls[0] if "://" in text_urls[0] else "http://" + text_urls[0]
                ).hostname or "")
                if claimed and registered and claimed != registered:
                    link.is_mismatch = True
                    add("URL_DISPLAY_MISMATCH", "Link text shows a different domain than it opens",
                        Severity.CRITICAL,
                        f"The message displays '{claimed}' as the destination but the link "
                        f"actually opens '{registered}'. There is no legitimate reason to "
                        f"label a link with someone else's domain — this is deception by "
                        f"construction, not a misconfiguration.",
                        evidence=f"Shown: {text[:90]}  ->  Opens: {link.url[:120]}")

        # ---- 2. credentials embedded in the URL -------------------------
        # http://paypal.com@evil.tk/ — everything before the @ is a username,
        # which browsers ignore. The reader's eye stops at the brand.
        if "@" in (parts.netloc or ""):
            userinfo = parts.netloc.split("@")[0]
            add("URL_USERINFO_TRICK", "Link hides its real destination behind an @",
                Severity.CRITICAL,
                f"The URL reads as '{userinfo[:60]}' but everything before the @ is "
                f"discarded by the browser as a username. The page that actually loads is "
                f"'{host}'. This construction exists for no purpose other than misdirection.",
                evidence=link.url[:200])

        # ---- 3. raw IP addresses ----------------------------------------
        ip = _is_ip_literal(host)
        if ip:
            notation = "dotted-quad"
            if re.fullmatch(r"\d{8,10}", host):
                notation = f"decimal ({host} = {ip})"
            elif host.lower().startswith("0x"):
                notation = f"hexadecimal ({host} = {ip})"
            add("URL_IP_LITERAL", "Link points to a bare IP address", Severity.HIGH,
                f"The destination is the IP address {ip} written in {notation} form, with "
                f"no domain name. Real services use names; an IP means no certificate that "
                f"matches, no registration record, and nothing to take down.",
                evidence=link.url[:200])
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                add("URL_INTERNAL_IP", "Link targets a private network address",
                    Severity.HIGH,
                    f"{ip} is inside private or loopback address space. In an inbound "
                    f"email this either indicates a leaked internal reference or an "
                    f"attempt to make the recipient's own browser reach internal systems.",
                    evidence=link.url[:200])

        # ---- 4. lookalike and script tricks -----------------------------
        if host:
            lookalike = intel.lookalike_brand(host)
            if lookalike:
                brand, legit, score = lookalike
                add("URL_LOOKALIKE_DOMAIN", "Link domain imitates a known brand",
                    Severity.CRITICAL,
                    f"'{host}' resolves to the visual shape of '{legit}' ({brand.title()}) "
                    f"at {score:.0%} similarity without being that domain. A lookalike "
                    f"domain paired with a login page is the standard credential-harvest "
                    f"pattern.",
                    evidence=f"{link.url[:140]}  ~  {legit}")

            mixed = intel.has_mixed_scripts(host)
            if mixed:
                add("URL_MIXED_SCRIPT", "Link domain mixes writing systems", Severity.CRITICAL,
                    f"'{host}' combines {mixed[0].title()} and {mixed[1].title()} characters. "
                    f"Rendered in a browser this is indistinguishable from an all-Latin "
                    f"domain, while resolving somewhere entirely different.",
                    evidence=link.url[:200])

            if host.startswith("xn--") or ".xn--" in host:
                add("URL_PUNYCODE", "Link uses a punycode domain", Severity.HIGH,
                    f"'{host}' is an encoded internationalised domain. It displays as "
                    f"ordinary text in the address bar, which is what makes it viable for "
                    f"impersonating a familiar name.",
                    evidence=link.url[:200])

            # Brand in the subdomain: paypal.com.secure-login.tk. Everything
            # left of the registered domain is attacker-chosen text, and a
            # reader scanning left to right sees the brand first.
            if registered and registered not in intel.LEGITIMATE_DOMAINS:
                prefix = host[: -len(registered)].rstrip(".") if host.endswith(registered) else ""
                if prefix:
                    for brand in intel.BRAND_DOMAINS:
                        if re.search(r"(^|[.\-])" + re.escape(brand) + r"([.\-]|$)", intel.deskeleton(prefix)):
                            add("URL_BRAND_IN_SUBDOMAIN", "Brand name placed in the subdomain",
                                Severity.CRITICAL,
                                f"'{brand}' appears in the subdomain '{prefix}', but the "
                                f"domain that actually owns this address is '{registered}'. "
                                f"Anyone can put any brand to the left of their own domain; "
                                f"only the rightmost part indicates who controls the site.",
                                evidence=link.url[:200])
                            break

            depth = host.count(".")
            if depth >= 4:
                add("URL_DEEP_SUBDOMAIN", "Unusually deep subdomain chain", Severity.MEDIUM,
                    f"'{host}' nests {depth} levels. Long chains are used to push the real "
                    f"domain past the visible width of a mobile address bar.",
                    evidence=link.url[:200])

            if registered in intel.URL_SHORTENERS:
                add("URL_SHORTENER", "Link is behind a URL shortener", Severity.MEDIUM,
                    f"'{registered}' conceals the true destination until the moment of the "
                    f"click. Legitimate in social media, a deliberate choice in email where "
                    f"there is no character limit to justify it.",
                    evidence=link.url[:200])

            tld = registered.rsplit(".", 1)[-1] if "." in registered else ""
            if tld in intel.SUSPICIOUS_TLDS:
                add("URL_SUSPICIOUS_TLD", f"Link on a high-abuse TLD (.{tld})", Severity.MEDIUM,
                    f"'{registered}' uses .{tld}, a TLD with free or very cheap registration "
                    f"and heavy abuse. Weak alone, corroborating in combination.",
                    evidence=link.url[:200])

        # ---- 5. transport and port --------------------------------------
        if parts.scheme == "http" and CREDENTIAL_PATHS.search(parts.path or ""):
            add("URL_PLAINTEXT_LOGIN", "Credential page served over plain HTTP",
                Severity.HIGH,
                f"The link asks for a login or account action over unencrypted HTTP. No "
                f"genuine service has handled credentials this way for years — and it means "
                f"anything typed there also crosses the network in clear text.",
                evidence=link.url[:200])

        if parts.port and parts.port not in (80, 443, 8080, 8443):
            add("URL_ODD_PORT", f"Link uses a non-standard port ({parts.port})",
                Severity.MEDIUM,
                f"Destination listens on port {parts.port} rather than the usual 80 or 443. "
                f"Typical of a host run directly by an operator rather than a hosting "
                f"provider, and of infrastructure meant to be short-lived.",
                evidence=link.url[:200])

        # ---- 6. payload and intent --------------------------------------
        if EXECUTABLE_LINK.search(link.url):
            add("URL_DIRECT_DOWNLOAD", "Link downloads an executable or archive",
                Severity.HIGH,
                "The URL ends in a file type that executes or unpacks to something that "
                "does. Delivering the payload by link rather than attachment bypasses mail "
                "gateways that only scan attachments.",
                evidence=link.url[:200])

        # Only meaningful OFF-DOMAIN. A sender linking to a sign-in or security
        # page on its own domain is describing where to go in its own product,
        # which is what genuine account notifications do all day — GitHub
        # pointing at github.com/settings/security-log is not evidence of
        # anything. The signal exists to catch a message steering the reader to
        # log in SOMEWHERE ELSE, so a same-domain or known-brand destination is
        # excluded rather than reported as a weak hit an analyst has to dismiss.
        if CREDENTIAL_PATHS.search(parts.path or ""):
            same_domain = bool(registered) and registered == sender_domain
            known_brand = registered in intel.LEGITIMATE_DOMAINS
            if not (same_domain or known_brand):
                add("URL_CREDENTIAL_PATH", "Link targets a login or verification page",
                    Severity.LOW,
                    f"The path points at a sign-in, verification or payment endpoint on "
                    f"'{registered}', which is not the sender's own domain. Entirely normal "
                    f"in isolation — it matters because it establishes what the message wants "
                    f"the reader to do, and it compounds every sender problem above.",
                    evidence=link.url[:200])

        # ---- 7. obfuscation ----------------------------------------------
        if link.url.count("%") >= 6:
            decoded = unquote(link.url)
            if decoded != link.url:
                add("URL_HEAVY_ENCODING", "Link is heavily percent-encoded", Severity.MEDIUM,
                    f"The URL contains {link.url.count('%')} encoded sequences. Encoding a "
                    f"URL this aggressively hides its readable form from both the recipient "
                    f"and any filter that does not decode before matching.",
                    evidence=f"{link.url[:100]}  ->  {decoded[:100]}")

        try:
            query = parse_qs(parts.query or "")
        except (ValueError, UnicodeDecodeError):
            query = {}
        for key, values in query.items():
            if key.lower() in REDIRECT_PARAMS:
                for value in values[:2]:
                    candidate = unquote(str(value))
                    if re.match(r"(?i)^https?://", candidate):
                        target = domain_of("x@" + (urlsplit(candidate).hostname or ""))
                        if target and target != registered:
                            add("URL_OPEN_REDIRECT", "Link bounces through a redirect parameter",
                                Severity.HIGH,
                                f"'{registered}' is being used to forward the reader to "
                                f"'{target}'. This borrows a recognisable domain's "
                                f"reputation — the link the recipient inspects is not the "
                                f"site they land on.",
                                evidence=f"{link.url[:150]}")
                            break

    # ---- 8. message-level link patterns ---------------------------------
    if sender_domain and domains:
        off_domain = sum(c for d, c in domains.items() if d != sender_domain)
        if off_domain == sum(domains.values()) and len(domains) == 1:
            only = next(iter(domains))
            if only not in intel.LEGITIMATE_DOMAINS and only != sender_domain:
                add("URL_SINGLE_OFFSITE_TARGET", "Every link points to one unrelated domain",
                    Severity.MEDIUM,
                    f"All {sum(domains.values())} links go to '{only}', which is unrelated to "
                    f"the sender '{sender_domain}'. Genuine mail normally mixes its own "
                    f"domain with recognisable third parties; a single foreign destination "
                    f"is a funnel.",
                    evidence=only)

    # Record the wrapped URLs so the reasoning stays visible rather than the
    # rules just silently not firing.
    if tracking_wrapped:
        signals.append(_sig(
            "URL_TRACKING_WRAPPED",
            f"{len(tracking_wrapped)} link(s) use the sender's click tracking",
            Severity.INFO,
            f"These links pass through a click-tracking redirector belonging to the "
            f"sender's email provider. The anchor-mismatch and redirect rules were "
            f"suppressed for them because the sending domain is cryptographically "
            f"authenticated — this is analytics, not cloaking.",
            evidence=", ".join(u[:70] for u in tracking_wrapped[:3]),
        ))

    # Brand consistency as POSITIVE evidence. If the message invokes a brand
    # and its main link resolves to that brand's own domain, the two agree —
    # which is the opposite of the impersonation pattern and should read that
    # way rather than simply not firing anything.
    claimed = intel.brands_mentioned((email.subject or "") + " " + (email.body_text or "")[:4000])
    if claimed and links:
        for brand in claimed[:3]:
            legit = set(intel.BRAND_DOMAINS.get(brand, []))
            if any(l.registered_domain in legit for l in links):
                signals.append(_sig(
                    "URL_BRAND_CONSISTENT", f"Links resolve to {brand.title()}'s own domain",
                    Severity.INFO,
                    f"The message refers to {brand.title()} and its links point to "
                    f"{', '.join(sorted(legit & {l.registered_domain for l in links}))}. "
                    f"Brand and destination agree, which is what genuine mail from an "
                    f"organisation looks like and the inverse of the impersonation "
                    f"pattern.",
                    evidence=next(l.url for l in links if l.registered_domain in legit)[:150],
                ))
                break

    if len(domains) >= 8:
        add("URL_MANY_DOMAINS", "Links scattered across many domains", Severity.LOW,
            f"The message links to {len(domains)} distinct domains. Common in newsletters, "
            f"also typical of templates assembled from harvested content.",
            evidence=", ".join(list(domains)[:8]))

    if email.body_html and len(links) > 25:
        add("URL_LINK_FLOOD", "Very large number of links", Severity.LOW,
            f"{len(links)} links in one message. Bulk-mail characteristic; raises the odds "
            f"that at least one is the intended trap.",
            evidence=f"{len(links)} links across {len(domains)} domains")

    return signals

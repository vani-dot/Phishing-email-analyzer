# tools.py
# The investigation toolbox the agent can call.
#
# Each tool answers ONE question about the message under analysis. They are
# deterministic, side-effect free, and bounded. Two of them touch the network
# and both are off unless the operator opts in.
#
# WHY TOOLS RATHER THAN ONE BIG PROMPT
# Dumping every fact into a single prompt makes the model a classifier: it sees
# a fixed summary, pattern-matches, and answers. Tools make it an investigator —
# it decides what to look at based on what it has found so far, and follows the
# thread. A summary cannot tell it "the third link's anchor text claims PayPal";
# it has to go and look.
#
# The practical difference is generalisation. A fixed prompt can only surface
# what its author thought to include. An agent that can ask "what is actually
# at the end of this URL" finds things nobody anticipated.
#
# SAFETY
# Tool RESULTS re-enter the conversation, so anything that returns message
# content is sanitised exactly like the body is — otherwise read_body() would
# be a clean route around the prompt-injection defence.

import base64
import binascii
import hashlib
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlsplit

import intel
from config import config
from models import ParsedEmail
from parser import domain_of, host_of

MAX_RESULT_CHARS = 2500


def _clip(text: str, limit: int = MAX_RESULT_CHARS) -> str:
    text = str(text)
    return text if len(text) <= limit else text[:limit] + f"\n[... truncated at {limit} chars ...]"


def _safe(text: str) -> str:
    """Neutralise message content before it re-enters the conversation."""
    from llm import sanitise_for_model
    cleaned, _ = sanitise_for_model(str(text), MAX_RESULT_CHARS)
    return cleaned


class Investigation:
    """Holds the message under analysis and dispatches tool calls against it."""

    def __init__(self, email: ParsedEmail, authenticated: bool = False):
        self.email = email
        self.authenticated = authenticated
        self.trail: List[Dict[str, Any]] = []

    # ---- dispatch --------------------------------------------------------

    def dispatch(self, name: str, args: Dict[str, Any]) -> str:
        handler = getattr(self, f"tool_{name}", None)
        if handler is None:
            return f"ERROR: no such tool '{name}'."
        try:
            result = handler(**args)
        except TypeError as exc:
            result = f"ERROR: wrong arguments for {name}: {exc}"
        except Exception as exc:  # noqa: BLE001 - a tool must never kill the run
            result = f"ERROR: {name} failed ({type(exc).__name__}: {exc})"
        result = _clip(result)
        self.trail.append({"tool": name, "args": args, "result": result[:600]})
        return result

    # ---- headers ---------------------------------------------------------

    def tool_read_headers(self, names: Optional[List[str]] = None) -> str:
        """Raw header values. The agent asks for what it wants to see."""
        if not self.email.headers_present:
            return "No headers were supplied with this message. Only the body is available."
        if not names:
            items = list(self.email.headers.items())[:40]
        else:
            items = [(n.lower(), self.email.headers.get(n.lower(), "(not present)"))
                     for n in names[:15]]
        lines = [f"{key}: {_safe(value)[:400]}" for key, value in items]
        if not names:
            lines.append(f"\nReceived chain ({len(self.email.received_chain)} hops):")
            for hop in self.email.received_chain[:6]:
                lines.append(f"  {_safe(hop)[:200]}")
        return "\n".join(lines) or "(no headers matched)"

    # ---- body ------------------------------------------------------------

    def tool_read_body(self, start: int = 0, length: int = 2000,
                       part: str = "text") -> str:
        """A window of the message body. Lets the agent read a long email in
        pieces rather than being handed a truncated summary."""
        source = self.email.body_html if part == "html" else self.email.body_text
        if not source:
            other = "html" if part == "text" else "text"
            return f"No {part} part in this message. Try part='{other}'."
        start = max(0, int(start))
        length = max(100, min(int(length), 4000))
        window = source[start:start + length]
        tail = "" if start + length >= len(source) else \
            f"\n[window {start}-{start+length} of {len(source)} chars; call again with start={start+length}]"
        return _safe(window) + tail

    def tool_search_body(self, pattern: str, regex: bool = False,
                         context: int = 90) -> str:
        """Find something specific in the FULL body, not a truncated copy.

        This is what lets the agent test a hypothesis — "does this message
        mention a bank account number anywhere" — against the whole text.
        """
        haystack = (self.email.body_text or "") + "\n" + (self.email.body_html or "")
        if not haystack.strip():
            return "The message has no body text to search."
        pattern = str(pattern)[:200]
        context = max(20, min(int(context), 300))
        try:
            matcher = (re.compile(pattern, re.IGNORECASE | re.DOTALL) if regex
                       else re.compile(re.escape(pattern), re.IGNORECASE))
        except re.error as exc:
            return f"ERROR: invalid regex: {exc}"
        hits = []
        for match in matcher.finditer(haystack[:200000]):
            lo = max(0, match.start() - context)
            hits.append(_safe(haystack[lo:match.end() + context]).replace("\n", " "))
            if len(hits) >= 6:
                break
        if not hits:
            return f"No match for {pattern!r} anywhere in the body."
        return f"{len(hits)} match(es) for {pattern!r}:\n" + \
               "\n".join(f"  ...{h}..." for h in hits)

    # ---- domains and URLs ------------------------------------------------

    def tool_inspect_domain(self, domain: str) -> str:
        """Everything known about a domain without touching the network."""
        raw = str(domain).strip().lower().strip("<>[]/ ")
        if "@" in raw:
            raw = raw.rsplit("@", 1)[-1]
        if "//" in raw:
            raw = urlsplit(raw).hostname or raw
        registrable = domain_of("x@" + raw) or raw
        tld = registrable.rsplit(".", 1)[-1] if "." in registrable else ""

        lines = [f"hostname          : {raw}",
                 f"registrable domain: {registrable}   <-- this is who controls it",
                 f"TLD               : .{tld}"]

        owner = next((b for b, domains in intel.BRAND_DOMAINS.items()
                      if registrable in domains), None)
        if owner:
            lines.append(f"VERDICT           : this IS a genuine {owner.title()} domain")
        else:
            lines.append("VERDICT           : not a known brand domain")

        lookalike = intel.lookalike_brand(raw)
        if lookalike:
            brand, legit, score = lookalike
            lines.append(f"LOOKALIKE WARNING : resembles '{legit}' ({brand.title()}) "
                         f"at {score:.0%} similarity but is NOT that domain")
        else:
            lines.append("lookalike check   : does not resemble any known brand")

        mixed = intel.has_mixed_scripts(raw)
        if mixed:
            lines.append(f"MIXED SCRIPTS     : contains both {mixed[0]} and {mixed[1]} "
                         f"characters — renders like Latin but is not")
        if raw.startswith("xn--") or ".xn--" in raw:
            lines.append("PUNYCODE          : internationalised domain, displays as ordinary text")
        if tld in intel.SUSPICIOUS_TLDS:
            lines.append(f"TLD reputation    : .{tld} has free/cheap registration and high abuse")
        if registrable in intel.URL_SHORTENERS:
            lines.append("SHORTENER         : hides its real destination until clicked")
        if registrable in intel.FREE_MAIL_PROVIDERS:
            lines.append("FREE WEBMAIL      : consumer mail provider, anyone can register")
        if registrable in intel.DISPOSABLE_MAIL:
            lines.append("DISPOSABLE        : throwaway mailbox service")
        if intel.is_tracking_wrapper(raw):
            lines.append("CLICK TRACKER     : this is an email provider's analytics "
                         "redirector — normal for bulk senders, NOT cloaking")
        sender_domain = domain_of(self.email.from_address)
        if sender_domain:
            lines.append(f"sender's domain   : {sender_domain} "
                         f"({'SAME' if sender_domain == registrable else 'DIFFERENT'})")
        return "\n".join(lines)

    def tool_inspect_url(self, url: str) -> str:
        """Full decomposition of one URL."""
        raw = str(url).strip()[:2000]
        try:
            parts = urlsplit(raw if "//" in raw else "http://" + raw)
        except ValueError as exc:
            return f"ERROR: unparseable URL ({exc})"
        host = (parts.hostname or "").lower()

        link = next((l for l in self.email.links if l.url == raw), None)
        lines = [f"url        : {raw[:300]}",
                 f"scheme     : {parts.scheme or '(none)'}",
                 f"host       : {host or '(none)'}",
                 f"path       : {parts.path or '/'}"]
        if parts.port:
            lines.append(f"port       : {parts.port}" +
                         ("   <-- non-standard" if parts.port not in (80, 443) else ""))
        if link and link.display_text:
            lines.append(f"shown to reader as: {_safe(link.display_text)[:150]}")
            claimed = re.findall(r"(?i)\b(?:https?://|www\.)[^\s<>\"']{1,200}", link.display_text)
            if claimed:
                claimed_domain = domain_of("x@" + (urlsplit(
                    claimed[0] if "://" in claimed[0] else "http://" + claimed[0]).hostname or ""))
                actual = domain_of("x@" + host)
                if claimed_domain and actual and claimed_domain != actual:
                    lines.append(f"MISMATCH   : text claims '{claimed_domain}' but it "
                                 f"opens '{actual}'")

        if "@" in (parts.netloc or ""):
            lines.append(f"USERINFO TRICK: everything before the @ "
                         f"('{parts.netloc.split('@')[0][:60]}') is discarded by the "
                         f"browser. The page that loads is '{host}'.")
        if raw.count("%") >= 5:
            lines.append(f"heavy encoding: {raw.count('%')} percent-escapes; decodes to "
                         f"{unquote(raw)[:150]}")
        try:
            query = parse_qs(parts.query or "")
        except (ValueError, UnicodeDecodeError):
            query = {}
        for key, values in query.items():
            for value in values[:1]:
                decoded = unquote(str(value))
                if re.match(r"(?i)^https?://", decoded):
                    lines.append(f"REDIRECT PARAM: '{key}' forwards to {decoded[:150]}")
        if re.search(r"(?i)/(login|signin|verify|account|secure|password|auth|billing|kyc)", parts.path or ""):
            lines.append("credential path: points at a sign-in or verification endpoint")
        lines.append("")
        lines.append("-- domain analysis --")
        lines.append(self.tool_inspect_domain(host))
        return "\n".join(lines)

    def tool_list_links(self) -> str:
        """Every link, with where it actually goes."""
        if not self.email.links:
            return "This message contains no links."
        sender = domain_of(self.email.from_address)
        lines = [f"{len(self.email.links)} link(s):"]
        for index, link in enumerate(self.email.links[:30]):
            note = []
            if link.registered_domain and link.registered_domain == sender:
                note.append("sender's own domain")
            if intel.is_tracking_wrapper(link.domain):
                note.append("click tracker")
            if link.registered_domain in intel.LEGITIMATE_DOMAINS:
                note.append("known brand")
            if intel.lookalike_brand(link.domain):
                note.append("LOOKALIKE")
            lines.append(f"  [{index}] {link.url[:150]}")
            lines.append(f"      -> {link.registered_domain or '(none)'}"
                         + (f"   [{', '.join(note)}]" if note else ""))
            if link.display_text:
                lines.append(f"      shown as: {_safe(link.display_text)[:90]}")
        return "\n".join(lines)

    # ---- sender ----------------------------------------------------------

    def tool_check_sender_alignment(self) -> str:
        """Does the cryptographic evidence support who this claims to be from?"""
        from parser import dkim_alignment
        if not self.email.headers_present:
            return "No headers supplied — sender authentication cannot be checked."
        aligned, signer = dkim_alignment(self.email)
        auth = (self.email.auth_results or "").lower()
        from_domain = domain_of(self.email.from_address)
        lines = [
            f"From address      : {self.email.from_address}",
            f"From domain       : {from_domain}",
            f"display name      : {_safe(self.email.from_display)[:120] or '(none)'}",
            f"DKIM signing domain: {signer or '(none found)'}",
            f"DKIM aligned      : {aligned}  "
            f"({'signature was made BY the From domain' if aligned else 'signed by a different domain, or unsigned'})",
            f"DMARC pass        : {'dmarc=pass' in auth}",
            f"SPF pass          : {'spf=pass' in auth}",
        ]
        if self.authenticated:
            lines.append("CONCLUSION        : VERIFIED. The From domain provably authorised "
                         "this message. Note: proves WHO sent it, not that the request "
                         "inside is legitimate.")
        else:
            lines.append("CONCLUSION        : NOT verified. The From header may be forged.")
        if self.email.reply_to:
            reply_domain = domain_of(self.email.reply_to)
            lines.append(f"Reply-To          : {self.email.reply_to}" +
                         ("   <-- DIFFERENT DOMAIN, replies go elsewhere"
                          if reply_domain != from_domain else ""))
        if self.email.return_path:
            lines.append(f"Return-Path       : {self.email.return_path}")
        return "\n".join(lines)

    def tool_compare_to_brand(self, brand: str) -> str:
        """Would this brand legitimately send from this domain?"""
        key = str(brand).strip().lower()
        match = next((b for b in intel.BRAND_DOMAINS if b == key or b in key or key in b), None)
        if not match:
            return (f"'{brand}' is not in the known-brand list, so no authoritative "
                    f"comparison is possible. Judge from the domain itself.")
        legit = intel.BRAND_DOMAINS[match]
        sender = domain_of(self.email.from_address)
        link_domains = sorted({l.registered_domain for l in self.email.links if l.registered_domain})
        lines = [f"{match.title()} legitimately sends from: {', '.join(legit)}",
                 f"this message was sent from       : {sender or '(unknown)'}",
                 f"sender matches the brand         : {sender in legit}"]
        if link_domains:
            lines.append(f"link destinations                : {', '.join(link_domains[:8])}")
            lines.append(f"any link on a genuine {match} domain: "
                         f"{any(d in legit for d in link_domains)}")
        return "\n".join(lines)

    # ---- attachments -----------------------------------------------------

    def tool_inspect_attachments(self) -> str:
        """What the attached files actually are, by content not by name."""
        if not self.email.attachments:
            return "This message has no attachments."
        lines = []
        for att in self.email.attachments[:15]:
            lines.append(f"filename     : {att.filename}")
            lines.append(f"  size       : {att.size:,} bytes")
            lines.append(f"  declared   : {att.content_type or '(none)'}  "
                         f"extension {att.declared_ext or '(none)'}")
            lines.append(f"  ACTUAL type: {att.detected_type or 'could not identify'}")
            lines.append(f"  sha256     : {att.sha256 or '(empty file)'}")
            if att.declared_ext in intel.DANGEROUS_EXTENSIONS:
                lines.append("  WARNING    : this extension executes code on open")
            if att.declared_ext in intel.MACRO_EXTENSIONS:
                lines.append("  WARNING    : macro-enabled Office format")
            if att.declared_ext in intel.CONTAINER_EXTENSIONS:
                lines.append("  WARNING    : disk image — strips mark-of-the-web from contents")
            if re.search(r"(?i)\.(pdf|docx?|xlsx?|jpg|png|txt)\s*\.(exe|scr|js|vbs|bat|cmd|lnk|hta)$",
                         att.filename or ""):
                lines.append("  WARNING    : DOUBLE EXTENSION — disguised as a document")
            if any(c in (att.filename or "") for c in "‪‫‬‭‮"):
                lines.append("  WARNING    : filename contains a right-to-left override")
        return "\n".join(lines)

    # ---- decoding --------------------------------------------------------

    def tool_decode(self, text: str, method: str = "auto") -> str:
        """Decode something the agent spotted: base64, percent-encoding,
        punycode, or homoglyph-folded text."""
        raw = str(text)[:2000]
        out = []
        if method in ("auto", "url"):
            decoded = unquote(raw)
            if decoded != raw:
                out.append(f"url-decoded : {_safe(decoded)[:400]}")
        if method in ("auto", "base64"):
            candidate = re.sub(r"\s+", "", raw)
            if len(candidate) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=]+", candidate or "x"):
                try:
                    decoded = base64.b64decode(candidate + "=" * (-len(candidate) % 4),
                                               validate=False)
                    text_out = decoded.decode("utf-8", "replace")
                    if sum(c.isprintable() for c in text_out) > len(text_out) * 0.7:
                        out.append(f"base64      : {_safe(text_out)[:400]}")
                except (binascii.Error, ValueError):
                    pass
        if method in ("auto", "punycode"):
            for label in raw.split("."):
                if label.startswith("xn--"):
                    try:
                        out.append(f"punycode    : {label} -> "
                                   f"{label.encode().decode('idna', errors='replace')}")
                    except (UnicodeError, ValueError):
                        out.append(f"punycode    : {label} -> (could not decode)")
        folded = intel.deskeleton(raw)
        if folded != raw.lower():
            out.append(f"homoglyph-folded to ASCII shape: {folded[:300]}")
        return "\n".join(out) if out else f"Nothing decoded from {raw[:120]!r}."

    # ---- network (opt-in) ------------------------------------------------

    def tool_lookup_dns(self, domain: str) -> str:
        """Live DNS: does this domain look like it actually sends mail?"""
        if not config.ENABLE_DNS_CHECKS:
            return ("DNS lookups are disabled by configuration (PEA_ENABLE_DNS_CHECKS). "
                    "Judge from the offline evidence.")
        import netcheck
        registrable = domain_of("x@" + str(domain).strip().lower())
        records = netcheck.domain_records(registrable)
        if records.get("error"):
            return f"DNS lookup unavailable: {records['error']}"
        lines = [f"domain: {registrable}",
                 f"  MX   : {', '.join(records['mx']) if records.get('mx') else 'NONE — cannot receive mail'}",
                 f"  SPF  : {records.get('spf') or 'none published'}",
                 f"  DMARC: {records.get('dmarc') or 'none published'}"]
        if not records.get("mx"):
            lines.append("  NOTE : a domain with no MX record cannot receive replies, "
                         "which is common for throwaway phishing infrastructure")
        return "\n".join(lines)

    def tool_expand_url(self, url: str) -> str:
        """Follow a redirect chain to its real destination. SSRF-guarded."""
        if not config.ENABLE_URL_EXPANSION:
            return ("Outbound URL expansion is disabled by configuration "
                    "(PEA_ENABLE_URL_EXPANSION). Judge from the URL as written.")
        import netcheck
        chain, status = netcheck.expand_redirects(str(url)[:2000])
        if not chain:
            return f"Could not expand: {status}"
        lines = [f"redirect chain ({len(chain)} hops), status: {status}"]
        for hop in chain[:10]:
            lines.append(f"  -> {hop[:200]}")
        final_domain = domain_of("x@" + (urlsplit(chain[-1]).hostname or ""))
        lines.append("")
        lines.append(f"final destination domain: {final_domain}")
        lines.append(self.tool_inspect_domain(final_domain))
        return "\n".join(lines)

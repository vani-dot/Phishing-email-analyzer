# parser.py
# Raw input -> ParsedEmail. Nothing in here judges anything; it only reads.
#
# The input is hostile by definition. Every loop in this file is bounded, every
# decode has an errors= policy, and nothing is ever rendered or executed —
# attachments are hashed and described, never written to disk or opened, and
# HTML is parsed for structure only. BeautifulSoup builds a tree; it does not
# fetch sub-resources or run script.

import email
import email.policy
import hashlib
import re
from email.header import decode_header, make_header
from email.message import Message
from email.utils import parseaddr
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from config import config
from models import Attachment, LinkInfo, ParsedEmail

import tldextract

# suffix_list_urls=() forces the bundled Public Suffix List snapshot. No
# network call on first use, deterministic results, and one less outbound
# request from a security tool.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Bounded on both sides so a pathological body cannot drive the regex engine
# into quadratic behaviour. No nested quantifiers.
URL_RE = re.compile(
    r"""(?i)\b(?:https?://|ftp://|www\.)[^\s<>"'`\]\[{}|\\^]{1,2000}""",
)

# Header names worth surfacing in the UI's raw-header view.
INTERESTING_HEADERS = (
    "from", "to", "cc", "reply-to", "return-path", "subject", "date",
    "message-id", "authentication-results", "received-spf", "dkim-signature",
    "x-mailer", "x-originating-ip", "x-priority", "list-unsubscribe",
    "content-type", "mime-version", "x-spam-status", "x-spam-score",
    "sender", "x-sender", "x-forwarded-for", "user-agent",
    # Needed by rules, not just the UI. Without in-reply-to / references the
    # hijacked-thread check (HDR_THREAD_DOMAIN_MISMATCH) never received its
    # input from a real .eml file; without list-id the bulk-mail marker only
    # ever saw list-unsubscribe.
    "in-reply-to", "references", "list-id",
)

# First bytes -> real format. Replaces python-magic, which needs a libmagic
# system install that breaks on any machine that is not the developer's.
MAGIC_SIGNATURES: List[Tuple[bytes, str]] = [
    (b"MZ", "PE executable (.exe/.dll)"),
    (b"\x7fELF", "ELF executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O / Java class"),
    (b"%PDF-", "PDF document"),
    (b"PK\x03\x04", "ZIP archive (also .docx/.xlsx/.jar/.apk)"),
    (b"PK\x05\x06", "ZIP archive (empty)"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 / legacy Office document"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"GIF8", "GIF image"),
    (b"<!DOCTYPE html", "HTML document"),
    (b"<html", "HTML document"),
    (b"#!", "Script with shebang"),
    (b"{\\rtf", "RTF document"),
]


def _decode_header_value(raw: Optional[str]) -> str:
    """Decode RFC 2047 (=?utf-8?B?...?=) without ever raising.

    Phishing mail encodes headers specifically to slip past naive string
    matching, so this has to work — but a malformed encoded word is itself
    common in phishing, and must not crash the parse.
    """
    if not raw:
        return ""
    try:
        value = str(make_header(decode_header(raw)))
    except Exception:
        # Deliberately broad. email.errors.HeaderParseError does NOT inherit
        # from ValueError, and neither do several other failures this call can
        # produce on malformed input. Phishing mail malforms encoded words on
        # purpose — a header that breaks the parser is a header that never gets
        # inspected — so the only safe policy is to fall back to the raw string
        # and keep analysing.
        value = str(raw)
    # Header injection artefacts and null bytes have no business downstream.
    value = value.replace("\x00", "").replace("\r", " ").replace("\n", " ")
    return value.strip()[:1000]


def looks_like_email(text: str) -> bool:
    """Does this input carry real RFC 822 headers?

    A paste of just the message body is a legitimate input mode, but it must
    not be scored as though the headers were present and clean.
    """
    head = text[:8000]
    header_line = re.compile(r"(?im)^(from|to|subject|date|received|message-id|return-path)\s*:")
    return len(header_line.findall(head)) >= 2


def _best_charset(part: Message) -> str:
    charset = part.get_content_charset()
    return charset if charset else "utf-8"


def _part_text(part: Message) -> str:
    """Decoded payload of one MIME part, with every failure mode handled."""
    try:
        payload = part.get_payload(decode=True)
    except (AssertionError, ValueError, TypeError):
        return ""
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    if not isinstance(payload, bytes):
        return str(payload)
    try:
        return payload.decode(_best_charset(part), errors="replace")
    except (LookupError, UnicodeDecodeError, TypeError):
        return payload.decode("utf-8", errors="replace")


def _sniff_type(data: bytes) -> Optional[str]:
    for signature, label in MAGIC_SIGNATURES:
        if data.startswith(signature):
            return label
    return None


def _normalise_url(raw: str) -> str:
    url = raw.strip().rstrip(".,;:!?)”\"'")
    if url.lower().startswith("www."):
        url = "http://" + url
    return url[:2000]


def _link_from_url(url: str, display_text: Optional[str] = None) -> Optional[LinkInfo]:
    url = _normalise_url(url)
    if not url:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    ext = _extract(host)
    registered = ".".join(p for p in (ext.domain, ext.suffix) if p)
    return LinkInfo(
        url=url,
        domain=host,
        registered_domain=registered,
        scheme=(parts.scheme or "").lower(),
        display_text=display_text[:200] if display_text else None,
    )


def extract_links_from_text(text: str) -> List[LinkInfo]:
    links = []
    seen = set()
    for match in URL_RE.findall(text[: config.MAX_BODY_CHARS]):
        link = _link_from_url(match)
        if link and link.url not in seen:
            seen.add(link.url)
            links.append(link)
        if len(links) >= config.MAX_URLS_SCANNED:
            break
    return links


def extract_links_from_html(html: str) -> List[LinkInfo]:
    """Anchors plus their visible text.

    The display-text vs href comparison this enables is one of the strongest
    single signals in the whole analyser, so the anchor text is captured here
    rather than reconstructed later.
    """
    links: List[LinkInfo] = []
    seen = set()
    try:
        soup = BeautifulSoup(html[: config.MAX_BODY_CHARS], "html.parser")
    except Exception:
        return links

    for anchor in soup.find_all("a", href=True):
        href = str(anchor.get("href", "")).strip()
        if not href or href.startswith(("mailto:", "tel:", "#")):
            continue
        link = _link_from_url(href, anchor.get_text(strip=True) or None)
        if link and link.url not in seen:
            seen.add(link.url)
            links.append(link)
        if len(links) >= config.MAX_URLS_SCANNED:
            return links

    # Forms posting off-site are a credential-harvest pattern in their own
    # right — a login box rendered inside the mail client.
    for form in soup.find_all("form", action=True):
        link = _link_from_url(str(form.get("action", "")), "[form action]")
        if link and link.url not in seen:
            seen.add(link.url)
            links.append(link)
        if len(links) >= config.MAX_URLS_SCANNED:
            break
    return links


def html_to_text(html: str) -> str:
    try:
        soup = BeautifulSoup(html[: config.MAX_BODY_CHARS], "html.parser")
        for tag in soup(["script", "style", "head"]):
            tag.decompose()
        return soup.get_text(" ", strip=True)[: config.MAX_BODY_CHARS]
    except Exception:
        return re.sub(r"<[^>]{0,500}>", " ", html[: config.MAX_BODY_CHARS])


def parse_email(raw: str, filename: Optional[str] = None) -> ParsedEmail:
    """The one entry point. Accepts a full .eml or a bare pasted body."""
    notes: List[str] = []
    if not isinstance(raw, str):
        raw = str(raw)
    raw = raw.replace("\x00", "")
    if len(raw) > config.MAX_BODY_CHARS:
        raw = raw[: config.MAX_BODY_CHARS]
        notes.append(f"Input truncated to {config.MAX_BODY_CHARS:,} characters.")

    headers_present = looks_like_email(raw)
    if not headers_present:
        # Body-only paste. Still fully analysable for content and URL signals;
        # the report states plainly that header checks could not run.
        notes.append(
            "No email headers found — analysed as message body only. "
            "Header, SPF/DKIM/DMARC and sender checks could not run."
        )
        body_text = raw
        body_html = raw if re.search(r"(?i)<(a|html|body|div|table|form)\b", raw) else ""
        if body_html:
            body_text = html_to_text(raw)
        links = extract_links_from_html(body_html) if body_html else []
        text_links = extract_links_from_text(raw)
        known = {l.url for l in links}
        links.extend(l for l in text_links if l.url not in known)
        return ParsedEmail(
            body_text=body_text[: config.MAX_BODY_CHARS],
            body_html=body_html[: config.MAX_BODY_CHARS],
            links=links[: config.MAX_URLS_SCANNED],
            headers_present=False,
            parse_notes=notes,
        )

    try:
        # Parsed from BYTES, not from str. message_from_string() with compat32
        # stores the body as a str, and get_payload(decode=True) then has to
        # turn it back into bytes — it does so with 'raw-unicode-escape', which
        # rewrites every non-ASCII character as a literal \uXXXX text sequence.
        # That silently destroys exactly the evidence this analyser cares most
        # about: zero-width characters, Cyrillic homoglyphs and bidi overrides
        # all arrive as harmless ASCII and every Unicode evasion check goes
        # quiet. Encoding to UTF-8 first keeps the real code points intact.
        msg = email.message_from_bytes(raw.encode("utf-8", "surrogatepass"),
                                       policy=email.policy.compat32)
    except Exception as exc:
        notes.append(f"Header parse failed ({type(exc).__name__}); treated as plain text.")
        return ParsedEmail(
            body_text=raw[: config.MAX_BODY_CHARS],
            links=extract_links_from_text(raw),
            headers_present=False,
            parse_notes=notes,
        )

    headers = {}
    for index, (key, value) in enumerate(msg.items()):
        if index >= config.MAX_HEADER_COUNT:
            notes.append(f"Header list truncated at {config.MAX_HEADER_COUNT}.")
            break
        key_l = key.lower()
        if key_l in INTERESTING_HEADERS or key_l.startswith(("x-", "arc-", "dkim")):
            existing = headers.get(key_l)
            decoded = _decode_header_value(value)
            headers[key_l] = f"{existing} | {decoded}" if existing else decoded

    from_raw = _decode_header_value(msg.get("From", ""))
    from_display, from_address = parseaddr(from_raw)
    _, reply_to = parseaddr(_decode_header_value(msg.get("Reply-To", "")))
    _, return_path = parseaddr(_decode_header_value(msg.get("Return-Path", "")))

    received = []
    for value in msg.get_all("Received", [])[:30]:
        received.append(_decode_header_value(value)[:400])

    # ---- walk the MIME tree, bounded ------------------------------------
    body_text_parts: List[str] = []
    body_html_parts: List[str] = []
    attachments: List[Attachment] = []
    part_count = 0

    for part in msg.walk():
        part_count += 1
        if part_count > config.MAX_MIME_PARTS:
            notes.append(f"MIME tree truncated at {config.MAX_MIME_PARTS} parts.")
            break
        if part.is_multipart():
            continue

        content_type = (part.get_content_type() or "").lower()
        disposition = str(part.get("Content-Disposition", "") or "").lower()
        raw_name = part.get_filename()
        filename_part = _decode_header_value(raw_name) if raw_name else ""

        is_attachment = "attachment" in disposition or bool(filename_part)

        if is_attachment:
            if len(attachments) >= config.MAX_ATTACHMENTS:
                continue
            try:
                data = part.get_payload(decode=True) or b""
            except (AssertionError, ValueError, TypeError):
                data = b""
            # Strip any path component: a filename is a label here, and this
            # application never writes it, but a "../../" name should still be
            # shown for what it is rather than silently normalised away.
            clean_name = filename_part.replace("\\", "/").split("/")[-1][:250]
            ext = ""
            if "." in clean_name:
                ext = "." + clean_name.rsplit(".", 1)[-1].lower()
            attachments.append(Attachment(
                filename=filename_part[:250] or "(unnamed)",
                content_type=content_type,
                size=len(data),
                sha256=hashlib.sha256(data).hexdigest() if data else "",
                declared_ext=ext,
                detected_type=_sniff_type(data[:64]) if data else None,
            ))
            continue

        if content_type == "text/plain":
            body_text_parts.append(_part_text(part))
        elif content_type == "text/html":
            body_html_parts.append(_part_text(part))

    body_text = "\n".join(body_text_parts)[: config.MAX_BODY_CHARS]
    body_html = "\n".join(body_html_parts)[: config.MAX_BODY_CHARS]
    if not body_text and body_html:
        body_text = html_to_text(body_html)

    links = extract_links_from_html(body_html) if body_html else []
    known = {l.url for l in links}
    for link in extract_links_from_text(body_text):
        if link.url not in known and len(links) < config.MAX_URLS_SCANNED:
            known.add(link.url)
            links.append(link)

    return ParsedEmail(
        subject=_decode_header_value(msg.get("Subject", "")),
        from_address=from_address.lower()[:320],
        from_display=from_display[:250],
        reply_to=reply_to.lower()[:320],
        return_path=return_path.lower()[:320],
        to=_decode_header_value(msg.get("To", ""))[:500],
        date=_decode_header_value(msg.get("Date", "")),
        message_id=_decode_header_value(msg.get("Message-ID", ""))[:250],
        auth_results=_decode_header_value(msg.get("Authentication-Results", "")),
        received_chain=received,
        headers=headers,
        body_text=body_text,
        body_html=body_html,
        links=links,
        attachments=attachments,
        headers_present=True,
        parse_notes=notes,
    )


def domain_of(address: str) -> str:
    """Registered domain of an email address, '' if unparseable."""
    if not address or "@" not in address:
        return ""
    host = address.rsplit("@", 1)[-1].strip().lower().strip("<>[] ")
    ext = _extract(host)
    return ".".join(p for p in (ext.domain, ext.suffix) if p)


def host_of(address: str) -> str:
    if not address or "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].strip().lower().strip("<>[] ")


def dkim_alignment(email: ParsedEmail) -> Tuple[bool, Optional[str]]:
    """Does the DKIM signing domain match the domain in the From header?

    This is the distinction that matters and the one the analyser previously
    missed. A bare "dkim=pass" only says SOME domain signed the message — an
    email service provider signing with its own domain passes DKIM while
    proving nothing about the sender it claims to be. Alignment means the
    signature was made by the domain in the From header itself, which is
    cryptographic proof that that domain authorised this message.

    Returns (aligned, signing_domain).
    """
    auth = email.auth_results or ""
    from_domain = domain_of(email.from_address)
    if not from_domain:
        return False, None

    # Every d= that passed. A message routed through an ESP carries two: the
    # ESP's own and the sender's. Only the sender's counts as alignment.
    signing_domains = []
    for match in re.finditer(r"dkim\s*=\s*pass[^;]*?header\.d\s*=\s*([A-Za-z0-9.\-]+)",
                             auth, re.IGNORECASE):
        signing_domains.append(match.group(1).lower().strip("."))
    # Fall back to the DKIM-Signature header when Authentication-Results did
    # not spell out the signing domain.
    if not signing_domains:
        raw = email.headers.get("dkim-signature", "")
        for match in re.finditer(r"\bd\s*=\s*([A-Za-z0-9.\-]+)", raw):
            signing_domains.append(match.group(1).lower().strip("."))

    for signer in signing_domains:
        if domain_of("x@" + signer) == from_domain:
            return True, signer
    return False, signing_domains[0] if signing_domains else None

# headers_check.py
# Signals derived from the envelope and headers.
#
# Reasoning model: headers are where a spoof has to commit to something
# checkable. A body can claim anything at zero cost, but to actually deliver
# mail the sender must publish a From, survive the receiving server's SPF and
# DKIM evaluation, and leave a Received trail. Contradictions between what the
# mail claims and what it had to do to arrive are the highest-confidence
# evidence available, which is why these signals carry the heaviest weights.
#
# Each check states, in its detail string, what was observed and why that
# observation matters. That text is what the analyst reads — a signal that
# cannot explain itself is not worth firing.

import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import List

import intel
from models import Category, ParsedEmail, Severity, Signal
from parser import domain_of, host_of


def _sig(code, title, severity, detail, evidence=None, category=Category.HEADER) -> Signal:
    return Signal(code=code, title=title, category=category,
                  severity=severity, detail=detail, evidence=evidence)


def _parse_auth_results(auth: str):
    """Pull spf/dkim/dmarc results out of an Authentication-Results header.

    This header is written by the RECEIVING server, not the sender, so it is
    trustworthy in the normal case — the sender cannot forge it into the copy
    the recipient's own server stamped. The catch is that a forwarded or
    re-saved message can carry a stale one, so a pass is treated as "no
    evidence of spoofing" rather than proof of legitimacy.
    """
    out = {}
    lowered = auth.lower()
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(mechanism + r"\s*=\s*([a-z]+)", lowered)
        if match:
            out[mechanism] = match.group(1)
    return out


def analyse_headers(email: ParsedEmail, authenticated: bool = False) -> List[Signal]:
    """Header signals.

    `authenticated` means DKIM aligned with the From domain AND DMARC passed.
    Several rules below are DISABLED — not merely down-weighted — when it is
    true, because the behaviour they describe is standard for mail sent
    through a commercial provider and is only suspicious in the absence of
    cryptographic proof of the sender.
    """
    signals: List[Signal] = []

    if not email.headers_present:
        # Stated explicitly and scored at zero. The alternative — staying
        # silent — reads as "headers checked, nothing found", which is the
        # opposite of the truth and would quietly inflate the safety of every
        # body-only paste.
        signals.append(_sig(
            "HDR_ABSENT", "No headers supplied", Severity.INFO,
            "Input had no RFC 822 headers, so sender authentication, spoofing "
            "and routing checks could not run. Verdict rests on body and URL "
            "evidence alone — paste the full message with headers for a "
            "complete assessment.",
        ))
        return signals

    from_domain = domain_of(email.from_address)
    from_host = host_of(email.from_address)

    # ---- 1. sender authentication ---------------------------------------
    auth = _parse_auth_results(email.auth_results)
    if email.auth_results:
        for mechanism, label, explain in (
            ("spf", "SPF", "the sending server is not authorised to send for that domain"),
            ("dkim", "DKIM", "the message signature did not validate, so the content or sender was altered in transit or never signed"),
            ("dmarc", "DMARC", "the domain owner's published policy was not satisfied"),
        ):
            result = auth.get(mechanism)
            if result in ("fail", "permerror"):
                signals.append(_sig(
                    f"AUTH_{mechanism.upper()}_FAIL", f"{label} authentication failed",
                    Severity.CRITICAL,
                    f"The receiving mail server recorded {label.lower()}={result} — {explain}. "
                    f"This is a direct, server-verified contradiction of the claimed sender.",
                    evidence=email.auth_results[:300],
                ))
            elif result == "softfail":
                signals.append(_sig(
                    f"AUTH_{mechanism.upper()}_SOFTFAIL", f"{label} soft-failed", Severity.HIGH,
                    f"{label} returned softfail: the domain owner lists this sender as "
                    f"probably unauthorised but asked receivers not to reject outright.",
                    evidence=email.auth_results[:300],
                ))
            elif result in ("none", "neutral") and mechanism == "dmarc":
                signals.append(_sig(
                    "AUTH_DMARC_NONE", "Sender domain publishes no DMARC policy", Severity.LOW,
                    "No DMARC policy was found for the sending domain. Legitimate "
                    "organisations that send transactional mail normally publish one, "
                    "and its absence means nothing stops anyone spoofing this domain.",
                ))
    else:
        signals.append(_sig(
            "AUTH_MISSING", "No Authentication-Results header", Severity.MEDIUM,
            "The message carries no Authentication-Results header, so SPF, DKIM "
            "and DMARC outcomes are unknown. Mail delivered through a normal "
            "provider almost always has one; its absence suggests the message was "
            "saved before delivery, hand-crafted, or injected directly.",
        ))

    # ---- 2. address relationships ---------------------------------------
    # Reasoning: a real sender wants replies at the domain they sent from.
    # Redirecting replies elsewhere is how a spoof collects the conversation
    # without controlling the mailbox it impersonated.
    if email.reply_to:
        reply_domain = domain_of(email.reply_to)
        if reply_domain and from_domain and reply_domain != from_domain:
            signals.append(_sig(
                "HDR_REPLY_TO_MISMATCH", "Reply-To points to a different domain",
                Severity.HIGH,
                f"Mail claims to be from {from_domain} but replies are directed to "
                f"{reply_domain}. This is how an impersonator receives the victim's "
                f"response without ever controlling the domain they are imitating.",
                evidence=f"From: {email.from_address}  |  Reply-To: {email.reply_to}",
            ))

    # Envelope-vs-header mismatch is how EVERY email service provider sends
    # mail: Amazon SES bounces to amazonses.com while the From stays
    # amazon.in. When DKIM aligns and DMARC passes, the header From is
    # cryptographically proven and the envelope domain tells us nothing —
    # so this rule contributes zero rather than a reduced amount.
    if email.return_path and not authenticated:
        return_domain = domain_of(email.return_path)
        if return_domain and from_domain and return_domain != from_domain:
            signals.append(_sig(
                "HDR_RETURN_PATH_MISMATCH", "Return-Path does not match From",
                Severity.MEDIUM,
                f"The envelope sender ({return_domain}) differs from the displayed "
                f"sender ({from_domain}). Bulk senders legitimately do this, but it is "
                f"also the basic shape of a forged From header.",
                evidence=f"From: {email.from_address}  |  Return-Path: {email.return_path}",
            ))

    # ---- 3. display-name deception --------------------------------------
    # Reasoning: mail clients show the display name and hide the address.
    # That gap is the cheapest, most effective impersonation available.
    display = email.from_display or ""
    if display:
        embedded = re.search(r"[\w.+-]{1,64}@[\w.-]{1,190}\.[a-zA-Z]{2,24}", display)
        if embedded and embedded.group(0).lower() != email.from_address.lower():
            signals.append(_sig(
                "HDR_DISPLAY_NAME_SPOOF", "Display name contains a different address",
                Severity.CRITICAL,
                f"The name shown to the recipient reads as '{embedded.group(0)}' while "
                f"the message actually comes from '{email.from_address}'. Most mail "
                f"clients show only the name, so the recipient sees an address that is "
                f"not the one that sent this.",
                evidence=f"Display: {display[:120]}  |  Actual: {email.from_address}",
            ))

        claimed = intel.brands_mentioned(display, limit=3)
        for brand in claimed:
            legit = intel.BRAND_DOMAINS.get(brand, [])
            if from_domain and from_domain not in legit:
                if from_domain in intel.FREE_MAIL_PROVIDERS:
                    signals.append(_sig(
                        "HDR_BRAND_FROM_FREEMAIL", f"Claims to be {brand.title()} but sent from free webmail",
                        Severity.CRITICAL,
                        f"The sender presents itself as {brand.title()} while sending from "
                        f"{from_domain}, a free consumer mail provider. {brand.title()} sends "
                        f"from {legit[0]}. No organisation sends official mail this way.",
                        evidence=f"Display: {display[:120]}  |  From: {email.from_address}",
                    ))
                else:
                    signals.append(_sig(
                        "HDR_BRAND_DOMAIN_MISMATCH", f"Claims to be {brand.title()} from an unrelated domain",
                        Severity.HIGH,
                        f"The display name says {brand.title()}, but the message was sent from "
                        f"{from_domain}, which is not one of their known sending domains "
                        f"({', '.join(legit[:3])}).",
                        evidence=f"Display: {display[:120]}  |  From: {email.from_address}",
                    ))

    # ---- 4. the sending domain itself -----------------------------------
    if from_domain:
        lookalike = intel.lookalike_brand(from_host or from_domain)
        if lookalike:
            brand, legit, score = lookalike
            signals.append(_sig(
                "HDR_LOOKALIKE_DOMAIN", "Sender domain imitates a known brand",
                Severity.CRITICAL,
                f"The sending domain '{from_host}' resolves to the visual shape of "
                f"'{legit}' ({brand.title()}) at {score:.0%} similarity, but is not that "
                f"domain. Registering a near-identical domain is the defining move of a "
                f"credential-harvesting campaign.",
                evidence=f"{from_host}  ~  {legit}",
                category=Category.HEADER,
            ))

        mixed = intel.has_mixed_scripts(from_host)
        if mixed:
            signals.append(_sig(
                "HDR_MIXED_SCRIPT_DOMAIN", "Sender domain mixes writing systems",
                Severity.CRITICAL,
                f"The domain contains both {mixed[0].title()} and {mixed[1].title()} "
                f"characters. A genuine domain has no reason to mix alphabets; this is "
                f"done so the name renders identically to a real one while resolving "
                f"somewhere else entirely.",
                evidence=from_host,
            ))

        if from_host.startswith("xn--") or ".xn--" in from_host:
            signals.append(_sig(
                "HDR_PUNYCODE_DOMAIN", "Sender domain is punycode-encoded", Severity.HIGH,
                f"'{from_host}' is an internationalised domain shown in its encoded form. "
                f"These render as ordinary-looking words in a mail client, which is what "
                f"makes them useful for impersonation.",
                evidence=from_host,
            ))

        tld = from_domain.rsplit(".", 1)[-1] if "." in from_domain else ""
        if tld in intel.SUSPICIOUS_TLDS:
            signals.append(_sig(
                "HDR_SUSPICIOUS_TLD", f"Sender uses a high-abuse TLD (.{tld})", Severity.MEDIUM,
                f"The domain sits on .{tld}, a top-level domain with free or near-free "
                f"registration and a correspondingly high rate of abuse. Weak on its own; "
                f"meaningful alongside other findings.",
                evidence=from_domain,
            ))

        if from_domain in intel.DISPOSABLE_MAIL:
            signals.append(_sig(
                "HDR_DISPOSABLE_SENDER", "Sent from a disposable mail service", Severity.HIGH,
                f"{from_domain} provides throwaway inboxes that need no identity and expire "
                f"on their own. It is a sender address chosen to be untraceable.",
                evidence=email.from_address,
            ))
    else:
        signals.append(_sig(
            "HDR_NO_FROM", "Missing or unparseable From address", Severity.HIGH,
            "No valid sender address could be read from the From header. Legitimate mail "
            "always has one; its absence indicates a hand-crafted or damaged message.",
            evidence=email.headers.get("from", "")[:200],
        ))

    # ---- 5. routing ------------------------------------------------------
    # Reasoning: every hop appends a Received header. The trail is written by
    # the servers, not the sender, so a missing or too-short trail means the
    # message did not travel the way a real one does.
    hops = len(email.received_chain)
    if hops == 0:
        signals.append(_sig(
            "HDR_NO_RECEIVED", "No Received headers", Severity.HIGH,
            "The message carries no routing trail at all. Any mail that actually "
            "crossed the internet accumulates at least one Received header, so this "
            "was composed locally, injected directly into a server, or stripped.",
        ))
    elif hops == 1:
        signals.append(_sig(
            "HDR_SHORT_ROUTE", "Only one routing hop", Severity.LOW,
            "A single Received header. Normal for internal mail, unusual for anything "
            "claiming to come from an external organisation.",
        ))

    for line in email.received_chain[:5]:
        if re.search(r"\[(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.)", line):
            signals.append(_sig(
                "HDR_PRIVATE_IP_HOP", "Routing trail includes a private IP", Severity.LOW,
                "A Received header references RFC 1918 private address space. Expected "
                "inside a corporate network, out of place on mail claiming an external origin.",
                evidence=line[:200],
            ))
            break

    # ---- 6. identifier consistency ---------------------------------------
    if email.message_id:
        mid_host = email.message_id.split("@")[-1].strip("<>[] ").lower() if "@" in email.message_id else ""
        if mid_host and from_domain:
            mid_domain = domain_of("x@" + mid_host)
            if mid_domain and mid_domain != from_domain:
                signals.append(_sig(
                    "HDR_MESSAGE_ID_MISMATCH", "Message-ID domain differs from sender",
                    Severity.LOW,
                    f"The Message-ID was generated by {mid_domain} while the mail claims to "
                    f"come from {from_domain}. Relays and mailing lists cause this "
                    f"legitimately, so it is corroboration rather than proof.",
                    evidence=email.message_id[:200],
                ))
    else:
        signals.append(_sig(
            "HDR_NO_MESSAGE_ID", "Missing Message-ID", Severity.LOW,
            "No Message-ID header. Every standards-compliant mail server adds one; "
            "bulk-sending scripts frequently do not.",
        ))

    # ---- 7. date ---------------------------------------------------------
    if email.date:
        try:
            sent = parsedate_to_datetime(email.date)
            if sent:
                now = datetime.now(timezone.utc)
                if sent.tzinfo is None:
                    sent = sent.replace(tzinfo=timezone.utc)
                if sent > now + timedelta(days=1):
                    signals.append(_sig(
                        "HDR_FUTURE_DATE", "Sent date is in the future", Severity.MEDIUM,
                        f"The Date header reads {sent.date()}, later than the present. "
                        f"Post-dating is used to float a message to the top of a mailbox "
                        f"and indicates a forged header.",
                        evidence=email.date,
                    ))
                elif sent < now - timedelta(days=3650):
                    signals.append(_sig(
                        "HDR_ANCIENT_DATE", "Implausible sent date", Severity.LOW,
                        f"The Date header reads {sent.date()}, over ten years old — "
                        f"typically a broken or fabricated header.",
                        evidence=email.date,
                    ))
        except (TypeError, ValueError, OverflowError):
            signals.append(_sig(
                "HDR_BAD_DATE", "Malformed Date header", Severity.LOW,
                "The Date header could not be parsed as a valid timestamp, which points "
                "to a hand-assembled message rather than one produced by a mail client.",
                evidence=email.date[:120],
            ))
    else:
        signals.append(_sig(
            "HDR_NO_DATE", "Missing Date header", Severity.LOW,
            "No Date header. Mail clients always set one.",
        ))

    # ---- 8. delivery and priority tells ---------------------------------
    priority = email.headers.get("x-priority", "") or email.headers.get("importance", "")
    if priority and re.search(r"\b(1|high|urgent)\b", priority.lower()):
        signals.append(_sig(
            "HDR_HIGH_PRIORITY", "Flagged high priority", Severity.LOW,
            "The message sets a high-priority flag. Legitimate automated mail rarely "
            "does; it is a standard device for manufacturing urgency before the "
            "recipient has read a word.",
            evidence=priority[:120],
        ))

    mailer = email.headers.get("x-mailer", "")
    if mailer and re.search(r"(?i)(php|mass|bulk|sender|blast|smtplib|python|perl|curl)", mailer):
        signals.append(_sig(
            "HDR_SCRIPTED_MAILER", "Sent by a script rather than a mail client", Severity.MEDIUM,
            f"The X-Mailer header identifies '{mailer[:60]}', a scripting or bulk-sending "
            f"tool. Ordinary correspondence comes from a mail client; this is the "
            f"signature of automated sending infrastructure.",
            evidence=mailer[:200],
        ))

    to_field = (email.to or "").lower()
    if "undisclosed" in to_field or not to_field:
        signals.append(_sig(
            "HDR_HIDDEN_RECIPIENTS", "Recipients are hidden", Severity.LOW,
            "The To header is empty or reads 'undisclosed-recipients', meaning the real "
            "recipient list was in Bcc. Common in mass mailings, rare in genuine "
            "one-to-one correspondence.",
            evidence=email.to[:120] if email.to else "(empty)",
        ))

    # ---- 9. self-addressed spoof ----------------------------------------
    # Reasoning: "your account has been hacked, I emailed you from your own
    # address" sextortion relies on this, and so does internal-impersonation
    # fraud. It only works if SPF was not enforced.
    to_domain = domain_of(email.to.split(",")[0]) if email.to else ""
    if from_domain and to_domain and from_domain == to_domain:
        if auth.get("spf") in ("fail", "softfail", "none") or not email.auth_results:
            signals.append(_sig(
                "HDR_SELF_DOMAIN_SPOOF", "Claims to come from the recipient's own domain",
                Severity.HIGH,
                f"Sender and recipient are both on {from_domain}, but SPF did not confirm "
                f"the sending server. Impersonating an internal colleague — or the victim "
                f"themselves — is the basis of both business email compromise and "
                f"sextortion scams.",
                evidence=f"From: {email.from_address}  |  To: {email.to[:80]}",
            ))

    # ---- 9b. bulk mail declared by the sender ---------------------------
    # List-Unsubscribe and List-Id are how a sender declares "this is bulk".
    # Not a risk signal — genuine newsletters set them — but it is the single
    # most reliable marker of commercial mass mail, which is what separates
    # SPAM from a transactional message about an account you actually have.
    if email.headers.get("list-unsubscribe") or email.headers.get("list-id"):
        signals.append(_sig(
            "HDR_BULK_DECLARED", "Sender declares this as bulk mail", Severity.INFO,
            "Carries a List-Unsubscribe or List-Id header, which senders add to "
            "mass mailings. Legitimate for a newsletter; it marks the message as "
            "commercial bulk rather than correspondence about an existing account.",
            evidence=(email.headers.get("list-unsubscribe")
                      or email.headers.get("list-id", ""))[:150],
        ))

    # ---- 9c. hijacked reply thread --------------------------------------
    # Reasoning: an attacker who has read a real thread and continues it from
    # a lookalike domain is far more convincing than a cold approach — the
    # context is genuine. In-Reply-To and References point at the original
    # thread's domain, and that is the artefact the impersonation cannot fake.
    thread_refs = " ".join(filter(None, [
        email.headers.get("in-reply-to", ""), email.headers.get("references", "")
    ]))
    if thread_refs and from_domain:
        ref_domains = set()
        for match in re.finditer(r"@([A-Za-z0-9.\-]+)", thread_refs):
            ref = domain_of("x@" + match.group(1).strip(">. "))
            if ref:
                ref_domains.add(ref)
        foreign = {d for d in ref_domains if d != from_domain}
        if foreign and ref_domains:
            signals.append(_sig(
                "HDR_THREAD_DOMAIN_MISMATCH", "Continues a thread from a different domain",
                Severity.HIGH,
                f"The message references an existing conversation begun at "
                f"{', '.join(sorted(foreign)[:2])}, but is sent from {from_domain}. "
                f"An attacker who has obtained a real thread and resumes it from a "
                f"domain they control inherits all the trust the original built — "
                f"the context is genuine, only the sender has changed.",
                evidence=thread_refs[:200],
            ))

    # ---- 10. subject -----------------------------------------------------
    if not email.subject:
        signals.append(_sig(
            "HDR_NO_SUBJECT", "Empty subject line", Severity.LOW,
            "No subject. Used to slip past filters that key on subject text, and to "
            "provoke curiosity.",
        ))
    else:
        raw_subject = email.headers.get("subject", "")
        if raw_subject.count("=?") >= 3:
            signals.append(_sig(
                "HDR_OVER_ENCODED_SUBJECT", "Subject is heavily MIME-encoded", Severity.MEDIUM,
                f"The subject is split across {raw_subject.count('=?')} separate encoded "
                f"words. Encoding is normal for non-Latin text; fragmenting it this way is "
                f"a known technique for defeating keyword filters that do not decode first.",
                evidence=raw_subject[:200],
            ))
        if intel.has_mixed_scripts(email.subject):
            mixed = intel.has_mixed_scripts(email.subject)
            signals.append(_sig(
                "HDR_MIXED_SCRIPT_SUBJECT", "Subject mixes writing systems", Severity.MEDIUM,
                f"The subject line combines {mixed[0].title()} and {mixed[1].title()} "
                f"characters, a way of writing filter-triggering words so they read normally "
                f"to a human but do not match a keyword list.",
                evidence=email.subject[:150],
            ))

    return signals

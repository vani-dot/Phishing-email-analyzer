# content_check.py
# Signals derived from what the message says and how it is built.
#
# Reasoning model: headers and URLs expose the attacker's infrastructure;
# content exposes their METHOD. Phishing is a social engineering attack
# wearing a technical costume, and social engineering has a small, stable
# repertoire — manufacture urgency, invoke authority, threaten loss, demand
# secrecy, request an action that only benefits the attacker.
#
# Content evidence is weighted deliberately lower than header or URL evidence,
# because language is ambiguous: a real password-reset mail and a fake one say
# nearly the same words. What makes content decisive is CO-OCCURRENCE — urgency
# plus a credential request plus a threat is a script, not a coincidence, and
# scoring.py is where that combination is recognised.
#
# One check here is not about the human reader at all. PROMPT_INJECTION looks
# for text aimed at the language model that analyses this mail. An email that
# tries to instruct its own analyser is attacking the security control, and
# that is a finding in its own right.

import re
from typing import List, Tuple

import intel
from models import Category, ParsedEmail, Severity, Signal
from parser import domain_of

# Characters with no visual width, used to split keywords so that "pa<ZWSP>ssword"
# reads normally but matches no filter.
ZERO_WIDTH = "​‌‍⁠﻿᠎"
# Right-to-left override: turns "invoice[RLO]fdp.exe" into "invoiceexe.pdf"
# on screen while the file remains an executable.
BIDI_OVERRIDE = "‪‫‬‭‮⁦⁧⁨⁩"

CRYPTO_ADDRESS = re.compile(
    r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|"
    r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b"
)
# Phone numbers in the formats this project's users actually receive. The
# original pattern only matched US-style 3-3-4 numbers, so "+91 80 4471 2288"
# (an ordinary Indian landline written with a country code) was invisible and
# callback phishing sailed through. The look-behind/look-ahead stop it from
# matching a slice of a longer number such as a bank account or order id.
PHONE_NUMBER = re.compile(
    r"(?<![\w-])(?:"
    r"\+\d{1,3}[\s.-]?(?:\(\d{1,5}\)[\s.-]?)?\d{1,5}(?:[\s.-]?\d{2,5}){1,3}"  # +91 80 4471 2288
    r"|(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}"                          # 800-555-0199
    r"|1800[\s-]?\d{2,4}[\s-]?\d{3,4}"                                         # India toll-free
    r"|0\d{2,4}[\s-]\d{6,8}"                                                   # 080-44712288
    r"|[6-9]\d{9}"                                                              # Indian mobile
    r")(?!\w)"
)

# Payee bank details written into the body. Real invoices rarely spell out a
# full account in an email; "pay to this account instead" scams always do.
IFSC_CODE = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
BANK_ACCOUNT = re.compile(
    r"(?i)\b(?:a/?c|account)\s*(?:number|no\.?|#)\s*[:\-]?\s*(\d{9,18})\b"
    r"|\biban\s*[:\-]?\s*([A-Z]{2}\d{2}[A-Z0-9 ]{11,30})"
)

# Wallet recovery phrases. Nobody legitimate ever needs them, so a request is
# credential theft by definition. Negated warnings ("never share your seed
# phrase") are what genuine exchanges send, so those are excluded below.
SEED_PHRASE_ASK = re.compile(
    r"(?i)\b(enter|type|provide|submit|send|share|input|paste|reveal|read out|"
    r"confirm|verify|restore|import|supply)\b[^.\n]{0,60}?"
    r"(?:\b(?:seed|recovery|secret recovery|backup|mnemonic)\s+(?:phrase|words?)\b|"
    r"\b(?:12|24|twelve|twenty[- ]four)[- ]word\b)"
)
# Approving MFA prompts the reader did not start. This is MFA-fatigue: the
# attacker already has the password and needs the victim to tap "approve".
MFA_APPROVE_ASK = re.compile(
    r"(?i)\b(approve|accept|allow|confirm|tap)\b[^.\n]{0,40}?\b(all|every|each|any|them|both)\b"
    r"[^.\n]{0,25}?\b(prompt|notification|request|push|sign[- ]?in|login)s?\b"
    r"|\b(more than one|multiple|several|repeated)\s+(prompt|notification|push|request)s?\b"
    r"[^.\n]{0,40}?\b(approve|accept)\b"
)
_NEGATION = re.compile(r"(?i)\b(never|do not|don't|dont|will not|won't|should not|shouldn't|not)\b")


def _asked_for(pattern, text: str):
    """First match of an *ask* that is not negated in the words leading to it.

    "Never share your seed phrase" and "Enter your seed phrase" contain the
    same words; only one is an attack. Looking a few words back for a negation
    is what separates a warning from a request.
    """
    for m in pattern.finditer(text):
        lead = text[max(0, m.start() - 35): m.end()]
        if not _NEGATION.search(lead):
            return m
    return None


def _sig(code, title, severity, detail, evidence=None) -> Signal:
    return Signal(code=code, title=title, category=Category.CONTENT,
                  severity=severity, detail=detail, evidence=evidence)


def _find_phrases(text: str, phrases: List[str], limit: int = 6) -> List[str]:
    """Which phrases from a bank appear. Word-boundary matched, so 'urgent'
    does not fire on 'insurgent'."""
    found = []
    for phrase in phrases:
        if re.search(r"\b" + re.escape(phrase) + r"\b", text):
            found.append(phrase)
            if len(found) >= limit:
                break
    return found


def analyse_content(email: ParsedEmail, authenticated: bool = False) -> List[Signal]:
    signals: List[Signal] = []

    body = (email.body_text or "")[:120000]
    html = (email.body_html or "")[:120000]
    subject = email.subject or ""
    # Fold homoglyphs before matching, so a body written with Cyrillic
    # lookalikes is measured on what it says, not on how it is spelled.
    haystack = intel.deskeleton(subject + "\n" + body)
    sender_domain = domain_of(email.from_address)

    # ---- 1. attack on the analyser itself -------------------------------
    # Checked first because it changes how everything after it is read.
    injections = intel.find_injection_attempts(subject + "\n" + body + "\n" + html)
    if injections:
        signals.append(_sig(
            "CNT_PROMPT_INJECTION", "Message contains instructions aimed at an AI analyser",
            Severity.CRITICAL,
            f"The body contains text written to be read as instructions by a language "
            f"model rather than as prose by a person — {len(injections)} such passage"
            f"{'s' if len(injections) > 1 else ''} found. Legitimate correspondence never "
            f"addresses the software inspecting it. This is a deliberate attempt to "
            f"manipulate the verdict, and is treated as strong evidence of malicious "
            f"intent rather than as a reason to trust the message.",
            evidence=injections[0][:300],
        ))

    # ---- 2. social engineering repertoire -------------------------------
    tactic_hits: List[Tuple[str, List[str]]] = []

    urgency = _find_phrases(haystack, intel.URGENCY_PHRASES)
    if urgency:
        tactic_hits.append(("urgency", urgency))
        signals.append(_sig(
            "CNT_URGENCY", "Manufactured time pressure", Severity.MEDIUM,
            f"Uses {len(urgency)} urgency device(s). Deadlines exist to stop the reader "
            f"verifying through a second channel — the entire attack depends on them "
            f"acting before they think.",
            evidence=", ".join(urgency[:5]),
        ))

    threats = _find_phrases(haystack, intel.THREAT_PHRASES)
    if threats:
        tactic_hits.append(("threat", threats))
        signals.append(_sig(
            "CNT_THREAT", "Threat of loss or account action", Severity.MEDIUM,
            f"Warns of suspension, closure or a security problem ({len(threats)} phrase(s)). "
            f"Loss aversion reliably outperforms reward as a motivator, which is why the "
            f"majority of credential phishing opens with a threat rather than an offer.",
            evidence=", ".join(threats[:5]),
        ))

    credentials = _find_phrases(haystack, intel.CREDENTIAL_PHRASES)
    if credentials:
        tactic_hits.append(("credential request", credentials))
        signals.append(_sig(
            "CNT_CREDENTIAL_REQUEST", "Asks the reader to verify or update credentials",
            Severity.HIGH,
            f"Directly requests a login, identity confirmation or payment-detail update "
            f"({len(credentials)} phrase(s)). This is the payload of the message — the "
            f"action everything else was constructed to produce.",
            evidence=", ".join(credentials[:5]),
        ))

    lure = _find_phrases(haystack, intel.FINANCIAL_LURE_PHRASES)
    if lure:
        tactic_hits.append(("financial lure", lure))
        signals.append(_sig(
            "CNT_FINANCIAL_LURE", "Offers money, refunds or winnings", Severity.MEDIUM,
            f"Promises an unearned financial gain ({len(lure)} phrase(s)) — the advance-fee "
            f"pattern, where a small action now unlocks a large payout that never arrives.",
            evidence=", ".join(lure[:5]),
        ))

    secrecy = _find_phrases(haystack, intel.SECRECY_PHRASES)
    if secrecy:
        tactic_hits.append(("secrecy", secrecy))
        signals.append(_sig(
            "CNT_SECRECY", "Requests confidentiality", Severity.HIGH,
            f"Asks the reader not to discuss the message with anyone. This exists solely "
            f"to prevent the one action that reliably defeats the attack — asking a "
            f"colleague. It is a hallmark of business email compromise.",
            evidence=", ".join(secrecy[:4]),
        ))

    greeting = _find_phrases(haystack, intel.GENERIC_GREETINGS, limit=3)
    if greeting:
        signals.append(_sig(
            "CNT_GENERIC_GREETING", "Impersonal greeting", Severity.LOW,
            f"Opens with '{greeting[0]}' rather than a name. An organisation that genuinely "
            f"holds your account knows what to call you; a bulk sender working from a "
            f"harvested address list does not.",
            evidence=greeting[0],
        ))

    # ---- 2b. business email compromise ----------------------------------
    # Reasoning: BEC defeats every technical control in this analyser. The
    # sender is a real, fully authenticated mailbox — usually a genuine Gmail
    # account — so SPF, DKIM and DMARC all pass honestly. There is no link to
    # inspect and no attachment to hash. What is left is the claim of
    # authority and the nature of the request, and those are what these checks
    # read. It is the costliest email attack in existence precisely because
    # there is nothing technical to catch.

    display_lower = (email.from_display or "").lower()
    claimed_title = next(
        (t for t in intel.EXECUTIVE_TITLES
         if re.search(r"\b" + re.escape(t) + r"\b", display_lower)), None
    )
    sender_is_freemail = sender_domain in intel.FREE_MAIL_PROVIDERS

    payments = _find_phrases(haystack, intel.PAYMENT_INSTRUCTION_PHRASES)
    # Payee details spelled out in the body (IFSC / account number / IBAN).
    if IFSC_CODE.search(body) or BANK_ACCOUNT.search(body):
        payments.append("bank account details in body")
    isolation = _find_phrases(haystack, intel.CHANNEL_ISOLATION_PHRASES, limit=4)

    claimed_department = next(
        (d for d in intel.DEPARTMENT_NAMES
         if re.search(r"\b" + re.escape(d) + r"\b", display_lower)), None
    )

    if claimed_department and sender_is_freemail and email.headers_present and not claimed_title:
        # Reasoning: "Acme HR" or "Payroll Department" claims authority over a
        # process without naming a person anyone could ring to check. An
        # internal function does not correspond from a consumer mailbox, and
        # this catches the payroll-diversion shape independently of whether the
        # language model spots it — which makes the detection robust rather
        # than dependent on one layer.
        signals.append(_sig(
            "CNT_DEPARTMENT_FREEMAIL", "Claims an internal department from a personal account",
            Severity.CRITICAL,
            f"The sender presents as '{email.from_display[:60]}' — speaking for "
            f"{claimed_department.upper()} — while writing from {sender_domain}, a free "
            f"consumer mail provider. Internal functions correspond from the "
            f"organisation's own domain. Note that such a message authenticates "
            f"perfectly: the mailbox is real, it simply is not the department.",
            evidence=f"Display: {email.from_display[:80]}  |  From: {email.from_address}",
        ))

    if claimed_title and sender_is_freemail and email.headers_present:
        signals.append(_sig(
            "CNT_EXECUTIVE_FREEMAIL", f"Claims executive authority from a personal mail account",
            Severity.CRITICAL,
            f"The sender presents as '{email.from_display[:60]}' — a {claimed_title.upper()} — "
            f"while writing from {sender_domain}, a free consumer mail provider. Executives "
            f"issue instructions from their corporate mailbox. A personal account carrying a "
            f"job title is the opening move of business email compromise: the authority is "
            f"asserted in the display name because it cannot be proved by the address.",
            evidence=f"Display: {email.from_display[:80]}  |  From: {email.from_address}",
        ))
    elif claimed_title and email.headers_present:
        tactic_hits.append(("authority claim", [claimed_title]))
        signals.append(_sig(
            "CNT_AUTHORITY_CLAIM", "Sender asserts a position of authority", Severity.LOW,
            f"The display name asserts the role of {claimed_title.upper()}. Legitimate in "
            f"internal mail; it is also how an attacker manufactures the reluctance to "
            f"question an unusual request.",
            evidence=email.from_display[:120],
        ))

    if payments:
        tactic_hits.append(("payment instruction", payments))
        signals.append(_sig(
            "CNT_PAYMENT_INSTRUCTION", "Instructs the reader to move money", Severity.HIGH,
            f"Requests a transfer, payment or change of banking details "
            f"({len(payments)} phrase(s) found). Unlike an offer of money, this asks the "
            f"recipient to send it — the direction that costs the victim directly and, "
            f"once a wire clears, usually irreversibly.",
            evidence=", ".join(payments[:5]),
        ))

    if isolation:
        tactic_hits.append(("channel isolation", isolation))
        signals.append(_sig(
            "CNT_CHANNEL_ISOLATION", "Claims to be unreachable by any other means",
            Severity.HIGH,
            f"States the sender cannot be contacted except by replying to this message "
            f"({', '.join(isolation[:3])}). This pre-empts the one action that reliably "
            f"defeats impersonation — a thirty-second phone call to the person being "
            f"impersonated — and it is stated up front precisely because the attacker "
            f"cannot survive that call.",
            evidence=", ".join(isolation[:4]),
        ))

    if re.search(r"(?i)\b(gift\s?cards?|itunes\s?cards?|steam\s?cards?|google\s?play\s?cards?)\b", haystack):
        signals.append(_sig(
            "CNT_GIFT_CARD_REQUEST", "Asks for gift cards", Severity.CRITICAL,
            "Requests payment in gift cards. No organisation settles an obligation this "
            "way. Gift card codes are untraceable, instantly resold, and impossible to "
            "reverse — which is the entire reason they are asked for.",
            evidence=body[:200],
        ))

    # MENTIONING a brand is not IMPERSONATING it. An SEO agency writing "we
    # will get you ranking on Google", or a survey offering "a £100 Amazon
    # voucher", refers to those companies without claiming to be them. The
    # earlier version fired on any brand word anywhere in the body, which
    # turned ordinary commercial mail into brand impersonation and — because
    # impersonation is a theft vector — pushed plain spam toward PHISHING.
    #
    # Impersonation means the sender PRESENTS AS the brand. That shows up
    # structurally in one of three places, all of which an attacker must use
    # for the deception to work on a reader:
    #   * the display name            "PayPal Security" <x@evil.tk>
    #   * the sending domain           paypal-secure.tk
    #   * a link domain resembling it  paypal.com.verify.top
    # Prose alone does not qualify.
    mentioned = intel.brands_mentioned(subject + " " + body)
    if mentioned and sender_domain and email.headers_present:
        display_folded = intel.deskeleton(email.from_display or "")
        sender_folded = intel.deskeleton(sender_domain)
        link_domains = [l.registered_domain for l in email.links if l.registered_domain]

        impersonated = []
        for brand in mentioned:
            if sender_domain in intel.BRAND_DOMAINS.get(brand, []):
                continue                      # it really is them
            presents_as = (
                re.search(r"\b" + re.escape(brand) + r"\b", display_folded)
                or brand in sender_folded
                or any(brand in intel.deskeleton(d) for d in link_domains)
                or any((intel.lookalike_brand(d) or (None,))[0] == brand
                       for d in link_domains)
            )
            if presents_as:
                impersonated.append(brand)

        if impersonated:
            brand = impersonated[0]
            where = ("the display name" if re.search(r"\b" + re.escape(brand) + r"\b", display_folded)
                     else "the sending domain" if brand in sender_folded
                     else "a link destination")
            signals.append(_sig(
                "CNT_BRAND_IMPERSONATION", f"Presents as {brand.title()} but is not",
                Severity.HIGH,
                f"The message puts '{brand}' in {where} while originating from "
                f"'{sender_domain}', which is not a {brand.title()} sending domain. This "
                f"is the sender claiming to BE {brand.title()}, not merely referring to "
                f"them — brand authority is being borrowed to make the request feel routine.",
                evidence=f"{brand} in {where}  |  From: {sender_domain}",
            ))

    # ---- 4. structural evasion ------------------------------------------
    zero_width_count = sum(body.count(ch) + subject.count(ch) for ch in ZERO_WIDTH)
    if zero_width_count >= 3:
        signals.append(_sig(
            "CNT_ZERO_WIDTH", "Invisible characters inserted into the text", Severity.HIGH,
            f"{zero_width_count} zero-width characters found. These are invisible to the "
            f"reader but break keyword matching — 'pa<hidden>ssword' looks normal and "
            f"matches nothing. Their only purpose is filter evasion.",
            evidence=f"{zero_width_count} zero-width code points",
        ))

    bidi_count = sum(body.count(ch) + subject.count(ch) for ch in BIDI_OVERRIDE)
    if bidi_count:
        signals.append(_sig(
            "CNT_BIDI_OVERRIDE", "Text-direction override characters present", Severity.HIGH,
            f"{bidi_count} bidirectional override character(s). These reverse how text "
            f"renders, which is how 'invoice‮gpj.exe' displays as a harmless image name "
            f"while remaining an executable.",
            evidence=f"{bidi_count} bidi control characters",
        ))

    mixed = intel.has_mixed_scripts(body[:4000])
    if mixed and mixed[0] != "LATIN" or (mixed and mixed[1] != "LATIN"):
        if mixed:
            signals.append(_sig(
                "CNT_MIXED_SCRIPT_BODY", "Body mixes writing systems", Severity.MEDIUM,
                f"The text combines {mixed[0].title()} and {mixed[1].title()} characters. "
                f"Legitimate in genuinely multilingual mail; also the standard way to write "
                f"a trigger word so it reads normally but matches no filter.",
                evidence=body[:150],
            ))

    if html:
        # Hidden content: real text the reader never sees, present to dilute
        # spam scoring or to hide the actual payload.
        hidden = re.findall(
            r"(?i)(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|"
            r"color\s*:\s*#?(fff(fff)?|white)\b[^;]{0,40};?[^>]{0,80}background[^>]{0,40}(fff|white))",
            html,
        )
        if len(hidden) >= 2:
            signals.append(_sig(
                "CNT_HIDDEN_TEXT", "Hidden text in the HTML body", Severity.MEDIUM,
                f"{len(hidden)} element(s) are styled to be invisible — zero font size, "
                f"display:none, or white text on white. Content the reader cannot see but "
                f"a filter can is there to skew automated scoring.",
                evidence=str(hidden[0])[:150],
            ))

        if re.search(r"(?i)<\s*script[\s>]", html):
            signals.append(_sig(
                "CNT_SCRIPT_TAG", "HTML body contains script tags", Severity.HIGH,
                "The message embeds JavaScript. Mail clients block it, so its presence "
                "indicates content built for a browser — typically a phishing page pasted "
                "wholesale into the email, or an attempt at a client vulnerability.",
                evidence=re.search(r"(?i)<\s*script[^>]{0,120}>", html).group(0)[:150],
            ))

        if re.search(r"(?i)<\s*form[\s>]", html):
            signals.append(_sig(
                "CNT_EMBEDDED_FORM", "Login form embedded in the email", Severity.CRITICAL,
                "The body contains an HTML form. A message that asks for input inside the "
                "mail itself is harvesting directly — the reader never leaves what looks "
                "like their inbox, so none of the usual browser warnings apply.",
                evidence=re.search(r"(?i)<\s*form[^>]{0,200}>", html).group(0)[:200],
            ))

        if re.search(r"(?i)<\s*iframe[\s>]", html):
            signals.append(_sig(
                "CNT_IFRAME", "HTML body contains an iframe", Severity.HIGH,
                "An embedded frame pulls in content from elsewhere at render time, keeping "
                "the malicious portion out of the message that gateways scan.",
                evidence=re.search(r"(?i)<\s*iframe[^>]{0,150}>", html).group(0)[:150],
            ))

        # Image-only body: no text for any analyser to read, by design.
        text_len = len(re.sub(r"\s+", "", body))
        images = len(re.findall(r"(?i)<\s*img\b", html))
        if images >= 1 and text_len < 120:
            signals.append(_sig(
                "CNT_IMAGE_ONLY", "Message body is essentially one image", Severity.MEDIUM,
                f"{images} image(s) and only {text_len} characters of text. Rendering the "
                f"message as a picture defeats every text-based filter while looking "
                f"completely normal to the recipient.",
                evidence=f"{images} images, {text_len} chars of text",
            ))

        pixels = re.findall(r'(?i)<img[^>]{0,300}(?:width|height)\s*=\s*["\']?[01]["\']?[^>]{0,200}>', html)
        if pixels:
            signals.append(_sig(
                "CNT_TRACKING_PIXEL", "Tracking pixel present", Severity.LOW,
                f"{len(pixels)} image(s) sized 1x1. These confirm to the sender that the "
                f"address is live and the message was opened, which is how a harvested "
                f"list gets validated for the next campaign.",
                evidence=pixels[0][:150],
            ))

    # ---- 5. out-of-band contact ------------------------------------------
    crypto = CRYPTO_ADDRESS.findall(body)
    if crypto:
        signals.append(_sig(
            "CNT_CRYPTO_ADDRESS", "Cryptocurrency wallet address in the body", Severity.HIGH,
            f"Contains {len(crypto)} wallet address(es). A payment route that is "
            f"irreversible and effectively anonymous has no place in legitimate billing, "
            f"and is the standard demand in extortion and fake-invoice fraud.",
            evidence=str(crypto[0])[:100],
        ))

    seed = _asked_for(SEED_PHRASE_ASK, body)
    if seed:
        signals.append(_sig(
            "CNT_SEED_PHRASE_REQUEST", "Asks for a wallet recovery phrase", Severity.CRITICAL,
            "The message asks the reader to enter or share a wallet recovery (seed) phrase. "
            "That phrase is the wallet: whoever holds it can move every asset, permanently. "
            "No genuine wallet maker, exchange or support team ever needs it, so a request "
            "for it is theft regardless of how the message is dressed up.",
            evidence=body[max(0, seed.start() - 20): seed.end() + 30][:200],
        ))

    mfa = _asked_for(MFA_APPROVE_ASK, body)
    if mfa:
        signals.append(_sig(
            "CNT_MFA_APPROVAL_LURE", "Tells the reader to approve MFA prompts", Severity.HIGH,
            "The message tells the reader to approve sign-in prompts, or several of them. "
            "That is MFA fatigue: the attacker already has the password and is triggering "
            "the prompts themselves. A real IT team never asks anyone to approve a push "
            "notification they did not start.",
            evidence=body[max(0, mfa.start() - 20): mfa.end() + 30][:200],
        ))

    # Callback phishing: no link, no attachment, just a number to ring, which
    # moves the attack to a channel no mail gateway can inspect.
    if not email.links and not email.attachments:
        phones = PHONE_NUMBER.findall(body)
        if phones and any(w in haystack for w in
                          ("call", "phone", "contact us", "support", "representative", "helpdesk",
                           "helpline", "toll free", "toll-free")):
            signals.append(_sig(
                "CNT_CALLBACK_PHISH", "Directs the reader to phone a number", Severity.HIGH,
                "The message carries no links or attachments but urges the reader to call. "
                "This is callback phishing: with nothing for a mail gateway to scan, the "
                "attack succeeds by moving the victim to a phone call where a person talks "
                "them through installing remote access or reading out a code.",
                evidence=body[max(0, body.find(phones[0]) - 60): body.find(phones[0]) + 60][:200],
            ))

    # Tightened deliberately. The previous pattern allowed 60 characters of
    # anything between the verb and the secret, which let it match across a
    # sentence boundary: "...ignore this email - your password will not change"
    # in a legitimate Atlassian reset became a CRITICAL finding. Now the verb
    # must actually govern the secret (optionally via "with"/"us"/"me"), the
    # span is short, and negated or reassuring constructions are excluded.
    reply_secret = re.search(
        r"(?i)\b(reply|respond|send|forward|provide|confirm)\b"
        r"(?:\s+(?:to\s+)?(?:us|me|this|back|with|your|the)){0,3}\s{0,3}"
        r"[^.\n;]{0,28}?\b(password|otp|one[- ]time\s+(?:code|pin|password)|"
        r"\bpin\b|card number|cvv|ssn|social security|account number|credentials)\b",
        haystack)
    if reply_secret and not re.search(
            r"(?i)\b(will not|won't|never|do not|don't|did not|didn't|no need to|"
            r"we will never|nobody will)\b[^.\n]{0,40}\b(ask|request|send|reply)",
            haystack):
        signals.append(_sig(
            "CNT_REPLY_WITH_SECRET", "Asks for a secret to be sent by reply", Severity.CRITICAL,
            "The message asks the reader to send a password, one-time code, card number or "
            "similar by return mail. No legitimate organisation asks for this in any "
            "channel, and an OTP requested by a third party is the final step of an "
            "account takeover already in progress.",
            evidence=reply_secret.group(0)[:200],
        ))

    # ---- 6. attachment lure without an attachment -----------------------
    if not email.attachments and re.search(
            r"(?i)\b(see|find|please review|attached|enclosed)\b[^.\n]{0,40}"
            r"\b(attach(ed|ment)|invoice|document|statement|receipt|purchase order)\b", haystack):
        signals.append(_sig(
            "CNT_PHANTOM_ATTACHMENT", "Refers to an attachment that is not present",
            Severity.MEDIUM,
            "The text points at an attached document, but the message carries none. The "
            "'attachment' is normally a link styled to look like a file preview — a way to "
            "get a click while the mail itself stays clean for scanners.",
            evidence=body[:200],
        ))

    # ---- 6b. commercial solicitation ------------------------------------
    # A spam MARKER, not a risk signal. This answers "what is this message",
    # not "is it dangerous" — a cold sales email is spam at a risk score of 5,
    # and without this the analyser can only call something spam once it is
    # also alarming, which is the wrong test.
    promo = _find_phrases(haystack, intel.PROMOTIONAL_PHRASES, limit=8)
    if len(promo) >= 2:
        signals.append(_sig(
            "CNT_PROMOTIONAL", "Unsolicited commercial solicitation", Severity.INFO,
            f"Uses {len(promo)} selling phrase(s) — the message exists to promote a "
            f"product, service or meeting rather than to address an account or "
            f"conversation the recipient already has. This marks it as commercial "
            f"bulk mail; it carries no risk weight of its own.",
            evidence=", ".join(promo[:6]),
        ))

    # ---- 7. presentation quality ----------------------------------------
    letters = [c for c in body[:3000] if c.isalpha()]
    if len(letters) > 200:
        caps_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
        if caps_ratio > 0.45:
            signals.append(_sig(
                "CNT_EXCESSIVE_CAPS", "Body is largely capitalised", Severity.LOW,
                f"{caps_ratio:.0%} of letters are uppercase. Shouting is a crude urgency "
                f"device and is strongly associated with bulk unsolicited mail.",
                evidence=body[:120],
            ))

    if subject and len(subject) > 8:
        excl = subject.count("!")
        if excl >= 3:
            signals.append(_sig(
                "CNT_SUBJECT_PUNCTUATION", "Subject uses heavy punctuation", Severity.LOW,
                f"{excl} exclamation marks in the subject line — a bulk-mail characteristic "
                f"and an attempt to draw the eye in a crowded inbox.",
                evidence=subject[:120],
            ))

    # ---- 8. tactic stacking ---------------------------------------------
    # The judgement that matters: individually these are weak, together they
    # are a script. Three or more distinct tactics in one short message is not
    # how ordinary correspondence is written.
    if len(tactic_hits) >= 3:
        names = ", ".join(name for name, _ in tactic_hits)
        signals.append(_sig(
            "CNT_TACTIC_STACK", f"{len(tactic_hits)} social engineering tactics combined",
            Severity.HIGH,
            f"The message layers {names} in a single short mail. Any one of these appears "
            f"in legitimate correspondence; their combination is a recognisable persuasion "
            f"script, and the stacking is what distinguishes an attack from a badly worded "
            f"genuine notice.",
            evidence=names,
        ))

    return signals

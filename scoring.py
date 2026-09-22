# scoring.py
# Evidence -> score -> verdict, deterministically.
#
# A phishing analyser that just adds up keyword hits produces two failures that
# make it useless in practice: it flags every legitimate password-reset mail,
# and it can be defeated by removing one word. Four ideas prevent that here.
#
# 1. DIMINISHING RETURNS WITHIN A CATEGORY
#    Ten low-severity URL findings are not worth more than two critical header
#    findings. The Nth signal in a category counts for progressively less, so a
#    message cannot be pushed over a threshold by repetition of a weak tell —
#    breadth of evidence has to come from DIFFERENT kinds of evidence.
#
# 2. CORRELATION, NOT ADDITION
#    The reasoning that matters is conditional. "Asks for credentials" is
#    nearly meaningless alone — so does every real password reset. "Asks for
#    credentials AND the sender failed SPF AND the link is a lookalike domain"
#    is a complete attack, and is worth more than its three parts summed. These
#    combinations are named explicitly below and each one states its logic.
#
# 3. TRUST CREDITS
#    Genuine mail must be able to prove itself, not merely fail to trip
#    anything. Passing authentication from a domain that matches the sender,
#    with links that stay on that domain, is positive evidence and subtracts
#    from the score. Without this, every automated notification lands in
#    SUSPICIOUS and the tool gets ignored — which is how real security tools
#    actually fail.
#
# 4. SEPARATING SPAM FROM PHISHING
#    Both are unwanted; only one is trying to steal from you. The distinction
#    is intent: phishing seeks credentials, money or execution through
#    deception about identity. Spam sells something. A single score cannot
#    express that, so the verdict is chosen from the SHAPE of the evidence.

import re
from typing import Dict, List, Tuple

import intel
from parser import dkim_alignment
from models import (Category, ParsedEmail, Report, ScoreBreakdown, Severity,
                    Signal, Verdict)

# How much the Nth-strongest signal in one category still counts. A message
# with six URL findings gets 1.0+0.7+0.5+0.35+0.25+0.15 of their weights, not
# six full weights.
DECAY = [1.0, 0.7, 0.5, 0.35, 0.25, 0.15]
DECAY_TAIL = 0.1

# Verdict thresholds on the 0-100 scale.
# Score bands. The label comes from these and the theft gate, nowhere else.
THRESHOLD_PHISHING = 75      # 75-100, and only with a theft vector present
THRESHOLD_SUSPICIOUS = 50    # 50-74
THRESHOLD_SPAM = 25          # 25-49; below this is GENUINE


# Urgency is the largest single source of false positives in real deployments,
# because legitimate transactional security mail is inherently urgent — a
# password reset that expires in 60 minutes says so, loudly. These signals are
# therefore capped as a GROUP rather than trusted individually, and the cap is
# halved when the sender is cryptographically authenticated.
URGENCY_GROUP_CODES = {
    "CNT_URGENCY", "CNT_THREAT", "CNT_SUBJECT_PUNCTUATION",
    "CNT_EXCESSIVE_CAPS", "HDR_HIGH_PRIORITY",
}
URGENCY_CAP = 15
URGENCY_CAP_AUTHENTICATED = 7


def _apply_urgency_cap(signals: List[Signal], authenticated: bool) -> int:
    """How many points to remove so urgency cannot carry a verdict alone."""
    total = _decayed_total([s for s in signals if s.code in URGENCY_GROUP_CODES])
    cap = URGENCY_CAP_AUTHENTICATED if authenticated else URGENCY_CAP
    return max(0, total - cap)


def _decayed_total(signals: List[Signal]) -> int:
    """Sum a category's points with diminishing returns."""
    points = sorted((s.points for s in signals), reverse=True)
    total = 0.0
    for index, value in enumerate(points):
        weight = DECAY[index] if index < len(DECAY) else DECAY_TAIL
        total += value * weight
    return int(round(total))


# ---------------------------------------------------------------------------
# Correlation rules
# ---------------------------------------------------------------------------
# Each entry: (name, required signal codes, bonus points, the reasoning).
# A rule fires only when EVERY code in its set is present. The reasoning text
# is shown to the analyst — a bonus the tool cannot justify is a bonus it
# should not apply.

CORRELATIONS: List[Tuple[str, set, int, str]] = [
    (
        "Authenticated spoof with a harvesting destination",
        {"AUTH_SPF_FAIL", "URL_LOOKALIKE_DOMAIN"}, 18,
        "The sending server failed SPF for the domain it claims, and the message "
        "links to a domain built to look like a brand. Failed authentication "
        "establishes the sender is not who they say; the lookalike link "
        "establishes where the credentials are meant to go. Together these are "
        "the two halves of a complete credential-harvesting operation.",
    ),
    (
        "Impersonation with a credential request",
        {"HDR_BRAND_FROM_FREEMAIL", "CNT_CREDENTIAL_REQUEST"}, 20,
        "A message claiming to be a major brand, sent from free consumer webmail, "
        "asking the reader to verify an account. Each element is damning on its "
        "own; in combination there is no innocent reading.",
    ),
    (
        "Deceptive link plus login destination",
        {"URL_DISPLAY_MISMATCH", "URL_CREDENTIAL_PATH"}, 15,
        "The message displays one domain, opens another, and that destination is a "
        "sign-in page. Mislabelling a link is deception; mislabelling it toward a "
        "login form identifies what the deception is for.",
    ),
    (
        "Urgency driving a credential request",
        {"CNT_URGENCY", "CNT_CREDENTIAL_REQUEST"}, 10,
        "A deadline attached to a request for account verification. The time "
        "pressure exists to stop the reader checking with the organisation "
        "through a channel the attacker does not control.",
    ),
    (
        "Threat, urgency and a login link",
        {"CNT_THREAT", "CNT_URGENCY", "URL_CREDENTIAL_PATH"}, 14,
        "Account-loss threat, a deadline, and a link to a sign-in page — the "
        "standard three-beat structure of credential phishing, in order.",
    ),
    (
        "Spoofed sender carrying an executable",
        {"AUTH_SPF_FAIL", "ATT_EXECUTABLE"}, 22,
        "A message that failed sender authentication is delivering a file that "
        "runs code. This is malware distribution under a forged identity, not a "
        "phishing attempt — the payload arrived with the mail.",
    ),
    (
        "Disguised executable with social pressure",
        {"ATT_DOUBLE_EXTENSION", "CNT_URGENCY"}, 16,
        "An attachment disguised to look like a document, combined with pressure "
        "to open it promptly. The disguise and the urgency serve the same goal: "
        "a double-click before inspection.",
    ),
    (
        "Macro document with an enabling instruction",
        {"ATT_MACRO_DOCUMENT", "CNT_URGENCY"}, 12,
        "A macro-enabled document delivered with urgency. Macro payloads need the "
        "recipient to click through a security warning, and manufactured urgency "
        "is how that consent is obtained.",
    ),
    (
        "Reply-path diversion with impersonation",
        {"HDR_REPLY_TO_MISMATCH", "CNT_BRAND_IMPERSONATION"}, 14,
        "The message impersonates a brand while directing replies to an unrelated "
        "domain. The impersonation wins the reader's trust; the diverted reply "
        "path is how the resulting conversation reaches the attacker.",
    ),
    (
        "Executive impersonation directing a payment",
        {"CNT_EXECUTIVE_FREEMAIL", "CNT_PAYMENT_INSTRUCTION"}, 26,
        "Someone claiming executive authority, writing from a personal mail "
        "account, instructing the recipient to move money. This is business "
        "email compromise in its canonical form. Note that such a message "
        "passes SPF, DKIM and DMARC honestly — the account is real, it simply "
        "is not the executive's. No technical control catches this; only the "
        "mismatch between asserted authority and actual mailbox does.",
    ),
    (
        "Payment request shielded from verification",
        {"CNT_PAYMENT_INSTRUCTION", "CNT_CHANNEL_ISOLATION"}, 20,
        "A request to move money, accompanied by a claim that the sender cannot "
        "be reached any other way. The isolation is the tell: a genuine "
        "executive has no reason to foreclose a phone call, and an impersonator "
        "cannot survive one.",
    ),
    (
        "Gift card demand under claimed authority",
        {"CNT_GIFT_CARD_REQUEST", "CNT_AUTHORITY_CLAIM"}, 24,
        "A person asserting seniority is asking for payment in gift cards. There "
        "is no legitimate version of this request — it exists only because the "
        "proceeds are untraceable and irreversible.",
    ),
    (
        "Business email compromise pattern",
        {"CNT_SECRECY", "CNT_URGENCY"}, 16,
        "A request for confidentiality combined with time pressure. This pairing "
        "is the signature of business email compromise: secrecy removes the "
        "colleague who would notice, urgency removes the pause in which the "
        "target would think.",
    ),
    (
        "Harvesting form inside a spoofed message",
        {"CNT_EMBEDDED_FORM", "AUTH_SPF_FAIL"}, 20,
        "An unauthenticated sender has embedded an input form directly in the "
        "message. Credentials typed there never reach a browser, so no address "
        "bar, certificate warning or password manager can intervene.",
    ),
    (
        "Analyser manipulation alongside a real attack",
        {"CNT_PROMPT_INJECTION", "CNT_CREDENTIAL_REQUEST"}, 18,
        "The message both solicits credentials and contains text written to "
        "manipulate an automated analyser into clearing it. Attempting to disarm "
        "the security control is conclusive evidence of intent — no legitimate "
        "sender has any reason to address the software reading their mail.",
    ),
    (
        "Self-spoof with a payload",
        {"HDR_SELF_DOMAIN_SPOOF", "CNT_THREAT"}, 14,
        "Mail forged to appear internal, carrying a threat. Extortion scams rely "
        "on the victim believing a message from their own address proves account "
        "compromise; it proves only that SPF was not enforced.",
    ),
    (
        "Lookalike sender with a lookalike link",
        {"HDR_LOOKALIKE_DOMAIN", "URL_LOOKALIKE_DOMAIN"}, 16,
        "Both the sending domain and the link domain imitate a real brand. That is "
        "registered infrastructure prepared in advance — a campaign, not an "
        "opportunistic message.",
    ),
]

# ---------------------------------------------------------------------------
# Theft vectors — the gate on the PHISHING label
# ---------------------------------------------------------------------------
# Phishing is theft by deception about identity. Spam is unwanted selling.
# The difference is INTENT, and intent shows up as one of four concrete asks.
#
# Note what is deliberately NOT here: failed SPF, absent DKIM, failed DMARC, a
# disreputable TLD, bulk-mailer headers. Those were previously treated as
# phishing intent, which meant a pharmacy spammer with a broken mail setup got
# labelled a phishing attack. Bad hygiene is bad hygiene. It raises the score;
# it does not change what the message is trying to do.

THEFT_VECTOR_CODES: Dict[str, set] = {
    "credential_request": {
        "CNT_CREDENTIAL_REQUEST", "CNT_REPLY_WITH_SECRET", "CNT_EMBEDDED_FORM",
        "URL_PLAINTEXT_LOGIN", "CNT_CALLBACK_PHISH",
        # Asking for a wallet recovery phrase, or for the reader to approve
        # MFA prompts they did not start, are credential theft with no
        # "password" in sight, so the older patterns never saw them.
        "CNT_SEED_PHRASE_REQUEST", "CNT_MFA_APPROVAL_LURE",
    },
    "brand_impersonation": {
        "HDR_LOOKALIKE_DOMAIN", "URL_LOOKALIKE_DOMAIN", "HDR_BRAND_FROM_FREEMAIL",
        "HDR_BRAND_DOMAIN_MISMATCH", "CNT_BRAND_IMPERSONATION", "URL_BRAND_IN_SUBDOMAIN",
        "HDR_DISPLAY_NAME_SPOOF", "HDR_MIXED_SCRIPT_DOMAIN", "URL_MIXED_SCRIPT",
        "URL_PUNYCODE", "HDR_PUNYCODE_DOMAIN", "URL_USERINFO_TRICK",
        "URL_DISPLAY_MISMATCH", "CNT_EXECUTIVE_FREEMAIL", "HDR_SELF_DOMAIN_SPOOF",
        "CNT_DEPARTMENT_FREEMAIL", "HDR_THREAD_DOMAIN_MISMATCH",
    },
    "payment_redirection": {
        "CNT_PAYMENT_INSTRUCTION", "CNT_GIFT_CARD_REQUEST", "CNT_CRYPTO_ADDRESS",
    },
    "harvesting_attachment": {
        "ATT_HTML_ATTACHMENT", "ATT_MACRO_DOCUMENT", "ATT_EXECUTABLE",
        "ATT_HIDDEN_EXECUTABLE", "ATT_DOUBLE_EXTENSION", "ATT_DISK_IMAGE",
        "ATT_SHORTCUT", "ATT_RLO_FILENAME", "ATT_TYPE_MISMATCH",
    },
}


def credential_destination_trusted(email: ParsedEmail, authenticated: bool) -> bool:
    """Does the credential request point back at the sender's own property?

    A legitimate password reset asks you to reset your password — the words are
    identical to the attack. What separates them is WHERE the link goes.
    Atlassian mailing you a link to id.atlassian.com, signed by atlassian.com,
    is the genuine article; the same words pointing at a domain the sender does
    not own is the attack.
    """
    from parser import domain_of

    if not authenticated:
        return False
    from_domain = domain_of(email.from_address)
    if not from_domain:
        return False
    claimed = set(intel.brands_mentioned((email.subject or "") + " " + (email.body_text or "")[:4000]))
    permitted = {from_domain}
    for brand in claimed:
        permitted |= set(intel.BRAND_DOMAINS.get(brand, []))
    for link in email.links:
        if not link.registered_domain:
            continue
        if link.registered_domain in permitted:
            continue
        if intel.is_tracking_wrapper(link.domain):
            continue
        return False
    return True


def detect_theft_vectors(codes: set, credential_dest_trusted: bool = False) -> List[str]:
    """Which theft intents the evidence supports. Empty means: not phishing."""
    found = sorted(name for name, members in THEFT_VECTOR_CODES.items() if codes & members)
    if credential_dest_trusted and "credential_request" in found:
        # The message asks for a credential action, but every destination is
        # the authenticated sender's own. That is a password reset, not a
        # harvest. Dropping the vector is what stops a real Atlassian or
        # Google security email being labelled phishing.
        found = [v for v in found if v != "credential_request"]
    return found


def clamp_score_to_label(score: int, verdict: Verdict) -> int:
    """Keep the number consistent with the word.

    The theft gate can rule out PHISHING for a message whose hygiene scored
    badly — the pharmacy spam that fails SPF, has no DKIM and obfuscates its
    text reaches 90 on hygiene alone. Reporting "SPAM 90" is incoherent and
    breaks the guarantee that a higher score never carries a milder label, so
    the score is damped into the band its label occupies. The risk score is a
    statement about danger TO THE RECIPIENT, and unsolicited selling with no
    theft vector is not a 90.
    """
    if verdict == Verdict.GENUINE:
        return min(score, THRESHOLD_SPAM - 1)
    if verdict == Verdict.SPAM:
        # Floor as well as ceiling. Spam occupies its own band, so a harmless
        # cold sales email lands at 25 rather than 0 even though its actual
        # danger is nil. The trade-off is explicit: this makes the number an
        # ordered severity scale that the label reads off, rather than a pure
        # probability of harm. Without it a SPAM verdict could score below a
        # GENUINE one and the ordering guarantee breaks.
        return max(THRESHOLD_SPAM, min(score, THRESHOLD_SUSPICIOUS - 1))
    if verdict == Verdict.SUSPICIOUS:
        return min(score, THRESHOLD_PHISHING - 1)
    return score


# Markers that a message is unsolicited bulk commercial mail. These describe
# HOW it was sent and what it wants, not whether it is dangerous — which is
# why spam is decided separately from the risk score. A message can be
# low-risk and still be spam.
SPAM_MARKER_CODES = {
    "HDR_BULK_DECLARED", "HDR_HIDDEN_RECIPIENTS", "HDR_SCRIPTED_MAILER",
    "CNT_PROMOTIONAL", "CNT_TRACKING_PIXEL", "CNT_EXCESSIVE_CAPS",
    "CNT_SUBJECT_PUNCTUATION", "CNT_FINANCIAL_LURE", "CNT_IMAGE_ONLY",
    "URL_MANY_DOMAINS", "URL_LINK_FLOOD", "CNT_GENERIC_GREETING",
}

# Two independent markers. One alone is too common in legitimate mail — plenty
# of real transactional messages carry a tracking pixel.
SPAM_MARKER_THRESHOLD = 2


def count_spam_markers(codes: set) -> int:
    return len(codes & SPAM_MARKER_CODES)


def decide_label(score: int, theft_vectors: List[str], spam_markers: int,
                 analyst_says_spam: bool = False) -> Verdict:
    """The single place a label is produced. Derived from the score, gated.

    Called by fusion.fuse() and by nothing else. The language model's verdict
    is deliberately not a parameter here — it has already been folded into the
    score by the time this runs, and consulting it again would recreate the
    two-paths bug this design exists to remove.
    """
    has_theft = bool(theft_vectors)
    # The analyst reading a message as unsolicited commercial mail IS a spam
    # marker — arguably the best one available, since "is this selling me
    # something I did not ask for" is a judgement about meaning, not
    # structure. Requiring the rules to independently find two STRUCTURAL
    # markers before honouring it vetoed four correct SPAM verdicts in
    # evaluation: plain-text cold sales mail has no tracking pixel, no
    # undisclosed recipients and no bulk mailer header, so it scored zero
    # markers and was pushed to SUSPICIOUS.
    #
    # This is not the model overriding the label — the label is still a pure
    # function of (score, theft vectors, spam evidence). The model's reading
    # is one input to the spam evidence, alongside the structural markers.
    is_spam = (spam_markers >= SPAM_MARKER_THRESHOLD or analyst_says_spam) and not has_theft

    if score >= THRESHOLD_PHISHING:
        if has_theft:
            return Verdict.PHISHING
        # High risk with no theft intent: aggressive, badly-sent commercial
        # mail. That is the pharmacy-spam case.
        return Verdict.SPAM if is_spam else Verdict.SUSPICIOUS

    if score >= THRESHOLD_SUSPICIOUS:
        return Verdict.SPAM if is_spam else Verdict.SUSPICIOUS

    if score >= THRESHOLD_SPAM:
        return Verdict.SPAM if is_spam else Verdict.SUSPICIOUS

    # Low risk. Still spam if it announced itself as bulk commercial mail.
    return Verdict.SPAM if is_spam else Verdict.GENUINE


def _trust_credits(email: ParsedEmail, signals: List[Signal],
                   theft_vectors: List[str]) -> Tuple[int, List[str], bool]:
    """Positive evidence that this message is what it claims to be.

    Returns (points_to_subtract, reasons, authenticated_sender).

    One rule governs everything here: **authentication is suppressed as
    reassurance when a theft vector is present.** Aligned DKIM proves the
    sending domain authorised the message. It does not prove the human behind
    it is who they claim, and business email compromise is precisely an
    attacker using a real, correctly-authenticated mailbox. Crediting that
    message for passing DKIM is how a payroll-diversion attempt scores 11.
    """
    from parser import domain_of

    credits = 0
    reasons: List[str] = []
    codes = {s.code for s in signals}

    if not email.headers_present:
        return 0, [], False

    auth = (email.auth_results or "").lower()
    from_domain = domain_of(email.from_address)
    aligned, signer = dkim_alignment(email)
    dmarc_pass = "dmarc=pass" in auth
    authenticated = bool(aligned and dmarc_pass)

    if theft_vectors:
        # The message is asking for credentials, money, or is impersonating a
        # brand. Whether its envelope was signed correctly is not a reason to
        # trust that request. Report the authentication state — the analyst
        # should see it — but grant no points for it.
        if authenticated:
            reasons.append(
                f"DKIM aligns with {from_domain} and DMARC passed, so the sending "
                f"domain is genuine — but no trust credit is applied because the "
                f"message carries a theft vector ({', '.join(theft_vectors)}). "
                f"Authentication proves who sent it, not that the request is "
                f"legitimate; a real mailbox is exactly what this attack uses."
            )
        return 0, reasons, authenticated

    # ---- aligned DKIM + DMARC: the strongest genuine signal available -----
    if authenticated:
        credits += 30
        reasons.append(
            f"DKIM signature is aligned (d={signer} matches the From domain "
            f"{from_domain}) and DMARC passed. This is cryptographic proof that "
            f"{from_domain} authorised this message — the strongest evidence of "
            f"legitimacy an email can carry."
        )
    elif "dkim=pass" in auth and "spf=pass" in auth:
        credits += 12
        reasons.append(
            f"SPF and DKIM both passed, though the DKIM signature is not aligned "
            f"with {from_domain}" + (f" (signed by {signer})" if signer else "") +
            ". The message was authorised by some domain, but not demonstrably by "
            "the one it claims to be from."
        )
    elif "spf=pass" in auth:
        credits += 6
        reasons.append("SPF passed — the sending server is authorised for this domain.")

    # A recognised brand domain that also authenticated.
    if from_domain in intel.LEGITIMATE_DOMAINS and authenticated:
        credits += 12
        reasons.append(
            f"Sent from {from_domain}, a verified sending domain for that "
            f"organisation, with aligned authentication confirming it."
        )

    # Links that stay home. Tracking wrappers count as home when the sender is
    # authenticated — see intel.ESP_TRACKING_DOMAINS.
    if email.links and from_domain:
        offsite = [
            l for l in email.links
            if l.registered_domain
            and l.registered_domain != from_domain
            and l.registered_domain not in intel.LEGITIMATE_DOMAINS
            and not (authenticated and intel.is_tracking_wrapper(l.domain))
        ]
        if not offsite:
            credits += 8
            reasons.append(
                "Every link resolves to the sender's own domain, a recognised one, "
                "or the sender's click-tracking service — there is no third-party "
                "destination to harvest at."
            )

    if len(email.received_chain) >= 3 and "HDR_NO_RECEIVED" not in codes:
        credits += 4
        reasons.append(
            f"Carries a {len(email.received_chain)}-hop routing trail written by the "
            f"servers that handled it, consistent with normal delivery."
        )

    pressure = {"CNT_URGENCY", "CNT_THREAT", "CNT_CREDENTIAL_REQUEST", "CNT_SECRECY"}
    if not (pressure & codes) and email.body_text:
        credits += 6
        reasons.append(
            "No urgency, threat, secrecy or credential-request language — the "
            "message is not applying pressure of any kind."
        )

    return credits, reasons, authenticated


def score(email: ParsedEmail, signals: List[Signal]) -> Tuple[
        ScoreBreakdown, Verdict, int, str, List[Signal], List[str], int, bool]:
    """Turn evidence into a score, then derive a label from it.

    Returns:
        breakdown        per-category points, credits and the final score
        verdict          the label, from decide_label() and nowhere else
        confidence       how well the evidence supports that label
        assessment       the written explanation
        added            signals produced here (correlations, trust credits)
        theft_vectors    which theft intents were found; empty means not phishing
        spam_markers     count of bulk-commercial markers
        authenticated    DKIM aligned with the From domain AND DMARC passed
    """
    # Established first: both the urgency cap and the trust credits depend on
    # whether the sender is cryptographically authenticated, and the credits
    # in turn depend on whether a theft vector is present.
    codes = {s.code for s in signals}
    # Authentication is established directly rather than inferred from the
    # credit path, because the theft-vector decision depends on it and the
    # credit decision depends on the theft vectors.
    aligned, _signer = dkim_alignment(email)
    authenticated = bool(aligned and "dmarc=pass" in (email.auth_results or "").lower())
    dest_trusted = credential_destination_trusted(email, authenticated)
    theft_vectors = detect_theft_vectors(codes, dest_trusted)
    credits, credit_reasons, _auth = _trust_credits(email, signals, theft_vectors)

    by_category: Dict[Category, List[Signal]] = {}
    for signal in signals:
        by_category.setdefault(signal.category, []).append(signal)

    header_pts = _decayed_total(by_category.get(Category.HEADER, []))
    auth_pts = _decayed_total([s for s in signals if s.code.startswith("AUTH_")])
    # AUTH_ signals are tagged Category.HEADER, so remove them from the header
    # bucket to avoid counting the same evidence in two columns.
    header_only = [s for s in by_category.get(Category.HEADER, []) if not s.code.startswith("AUTH_")]
    header_pts = _decayed_total(header_only)
    url_pts = _decayed_total(by_category.get(Category.URL, []))
    content_pts = _decayed_total(by_category.get(Category.CONTENT, []))
    attach_pts = _decayed_total(by_category.get(Category.ATTACHMENT, []))

    base = header_pts + auth_pts + url_pts + content_pts + attach_pts
    # Urgency on its own must never reach the SUSPICIOUS threshold.
    base -= _apply_urgency_cap(signals, authenticated)

    # ---- correlations ----------------------------------------------------
    correlation_bonus = 0
    added: List[Signal] = []
    for name, required, bonus, reasoning in CORRELATIONS:
        if required.issubset(codes):
            correlation_bonus += bonus
            added.append(Signal(
                code="CORR_" + name.upper().replace(" ", "_")[:40],
                title=f"Correlated pattern: {name}",
                category=Category.CONTENT,
                severity=Severity.HIGH,
                detail=reasoning,
                evidence=" + ".join(sorted(required)),
            ))

    # ---- trust credits (computed above; recorded here) -------------------
    for reason in credit_reasons:
        added.append(Signal(
            code="TRUST_CREDIT", title="Positive indicator",
            category=Category.AUTH, severity=Severity.INFO,
            detail=reason,
        ))

    raw_total = base + correlation_bonus
    final_raw = max(0, raw_total - credits)

    # Map an unbounded point total onto 0-100. The curve is deliberately steep
    # early — the first genuinely serious finding should move the needle a long
    # way — and flattens above ~120 points, where more evidence stops changing
    # the decision that will be taken.
    if final_raw <= 0:
        rules_score = 0
    elif final_raw >= 150:
        rules_score = 100
    else:
        rules_score = int(round(100 * (1 - pow(2.718281828, -final_raw / 45.0))))
        rules_score = min(100, max(0, rules_score))

    # ---- floors ----------------------------------------------------------
    # Some findings are conclusive on their own and must not be averaged away
    # by an otherwise clean message.
    critical_codes = {s.code for s in signals if s.severity == Severity.CRITICAL}
    if critical_codes:
        rules_score = max(rules_score, 55)
    if critical_codes & {"ATT_EXECUTABLE", "ATT_HIDDEN_EXECUTABLE", "ATT_DOUBLE_EXTENSION",
                         "ATT_RLO_FILENAME", "ATT_SHORTCUT", "ATT_DISK_IMAGE"}:
        rules_score = max(rules_score, 78)
    # A gift card demand or an impersonated payment order is conclusive
    # regardless of how clean the rest of the message is — and these messages
    # are deliberately clean, which is the whole problem.
    if "CNT_GIFT_CARD_REQUEST" in codes:
        rules_score = max(rules_score, 80)
    if "CNT_PAYMENT_INSTRUCTION" in codes and (
            codes & {"CNT_EXECUTIVE_FREEMAIL", "CNT_DEPARTMENT_FREEMAIL",
                     "CNT_CHANNEL_ISOLATION", "CNT_SECRECY"}):
        # Someone outside the organisation's own mail system asking for money
        # to move. The authentication passing is not reassurance here — a real
        # Gmail account is exactly what this attack uses.
        rules_score = max(rules_score, 78)
    if "CNT_PROMPT_INJECTION" in codes:
        # A message attacking its own analyser is never cleared, whatever else
        # it looks like.
        rules_score = max(rules_score, 72)
    if len(critical_codes) >= 3:
        rules_score = max(rules_score, 85)

    breakdown = ScoreBreakdown(
        header_points=header_pts, auth_points=auth_pts, url_points=url_pts,
        content_points=content_pts, attachment_points=attach_pts,
        trust_credits=credits, raw_total=raw_total,
        rules_score=rules_score, final_score=rules_score,
    )

    spam_markers = count_spam_markers(codes)
    verdict = decide_label(rules_score, theft_vectors, spam_markers)
    rules_score = clamp_score_to_label(rules_score, verdict)
    breakdown.rules_score = rules_score
    breakdown.final_score = rules_score
    confidence = _confidence(email, signals, codes, rules_score, credits)
    assessment = _write_assessment(email, signals + added, verdict, rules_score,
                                   credits, credit_reasons, correlation_bonus,
                                   theft_vectors)
    return (breakdown, verdict, confidence, assessment, added,
            theft_vectors, spam_markers, authenticated)


def _confidence(email: ParsedEmail, signals: List[Signal], codes: set,
                score_value: int, credits: int = 0) -> int:
    """How much the evidence supports the verdict — not how bad the mail is.

    Confidence is about the QUALITY of what we could observe. A body-only
    paste with three keyword hits gives a verdict, but a weak one, and saying
    so is more useful than an unqualified answer.
    """
    confidence = 50

    # Verifiable evidence outranks inferred evidence.
    if email.headers_present:
        confidence += 12
    else:
        confidence -= 22

    if email.auth_results:
        confidence += 14      # a server-stamped result is hard evidence

    severities = [s.severity for s in signals]
    confidence += min(18, 6 * severities.count(Severity.CRITICAL))
    confidence += min(10, 3 * severities.count(Severity.HIGH))

    # Agreement across independent categories. Header, URL, content and
    # attachment evidence are gathered by unrelated means, so when they point
    # the same way the conclusion is much better supported than when one
    # category carries it alone.
    categories = {s.category for s in signals
                  if s.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)}
    confidence += 7 * max(0, len(categories) - 1)

    # A verdict sitting on a threshold is genuinely less certain.
    for threshold in (THRESHOLD_PHISHING, THRESHOLD_SUSPICIOUS, THRESHOLD_SPAM):
        if abs(score_value - threshold) <= 5:
            confidence -= 10
            break

    # Positive evidence is evidence. A message that actively proved its
    # identity supports a GENUINE verdict just as strongly as a spoof
    # supports a PHISHING one, and the clean case must not be reported as a
    # coin flip — an analyst who sees low confidence on every good email
    # stops reading the confidence field at all.
    if credits >= 35:
        confidence += 18
    elif credits >= 20:
        confidence += 12
    elif credits >= 10:
        confidence += 6

    if not signals:
        # No adverse findings. Certainty then rests entirely on how much could
        # be verified, which is what the credits measure.
        base = 58 if email.headers_present else 35
        confidence = max(base, base + min(30, credits))

    return max(10, min(98, confidence))


def _write_assessment(email: ParsedEmail, signals: List[Signal], verdict: Verdict,
                      score_value: int, credits: int, credit_reasons: List[str],
                      correlation_bonus: int, theft_vectors: List[str] = None) -> str:
    """The analyst's paragraph: what was found, and what it means together.

    Written from the deterministic evidence only. When the LLM is configured
    it adds its own reading alongside this; it never replaces it, so the report
    always carries an explanation that can be reproduced exactly.
    """
    criticals = [s for s in signals if s.severity == Severity.CRITICAL]
    highs = [s for s in signals if s.severity == Severity.HIGH]
    correlations = [s for s in signals if s.code.startswith("CORR_")]

    sender = email.from_address or "an unidentified sender"
    parts: List[str] = []

    if verdict == Verdict.PHISHING:
        vectors = ", ".join((theft_vectors or [])).replace("_", " ")
        parts.append(
            f"This message is assessed as phishing (risk {score_value}/100). "
            f"It presents as coming from {sender} and attempts "
            f"{vectors if vectors else 'theft by deception'}."
        )
    elif verdict == Verdict.SPAM and score_value >= THRESHOLD_SUSPICIOUS:
        parts.append(
            f"This message scores {score_value}/100 on risk, but no theft vector was "
            f"found — no credential request, no brand impersonation, no payment "
            f"redirection and no harvesting attachment. It is aggressive, poorly-sent "
            f"bulk commercial mail rather than an attack on the recipient."
        )
    elif verdict == Verdict.SUSPICIOUS:
        parts.append(
            f"This message is suspicious (risk {score_value}/100). There is enough "
            f"adverse evidence to withhold trust, but not the decisive combination "
            f"that would make the call conclusive."
        )
    elif verdict == Verdict.SPAM:
        parts.append(
            f"This message reads as unsolicited bulk mail (risk {score_value}/100). "
            f"It shows commercial mass-mailing characteristics without the identity "
            f"deception that marks a phishing attempt."
        )
    else:
        parts.append(
            f"No significant threat indicators were found (risk {score_value}/100). "
            f"The message behaves consistently with legitimate correspondence."
        )

    if criticals:
        names = "; ".join(s.title for s in criticals[:3])
        parts.append(
            f"{len(criticals)} critical finding{'s' if len(criticals) > 1 else ''}: {names}"
            f"{'.' if len(criticals) <= 3 else f', and {len(criticals) - 3} more.'}"
        )
    if highs and not criticals:
        names = "; ".join(s.title for s in highs[:3])
        parts.append(f"{len(highs)} high-severity finding{'s' if len(highs) > 1 else ''}: {names}.")

    if correlations:
        parts.append(
            f"{len(correlations)} correlated attack pattern"
            f"{'s were' if len(correlations) > 1 else ' was'} recognised, where separate "
            f"findings combine into a known technique rather than appearing independently."
        )

    if credits and credit_reasons:
        parts.append(
            f"Offsetting this, {len(credit_reasons)} positive indicator"
            f"{'s' if len(credit_reasons) > 1 else ''} reduced the score by {credits} points: "
            f"{credit_reasons[0].rstrip('.')}."
        )

    if not email.headers_present:
        parts.append(
            "Note: no headers were supplied, so sender authentication and routing "
            "could not be examined. This assessment rests on body and link evidence "
            "alone and should be treated as provisional."
        )

    return " ".join(parts)

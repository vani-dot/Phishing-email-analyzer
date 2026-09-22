# intel.py
# Static reference data and the lookalike-domain maths.
#
# Kept apart from the rule modules so the lists can be tuned from evaluation
# results without touching detection logic, and so every rule uses the same
# definition of "a brand" or "a risky TLD".

import difflib
import re
import unicodedata
from typing import Dict, List, Optional, Tuple

# Brands that get impersonated, mapped to the domains they legitimately send
# from. A mail claiming to be a brand but sending from anywhere else is the
# core impersonation check.
BRAND_DOMAINS: Dict[str, List[str]] = {
    "paypal":     ["paypal.com", "paypal.co.uk", "paypal-communication.com"],
    "microsoft":  ["microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com", "outlook.com"],
    "apple":      ["apple.com", "icloud.com", "itunes.com"],
    "google":     ["google.com", "gmail.com", "googlemail.com", "youtube.com"],
    "amazon":     ["amazon.com", "amazon.co.uk", "amazon.in", "amazonses.com"],
    "netflix":    ["netflix.com"],
    "facebook":   ["facebook.com", "facebookmail.com", "meta.com"],
    "instagram":  ["instagram.com", "mail.instagram.com"],
    "linkedin":   ["linkedin.com"],
    "whatsapp":   ["whatsapp.com"],
    "dhl":        ["dhl.com", "dhl.de"],
    "fedex":      ["fedex.com"],
    "ups":        ["ups.com"],
    "dropbox":    ["dropbox.com", "dropboxmail.com"],
    "adobe":      ["adobe.com"],
    "docusign":   ["docusign.com", "docusign.net"],
    "chase":      ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "hsbc":       ["hsbc.com", "hsbc.co.uk"],
    "barclays":   ["barclays.co.uk", "barclays.com"],
    "santander":  ["santander.co.uk", "santander.com"],
    "icloud":     ["icloud.com", "apple.com"],
    "coinbase":   ["coinbase.com"],
    "binance":    ["binance.com"],
    "steam":      ["steampowered.com", "valvesoftware.com"],
    "spotify":    ["spotify.com"],
    "sbi":        ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"],
    "hdfc":       ["hdfcbank.com", "hdfcbank.net"],
    "icici":      ["icicibank.com"],
    "axis":       ["axisbank.com"],
    "paytm":      ["paytm.com"],
    "phonepe":    ["phonepe.com"],
    "flipkart":   ["flipkart.com"],
}

# Flattened for fast membership tests.
LEGITIMATE_DOMAINS = {d for domains in BRAND_DOMAINS.values() for d in domains}

# TLDs with a poor abuse reputation or a free/cheap registration model.
# Presence is a weak signal on its own — weighted low, and always combined.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",           # historically free registration
    "zip", "mov",                            # confusable with file extensions
    "top", "xyz", "club", "online", "site", "icu", "cyou", "rest",
    "work", "click", "link", "buzz", "monster", "quest", "bar",
    "cam", "surf", "gdn", "kim", "loan", "men", "date", "racing",
    "stream", "download", "win", "review", "country", "science",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bl.ink", "lnkd.in", "shorte.st", "cutt.ly", "rb.gy", "rebrand.ly",
    "tiny.cc", "shorturl.at", "s.id", "t.ly", "clck.ru", "v.gd", "qr.ae",
    "soo.gd", "u.to", "tr.im", "chilp.it", "ity.im", "shrtco.de", "short.io",
}

# Commercial email service providers wrap every link in a click-tracking
# redirect. That produces two things that look exactly like an attack: the
# anchor text says one domain while the href points at another, and the link
# redirects before reaching its destination.
#
# It is not cloaking, it is analytics — and treating it as an attack signal is
# what made this analyser flag legitimate mail from Mandrill, SendGrid and SES.
# These domains are only trusted when the SENDER IS AUTHENTICATED: anyone can
# put a mandrillapp.com link in a forged email, so the wrapper alone proves
# nothing.
ESP_TRACKING_DOMAINS = {
    "mandrillapp.com", "sendgrid.net", "sendgrid.com", "list-manage.com",
    "sparkpostmail.com", "mailgun.org", "amazonses.com", "awstrack.me",
    "hubspotlinks.com", "hs-sites.com", "braze.com", "customeriomail.com",
    "mailchimp.com", "mcsv.net", "rs6.net", "constantcontact.com",
    "exacttarget.com", "et.exacttarget.com", "mkt.com", "marketo.com",
    "pardot.com", "salesforce.com", "intercom-mail.com", "postmarkapp.com",
    "mailjet.com", "sendinblue.com", "brevo.com", "klaviyomail.com",
    "cmail19.com", "createsend.com", "mailersend.net", "postoffice.net",
}

# Subdomain prefixes brands use for their own tracking hosts, e.g.
# click.e.nullcon.net, links.atlassian.com, email.amazon.in.
ESP_TRACKING_PREFIXES = ("click.", "clicks.", "link.", "links.", "track.",
                         "tracking.", "email.", "e.", "mail.", "go.", "url.")


def is_tracking_wrapper(host: str) -> bool:
    """Is this hostname a click-tracking redirector rather than a destination?"""
    if not host:
        return False
    host = host.lower().strip(".")
    ext = _extract_host(host)
    if ext in ESP_TRACKING_DOMAINS:
        return True
    return any(host.startswith(prefix) for prefix in ESP_TRACKING_PREFIXES)


def _extract_host(host: str) -> str:
    """Registrable domain of a hostname, using the same splitter as parser."""
    import tldextract
    ext = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)(host)
    return ".".join(p for p in (ext.domain, ext.suffix) if p)


FREE_MAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "gmx.com", "gmx.net", "yandex.com", "yandex.ru", "mail.ru",
    "protonmail.com", "proton.me", "zoho.com", "icloud.com", "live.com",
    "rediffmail.com", "inbox.lv", "tutanota.com", "hushmail.com",
}

DISPOSABLE_MAIL = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org",
    "throwawaymail.com", "yopmail.com", "trashmail.com", "sharklasers.com",
    "getnada.com", "maildrop.cc", "dispostable.com", "fakeinbox.com",
}

# Extensions that execute, or that Windows will happily run on a double click.
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".msi", ".msp", ".cpl",
    ".jar", ".reg", ".lnk", ".inf", ".scf", ".application", ".gadget",
    ".msc", ".dll", ".sys", ".chm", ".appref-ms",
}
# Containers, not executables. Handled by their own check so a single .iso
# does not fire both the executable rule and the disk-image rule and get
# counted twice.
CONTAINER_EXTENSIONS = {".iso", ".img", ".vhd", ".vhdx"}

MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam", ".sldm"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar", ".bz2", ".xz", ".ace", ".arj", ".cab"}
# Old Office formats carry macros and are a persistent malware vector.
LEGACY_OFFICE = {".doc", ".xls", ".ppt", ".rtf"}

# ---- content phrase banks ------------------------------------------------
# Grouped by tactic so the report can name the tactic, not just "keyword hit".

URGENCY_PHRASES = [
    "urgent", "immediate action", "act now", "expires today", "expires in",
    "within 24 hours", "within 48 hours", "final notice", "last warning",
    "time sensitive", "respond immediately", "as soon as possible",
    "failure to comply", "avoid suspension", "before it is too late",
    "limited time", "do not delay", "your immediate attention",
]

THREAT_PHRASES = [
    "account suspended", "account has been locked", "account will be closed",
    "account terminated", "unauthorized access", "unusual activity",
    "suspicious activity", "security alert", "violation", "legal action",
    "your account will be", "permanently deleted", "service interrupted",
    "unable to verify", "we have detected", "has been compromised",
    "will be deactivated", "restricted access",
]

CREDENTIAL_PHRASES = [
    "verify your account", "confirm your identity", "update your password",
    "reset your password", "sign in to continue", "log in to verify",
    "confirm your details", "validate your account", "re-enter your password",
    "update your payment", "confirm your payment", "update billing",
    "verify your identity", "click here to login", "secure your account",
    "confirm your email", "activate your account", "update your information",
]

FINANCIAL_LURE_PHRASES = [
    "you have won", "lottery", "prize", "inheritance", "beneficiary",
    "million dollars", "refund", "tax refund", "cash reward", "claim your",
    "unclaimed funds", "compensation", "wire transfer", "bank transfer",
    "bitcoin", "cryptocurrency", "investment opportunity", "guaranteed return",
    "no risk", "risk free", "earn money", "work from home",
]

SECRECY_PHRASES = [
    "strictly confidential", "do not tell anyone", "keep this between us",
    "do not share this", "private and confidential", "discreet",
    "between you and me", "do not inform",
]

# Business email compromise is the costliest email attack by a wide margin, and
# it is invisible to most of the checks above: a real Gmail account passes SPF,
# DKIM and DMARC, carries no links and attaches nothing. The only evidence is
# who the sender CLAIMS to be and what they ask for, so those get their own
# vocabularies.

# Titles that carry authority to instruct a finance team.
EXECUTIVE_TITLES = [
    "ceo", "cfo", "coo", "cto", "ciso", "cio", "chief executive",
    "chief financial", "chief operating", "president", "vice president",
    "managing director", "chairman", "chairwoman", "board member",
    "director", "head of finance", "head of hr", "finance manager",
    "founder", "co-founder", "owner", "partner", "principal",
]

# Internal functions an attacker claims to speak for. Distinct from
# EXECUTIVE_TITLES: "Acme HR" or "Payroll Department" carries authority over a
# specific process without naming a person, which is harder to verify and
# therefore more effective.
DEPARTMENT_NAMES = [
    "hr", "human resources", "payroll", "finance", "accounts", "accounting",
    "accounts payable", "accounts receivable", "billing", "it support",
    "it helpdesk", "helpdesk", "service desk", "security team", "it security",
    "admin", "administration", "procurement", "purchasing", "treasury",
    "benefits", "people team", "operations",
]

# Requests to MOVE money. Distinct from FINANCIAL_LURE_PHRASES, which offer
# money — the direction matters. A lure is a confidence trick on a stranger;
# a payment instruction is an order from an apparent superior.
PAYMENT_INSTRUCTION_PHRASES = [
    "wire transfer", "bank transfer", "process a payment", "process the payment",
    "make a payment", "send the payment", "transfer funds", "transfer the funds",
    "remittance", "bank details", "banking details", "account details",
    "payment details", "new supplier", "new vendor", "change of bank",
    "updated bank", "update the bank", "pay the invoice", "settle the invoice",
    "purchase gift cards", "buy gift cards", "gift card", "itunes card",
    "steam card", "payroll", "direct deposit", "beneficiary account",
]

# "You cannot verify this through any other channel." Attackers say this
# because a thirty-second phone call ends the entire attack.
CHANNEL_ISOLATION_PHRASES = [
    "i am travelling", "i'm travelling", "i am traveling", "i'm traveling",
    "in meetings all day", "tied up in meetings", "only be reached by email",
    "only reachable by email", "cannot take calls", "can't take calls",
    "unable to take calls", "no phone access", "away from my desk",
    "currently unavailable by phone", "do not call me", "email me instead",
    "my phone is not working", "poor signal", "in a conference",
]

# Unsolicited commercial selling. These mark a message as SPAM, which is a
# question about what it IS, not about how dangerous it is — a cold sales email
# is spam at a risk score of 5.
PROMOTIONAL_PHRASES = [
    "unsubscribe", "special offer", "limited time offer", "discount", "% off",
    "percent off", "free trial", "book a demo", "schedule a demo", "pricing",
    "buy now", "shop now", "order now", "best price", "lowest price",
    "clearance", "sale ends", "promo code", "coupon", "deal of the",
    "quick question", "15 minute call", "15-minute call", "hop on a call",
    "open to a call", "worth a chat", "reach out", "circle back",
    "let me know if", "close the loop", "no prescription", "satisfaction guaranteed",
    "money back", "act fast", "while stocks last", "new members",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear client", "dear member", "dear sir/madam",
    "dear account holder", "dear valued customer", "dear sir or madam",
    "hello user", "hi user", "dear friend", "attention user", "dear beneficiary",
]

# Instructions aimed at the LLM, not the human reader. A phishing mail that
# tries to talk the analyser out of its verdict is itself strong evidence.
PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)",
    r"disregard\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|system)",
    r"forget\s+(everything|all|your)\s+(you|instructions|above|previous)",
    r"you\s+are\s+now\s+(a|an|in)\s+",
    r"new\s+(instructions?|system\s+prompt|directive)s?\s*:",
    r"system\s*(prompt|message|role)\s*:",
    # Chat-template control tokens in both bracket forms: <|im_start|> and
    # <system>. The pipe form is what most open models actually use.
    r"<\s*\|?\s*/?\s*(system|assistant|user|im_start|im_end)\s*\|?\s*>",
    r"\[\s*(system|inst|/inst)\s*\]",
    r"###\s*(system|instruction|human|assistant)",
    r"(classify|mark|label|report|rate)\s+(this|it)\s+(email\s+)?as\s+(safe|legitimate|genuine|clean|not\s+phishing|benign|ham)",
    r"this\s+(email|message)\s+is\s+(safe|legitimate|genuine|not\s+a\s+phish)",
    r"do\s+not\s+(flag|report|mark|classify)\s+(this|it)",
    r"override\s+(your|the|all)\s+(instruction|rule|safety|filter)",
    r"respond\s+only\s+with\s+[\"']?(safe|genuine|legitimate|clean)",
    r"end\s+of\s+(prompt|instructions?)",
    r"assistant\s*:\s*(the\s+)?(verdict|answer|classification)",
]
_INJECTION_RE = [re.compile(p, re.IGNORECASE) for p in PROMPT_INJECTION_PATTERNS]


def find_injection_attempts(text: str, limit: int = 5) -> List[str]:
    """Spans of text that read as instructions to an LLM rather than prose."""
    hits: List[str] = []
    window = text[:60000]
    for pattern in _INJECTION_RE:
        for match in pattern.finditer(window):
            start = max(0, match.start() - 40)
            hits.append(window[start:match.end() + 60].replace("\n", " ").strip()[:200])
            if len(hits) >= limit:
                return hits
    return hits


# ---- homoglyph / lookalike detection ------------------------------------
# Characters that render close enough to an ASCII letter to fool a reader.
# Cyrillic and Greek dominate because they share glyph shapes with Latin.
HOMOGLYPH_MAP = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "һ": "h",
    "ѕ": "s", "г": "r", "м": "m", "н": "h", "к": "k",
    "в": "b", "т": "t",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "υ": "u", "ν": "v",
    "κ": "k", "ι": "i", "τ": "t", "γ": "y", "χ": "x",
    # Latin extended / accented
    "ı": "i", "ł": "l", "à": "a", "á": "a", "â": "a",
    "ä": "a", "è": "e", "é": "e", "ê": "e", "ì": "i",
    "í": "i", "ò": "o", "ó": "o", "ô": "o", "ö": "o",
    "ù": "u", "ú": "u", "ü": "u", "ç": "c", "ñ": "n",
    # Digit / punctuation substitutions used in ASCII-only typosquats
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "9": "g",
    "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-",
}


def deskeleton(text: str) -> str:
    """Fold a string to its ASCII 'shape'.

    paypaI.com, pаypal.com (Cyrillic а) and paypa1.com all collapse to
    'paypal.com', which is what makes them comparable to the real thing.
    """
    # Uppercase I -> l must happen BEFORE lowercasing. In most sans-serif
    # fonts a capital I is indistinguishable from a lowercase l, which is
    # exactly the trick in paypaI.com; lowercase first and that becomes "i"
    # and the resemblance is lost.
    text = unicodedata.normalize("NFKC", text).replace("I", "l")
    text = text.lower()
    out = [HOMOGLYPH_MAP.get(ch, ch) for ch in text]
    folded = "".join(out)
    # 'rn' renders almost identically to 'm' at small sizes — a classic.
    return folded.replace("rn", "m").replace("vv", "w").replace("cl", "d")


def has_mixed_scripts(text: str) -> Optional[Tuple[str, str]]:
    """Two different writing systems inside one label.

    Legitimate domains do not mix Cyrillic and Latin in a single word. This
    catches lookalikes that a pure spelling comparison misses.
    """
    scripts = {}
    for ch in text:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        script = name.split(" ")[0]
        if script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC"):
            scripts.setdefault(script, ch)
    if len(scripts) > 1:
        items = sorted(scripts.items())
        return items[0][0], items[1][0]
    return None


def similarity(a: str, b: str) -> float:
    """0.0-1.0 string closeness. difflib, so no C extension to compile."""
    return difflib.SequenceMatcher(None, a, b).ratio()


def lookalike_brand(domain: str, threshold: float = 0.80) -> Optional[Tuple[str, str, float]]:
    """Is this domain pretending to be a brand it is not?

    Returns (brand, matched_legit_domain, score) or None. An exact match
    against a real brand domain returns None — that is the brand, not a
    lookalike.
    """
    if not domain:
        return None
    domain = domain.strip()
    # Compare the REGISTRABLE domain, not the hostname. Checking the raw host
    # meant "www.amazon.in" was not found in the legitimate set and was then
    # scored as a lookalike of amazon.com — so a genuine link to
    # www.paypal.com was reported as a fake PayPal. Ownership lives in the
    # registrable domain; the subdomain is just a label in front of it.
    lowered = domain.lower()
    if lowered in LEGITIMATE_DOMAINS or _extract_host(lowered) in LEGITIMATE_DOMAINS:
        return None

    # Fold from the ORIGINAL case. deskeleton maps capital I to l, and that
    # mapping is destroyed by an earlier .lower().
    folded = deskeleton(domain)
    domain = domain.lower()
    label = folded.split(".")[0]

    best = None
    for brand, legit_domains in BRAND_DOMAINS.items():
        for legit in legit_domains:
            legit_label = legit.split(".")[0]
            # Exact brand word inside a different registered domain, e.g.
            # paypal.security-verify.tk — the brand is present but the domain
            # is not theirs.
            if brand in folded and domain not in LEGITIMATE_DOMAINS:
                score = 0.99 if folded.split(".")[0] == brand else 0.92
                if not best or score > best[2]:
                    best = (brand, legit, score)
                continue
            score = similarity(label, legit_label)
            if score >= threshold and label != legit_label:
                if not best or score > best[2]:
                    best = (brand, legit, score)
    return best


def brands_mentioned(text: str, limit: int = 6) -> List[str]:
    """Brand names appearing in the visible text of a message."""
    lowered = deskeleton(text[:30000])
    found = []
    for brand in BRAND_DOMAINS:
        if re.search(r"\b" + re.escape(brand) + r"\b", lowered):
            found.append(brand)
            if len(found) >= limit:
                break
    return found

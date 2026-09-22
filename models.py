# models.py
# The contract. Every layer speaks these types: the rules engine emits Signals,
# the LLM is forced to return LLMOpinion, the API serialises Report, the
# database stores Report. One definition, four uses — which is the whole
# reason pydantic is in this project.

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, computed_field, field_validator


class Verdict(str, Enum):
    PHISHING = "PHISHING"
    SUSPICIOUS = "SUSPICIOUS"
    SPAM = "SPAM"
    GENUINE = "GENUINE"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Points a single signal contributes to the risk score. Kept here rather than
# inline at each call site so the scoring model can be read in one glance and
# tuned in one place when evaluation says it is miscalibrated.
SEVERITY_POINTS: Dict[str, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 22,
    Severity.MEDIUM: 11,
    Severity.LOW: 4,
    Severity.INFO: 0,
}


class Category(str, Enum):
    HEADER = "header"
    AUTH = "authentication"
    URL = "url"
    CONTENT = "content"
    ATTACHMENT = "attachment"
    LLM = "llm"


class Signal(BaseModel):
    """One piece of evidence. Never a conclusion — a fact plus its weight."""
    code: str                       # stable id, e.g. "URL_HOMOGLYPH"
    title: str                      # human summary
    category: Category
    severity: Severity
    detail: str = ""                # the specific observation
    # Where it was found, so the UI can point at it. Attacker-controlled text,
    # so the front end renders it with textContent, never innerHTML.
    evidence: Optional[str] = None

    @computed_field
    @property
    def weight(self) -> int:
        """Points this signal contributes, exposed in the serialised report.

        The per-signal weight breakdown is what makes this a security tool
        rather than a classifier: "malicious because X, Y and Z, each worth
        this much" is an answer that can be checked, argued with and tuned.
        """
        return SEVERITY_POINTS[self.severity]

    @property
    def points(self) -> int:
        return SEVERITY_POINTS[self.severity]

    @field_validator("detail", "evidence")
    @classmethod
    def _truncate(cls, v):
        """Attacker-controlled strings never grow without bound in our DB."""
        if v is None:
            return v
        v = v.replace("\x00", "")
        return v if len(v) <= 500 else v[:497] + "..."


class Attachment(BaseModel):
    filename: str = ""
    content_type: str = ""
    size: int = 0
    sha256: str = ""
    declared_ext: str = ""
    detected_type: Optional[str] = None   # from magic bytes, not the name


class LinkInfo(BaseModel):
    url: str
    domain: str = ""
    registered_domain: str = ""
    scheme: str = ""
    # Anchor text in an HTML body. The classic phish is text saying one domain
    # and an href pointing at another.
    display_text: Optional[str] = None
    is_mismatch: bool = False
    redirect_chain: List[str] = Field(default_factory=list)


class ParsedEmail(BaseModel):
    """Structured form of whatever the user pasted or uploaded."""
    subject: str = ""
    from_address: str = ""
    from_display: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    date: str = ""
    message_id: str = ""
    auth_results: str = ""
    received_chain: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    body_text: str = ""
    body_html: str = ""
    links: List[LinkInfo] = Field(default_factory=list)
    attachments: List[Attachment] = Field(default_factory=list)
    # True when the input had no recognisable headers and we treated the whole
    # thing as a body. Header signals are then unavailable, not "clean" — the
    # report must say so rather than quietly scoring it safe.
    headers_present: bool = True
    parse_notes: List[str] = Field(default_factory=list)


class TheftVector(str, Enum):
    """The intents that separate phishing from merely unwanted mail.

    A message may only be labelled PHISHING if at least one of these is
    present. Bad hygiene — failed SPF, absent DKIM, a disreputable TLD — is not
    theft; it is bad hygiene, and a spam sender with a broken mail setup is
    still a spam sender.
    """
    CREDENTIAL_REQUEST = "credential_request"
    BRAND_IMPERSONATION = "brand_impersonation"
    PAYMENT_REDIRECTION = "payment_redirection"
    HARVESTING_ATTACHMENT = "harvesting_attachment"


class LLMOpinion(BaseModel):
    """The analyst's assessment. The only shape the model may return.

    The model is now the PRIMARY judge, so it returns a score as well as a
    label — not a nudge to somebody else's number. Anything that does not
    validate is discarded and the analysis falls back to the rules engine.
    """
    verdict: Verdict
    # 0-100, on the same scale the rules engine uses. The model is given
    # explicit calibration anchors in the system prompt so this number means
    # the same thing across messages.
    risk_score: int = Field(default=-1, ge=-1, le=100)
    confidence: int = Field(ge=0, le=100)
    reasoning: str = Field(default="", max_length=1500)
    social_engineering_tactics: List[str] = Field(default_factory=list, max_length=10)
    # Which theft intents the analyst identified. The model can see intent the
    # rules cannot — a payroll diversion written in plain business English has
    # no keyword to match — so its vectors are unioned with the rules engine's.
    theft_vectors: List[str] = Field(default_factory=list, max_length=4)
    # Why it is NOT the other thing. Forces the model to consider the
    # alternative rather than pattern-matching to the first plausible label.
    counter_argument: str = Field(default="", max_length=600)
    # The model reports, as data, whether the body tried to give it
    # instructions. A phishing mail that attacks the analyser is itself a
    # finding.
    injection_attempt_detected: bool = False

    @field_validator("theft_vectors")
    @classmethod
    def _valid_vectors(cls, v):
        allowed = {t.value for t in TheftVector}
        return sorted({str(x).strip().lower() for x in v} & allowed)

    @field_validator("social_engineering_tactics")
    @classmethod
    def _clean_tactics(cls, v):
        return [str(t)[:120] for t in v][:10]


class ScoreBreakdown(BaseModel):
    header_points: int = 0
    auth_points: int = 0
    url_points: int = 0
    content_points: int = 0
    attachment_points: int = 0
    trust_credits: int = 0        # positive evidence, subtracted from the total
    llm_points: int = 0           # the model's weighted contribution to the score
    raw_total: int = 0
    rules_score: int = 0          # 0-100 from deterministic rules alone
    final_score: int = 0          # 0-100 after fusion with the LLM


class Report(BaseModel):
    """The complete analysis. This is what the API returns and the DB stores."""
    id: Optional[int] = None
    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    confidence: int = Field(ge=0, le=100)
    summary: str = ""
    signals: List[Signal] = Field(default_factory=list)
    breakdown: ScoreBreakdown = Field(default_factory=ScoreBreakdown)
    email: ParsedEmail
    llm: Optional[LLMOpinion] = None
    # True when DKIM d= aligns with the header From domain AND DMARC passed —
    # cryptographic proof that the sending domain authorised this message.
    authenticated_sender: bool = False
    # Which theft intents were detected. Empty means this cannot be PHISHING.
    theft_vectors: List[str] = Field(default_factory=list)
    # Set when the model found an attack the rules engine could not see — the
    # business email compromise case. A finding worth surfacing, not an error.
    divergence: Optional[str] = None
    # What the agent actually did: which tools it called, with what arguments,
    # and what came back. This is the audit trail of the investigation and the
    # most persuasive thing in the report — it shows the conclusion was
    # reached by looking, not by pattern-matching a summary.
    investigation: List[Dict[str, Any]] = Field(default_factory=list)
    # "disabled" | "ok:<provider>" | "ok:<provider> (fallback; <why primary failed>)"
    # | "error:<provider>=<reason>, ..."  — the provider is named so a report
    # says which layer actually answered rather than implying the primary did.
    llm_status: str = "disabled"
    rules_overrode_llm: bool = False
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
    duration_ms: int = 0
    source: str = "paste"          # paste | upload | cli
    filename: Optional[str] = None

    def counts_by_severity(self) -> Dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for sig in self.signals:
            out[sig.severity.value] += 1
        return out


# ---- auth / user models --------------------------------------------------

class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Permission(str, Enum):
    """Granular capabilities. Roles are a convenient default bundle; the admin
    can grant or revoke any of these individually per user."""
    ANALYZE = "analyze"                 # run an analysis
    VIEW_HISTORY = "view_history"       # see own analyses
    VIEW_ALL_HISTORY = "view_all_history"  # see everyone's analyses
    DELETE_ANALYSIS = "delete_analysis"
    EXPORT = "export"                   # download reports as JSON
    MANAGE_USERS = "manage_users"
    VIEW_AUDIT = "view_audit"


ROLE_PERMISSIONS: Dict[str, List[str]] = {
    Role.ADMIN: [p.value for p in Permission],
    Role.ANALYST: [
        Permission.ANALYZE.value,
        Permission.VIEW_HISTORY.value,
        Permission.DELETE_ANALYSIS.value,
        Permission.EXPORT.value,
    ],
    Role.VIEWER: [
        Permission.VIEW_HISTORY.value,
    ],
}


class User(BaseModel):
    id: int
    username: str
    email: str = ""
    role: Role
    permissions: List[str] = Field(default_factory=list)
    is_active: bool = True
    must_change_password: bool = False
    created_at: Optional[str] = None
    last_login: Optional[str] = None
    failed_attempts: int = 0
    locked_until: Optional[str] = None

    def can(self, permission: str) -> bool:
        # An inactive account has no capabilities at all, whatever its grants
        # say. Disabling a user must be one switch, not a permission sweep.
        if not self.is_active:
            return False
        return permission in self.permissions

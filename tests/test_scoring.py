"""Scoring, verdict selection, and the fusion guarantees."""

import pytest
from conftest import GENUINE_EML, PHISHING_EML, sample

import analyzer
import fusion
import scoring
from models import (Category, LLMOpinion, ScoreBreakdown, Severity, Signal,
                    Verdict)


def sig(code, severity=Severity.HIGH, category=Category.URL):
    return Signal(code=code, title=code, category=category, severity=severity)


# ---- verdicts on the bundled corpus ---------------------------------------

@pytest.mark.parametrize("filename,expected", [
    ("01-phishing-credential-harvest.eml", Verdict.PHISHING),
    ("02-genuine-notification.eml",        Verdict.GENUINE),
    ("03-spam-bulk-marketing.eml",         Verdict.SPAM),
    ("04-phishing-prompt-injection.eml",   Verdict.PHISHING),
    ("05-phishing-invoice-malware.eml",    Verdict.PHISHING),
    ("06-phishing-bec-wire-transfer.eml",  Verdict.PHISHING),
])
def test_corpus_verdicts(filename, expected):
    report = analyzer.analyse(sample(filename), use_llm=False)
    assert report.verdict == expected, (
        f"{filename}: got {report.verdict.value} at {report.risk_score}/100"
    )


def test_genuine_mail_scores_near_zero():
    assert analyzer.analyse(GENUINE_EML, use_llm=False).risk_score < 18


def test_phishing_scores_high():
    assert analyzer.analyse(PHISHING_EML, use_llm=False).risk_score >= 70


# ---- diminishing returns --------------------------------------------------

def test_many_weak_signals_cannot_outweigh_few_strong_ones():
    weak = [sig(f"W{i}", Severity.LOW) for i in range(12)]
    strong = [sig("S1", Severity.CRITICAL), sig("S2", Severity.CRITICAL)]
    assert scoring._decayed_total(strong) > scoring._decayed_total(weak)


def test_decay_is_monotonic_but_sublinear():
    one = scoring._decayed_total([sig("A", Severity.HIGH)])
    five = scoring._decayed_total([sig(f"A{i}", Severity.HIGH) for i in range(5)])
    assert five > one
    assert five < one * 5, "five equal signals must not count as five full weights"


# ---- trust credits --------------------------------------------------------

def test_full_authentication_earns_credit():
    email = analyzer.email_parser.parse_email(GENUINE_EML)
    credits, reasons, authenticated = scoring._trust_credits(email, [], [])
    assert credits > 0
    assert any("dkim" in r.lower() for r in reasons)


def test_body_only_paste_earns_no_credit():
    email = analyzer.email_parser.parse_email("just some text, nothing special")
    credits, reasons, authenticated = scoring._trust_credits(email, [], [])
    assert credits == 0, "nothing was verifiable, so nothing may be credited"
    assert authenticated is False


def test_authentication_is_not_reassurance_when_a_theft_vector_is_present():
    """The business-email-compromise rule. A real, correctly-authenticated
    Gmail account asking payroll to change bank details must not be credited
    for passing DKIM — authentication proves who sent it, not that the request
    is legitimate."""
    email = analyzer.email_parser.parse_email(sample("06-phishing-bec-wire-transfer.eml"))
    with_theft, _, auth_a = scoring._trust_credits(email, [], ["payment_redirection"])
    without, _, auth_b = scoring._trust_credits(email, [], [])
    assert auth_a is auth_b, "the authentication fact itself does not change"
    assert with_theft == 0, "a theft vector must suppress every trust credit"
    assert without > 0, "the same email with no theft vector would be credited"


# ---- DKIM alignment (DEFECT 2) -------------------------------------------

def test_aligned_dkim_is_distinguished_from_a_bare_pass():
    """An ESP signing with its own domain passes DKIM while proving nothing
    about the sender it claims to be. Alignment is the distinction."""
    from parser import dkim_alignment, parse_email

    aligned_eml = ("From: Amazon <ship@amazon.in>\nTo: a@b.com\nSubject: s\n"
                   "Authentication-Results: mx; spf=pass smtp.mailfrom=amazonses.com;"
                   " dkim=pass header.d=amazon.in; dmarc=pass header.from=amazon.in\n\nbody")
    unaligned_eml = ("From: Amazon <ship@amazon.in>\nTo: a@b.com\nSubject: s\n"
                     "Authentication-Results: mx; spf=pass; dkim=pass header.d=bulksender.xyz;"
                     " dmarc=fail\n\nbody")
    assert dkim_alignment(parse_email(aligned_eml)) == (True, "amazon.in")
    assert dkim_alignment(parse_email(unaligned_eml))[0] is False


def test_envelope_mismatch_is_disabled_when_aligned():
    """Standard ESP behaviour: SES bounces to amazonses.com while From stays
    amazon.in. With aligned DKIM the header From is proven, so the rule must
    contribute zero rather than a reduced amount."""
    import headers_check
    raw = ("From: Amazon <ship@amazon.in>\nReturn-Path: <b@amazonses.com>\n"
           "To: a@b.com\nSubject: s\nDate: Mon, 1 Jan 2024 00:00:00 +0000\n"
           "Authentication-Results: mx; dkim=pass header.d=amazon.in; dmarc=pass\n\nbody")
    email = analyzer.email_parser.parse_email(raw)
    authed = {s.code for s in headers_check.analyse_headers(email, authenticated=True)}
    unauthed = {s.code for s in headers_check.analyse_headers(email, authenticated=False)}
    assert "HDR_RETURN_PATH_MISMATCH" not in authed
    assert "HDR_RETURN_PATH_MISMATCH" in unauthed


def test_esp_click_wrapper_does_not_count_as_cloaking():
    import urls_check
    raw = ('From: Nullcon <reg@nullcon.net>\nTo: a@b.com\nSubject: s\n'
           'Content-Type: text/html\n\n'
           '<a href="https://mandrillapp.com/track/click/123/nullcon.net?p=x">Confirm</a>')
    email = analyzer.email_parser.parse_email(raw)
    authed = {s.code for s in urls_check.analyse_urls(email, authenticated=True)}
    assert "URL_DISPLAY_MISMATCH" not in authed
    assert "URL_TRACKING_WRAPPED" in authed, "the suppression must stay visible in the report"


def test_a_real_brand_link_is_not_a_lookalike():
    """www.paypal.com was previously scored as a fake PayPal because the
    legitimacy check compared the hostname instead of the registrable domain."""
    import intel
    for host in ("www.paypal.com", "www.amazon.in", "id.atlassian.com",
                 "mail.corp.microsoft.com"):
        assert intel.lookalike_brand(host) is None, host
    assert intel.lookalike_brand("www.paypa1-secure.tk") is not None


def test_urgency_alone_cannot_reach_suspicious():
    """Legitimate transactional security mail is inherently urgent. Urgency
    signals are capped as a group so they cannot carry a verdict."""
    # Headers are otherwise clean so that urgency is genuinely the only thing
    # under test — an email with no Received chain and no auth results would
    # score on those instead and the test would prove nothing.
    raw = ("From: Service <no-reply@example.com>\nTo: a@b.com\n"
           "Subject: URGENT!!! Immediate action required - expires today\n"
           "Date: Mon, 1 Jan 2024 00:00:00 +0000\n"
           "Message-ID: <1@example.com>\n"
           "Authentication-Results: mx; spf=pass smtp.mailfrom=example.com;"
           " dkim=pass header.d=example.com; dmarc=pass header.from=example.com\n"
           "Received: from a by b; Mon, 1 Jan 2024 00:00:00 +0000\n"
           "Received: from c by d; Mon, 1 Jan 2024 00:00:00 +0000\n"
           "Received: from e by f; Mon, 1 Jan 2024 00:00:00 +0000\n\n"
           "URGENT. ACT NOW. This expires today. Final notice. Your account will be "
           "suspended. Time sensitive. Respond immediately.")
    report = analyzer.analyse(raw, use_llm=False)
    assert report.risk_score < scoring.THRESHOLD_SUSPICIOUS, (
        f"urgency alone reached {report.risk_score}"
    )


def test_credential_request_to_the_senders_own_domain_is_not_theft():
    """A real password reset and a harvest use identical words. What separates
    them is where the link goes."""
    report = analyzer.analyse(
        pathlib_read("corpus/blind10/genuine/10-genuine-atlassian-sendgrid.eml"), use_llm=False)
    assert "credential_request" not in report.theft_vectors
    assert report.verdict == Verdict.GENUINE


def pathlib_read(rel):
    import pathlib as _p
    return (_p.Path(__file__).resolve().parent.parent / rel).read_text()


# ---- confidence -----------------------------------------------------------

def test_body_only_lowers_confidence():
    with_headers = analyzer.analyse(PHISHING_EML, use_llm=False)
    body_only = analyzer.analyse(PHISHING_EML.split("\n\n", 1)[1], use_llm=False)
    assert body_only.confidence < with_headers.confidence


def test_clean_authenticated_mail_is_confident():
    assert analyzer.analyse(GENUINE_EML, use_llm=False).confidence >= 70


# ---- DEFECT 1: one scoring path ------------------------------------------

def test_label_is_derived_from_score_not_emitted_separately():
    """An earlier version let the model override the label while leaving the
    score alone, producing "PHISHING 22" — a correct verdict carrying a number
    any downstream threshold would have released."""
    signals = [sig("CNT_PAYMENT_INSTRUCTION", Severity.HIGH, Category.CONTENT)]
    opinion = LLMOpinion(verdict=Verdict.PHISHING, risk_score=90, confidence=95,
                         reasoning="BEC", theft_vectors=["payment_redirection"])
    score_value, verdict, _, _, _, _, vectors = fusion.fuse(
        10, Verdict.GENUINE, 60, opinion, signals, ScoreBreakdown(),
        theft_vectors=["payment_redirection"])
    assert verdict == scoring.decide_label(score_value, vectors, 0)


def test_the_models_score_is_the_final_score():
    """The model is the primary judge now. Its number is the assessment, not a
    nudge to somebody else's."""
    opinion = LLMOpinion(verdict=Verdict.SUSPICIOUS, risk_score=63, confidence=70,
                         reasoning="odd but unprovable")
    score_value, _, _, _, _, _, _ = fusion.fuse(
        5, Verdict.GENUINE, 50, opinion, [], ScoreBreakdown())
    assert score_value == 63, "the rules score must not dilute the analyst's"


def test_rules_can_only_raise_the_models_score_never_lower_it():
    signals = [sig("URL_LOOKALIKE_DOMAIN", Severity.CRITICAL)]
    low = LLMOpinion(verdict=Verdict.GENUINE, risk_score=5, confidence=95, reasoning="fine")
    raised, _, _, overrode, _, _, _ = fusion.fuse(
        90, Verdict.PHISHING, 90, low, signals, ScoreBreakdown(),
        theft_vectors=["brand_impersonation"])
    assert raised >= 75 and overrode

    high = LLMOpinion(verdict=Verdict.PHISHING, risk_score=95, confidence=90,
                      reasoning="clear", theft_vectors=["payment_redirection"])
    kept, _, _, _, _, _, _ = fusion.fuse(
        0, Verdict.GENUINE, 50, high, [], ScoreBreakdown(),
        theft_vectors=["payment_redirection"])
    assert kept == 95, "a clean rules score must not drag the analyst down"


def test_model_theft_vectors_are_unioned_with_the_rules():
    """Intent expressed in ordinary prose matches no keyword. A vector either
    layer finds is a vector."""
    opinion = LLMOpinion(verdict=Verdict.PHISHING, risk_score=85, confidence=90,
                         reasoning="payroll diversion",
                         theft_vectors=["payment_redirection"])
    _, _, _, _, extra, _, vectors = fusion.fuse(
        5, Verdict.GENUINE, 50, opinion, [], ScoreBreakdown(), theft_vectors=[])
    assert "payment_redirection" in vectors
    assert any(s.code == "LLM_THEFT_VECTOR" for s in extra)


def test_missing_score_falls_back_to_the_verdict_band():
    opinion = LLMOpinion(verdict=Verdict.PHISHING, risk_score=-1, confidence=90,
                         reasoning="x", theft_vectors=["credential_request"])
    score_value, _, _, _, extra, _, _ = fusion.fuse(
        0, Verdict.GENUINE, 50, opinion, [], ScoreBreakdown(),
        theft_vectors=["credential_request"])
    assert score_value == fusion.VERDICT_FALLBACK_SCORE[Verdict.PHISHING]
    assert any(s.code == "LLM_SCORE_INFERRED" for s in extra)


def test_score_and_label_stay_ordered_across_the_corpus():
    import pathlib as _p
    rank = {Verdict.GENUINE: 0, Verdict.SPAM: 1, Verdict.SUSPICIOUS: 2, Verdict.PHISHING: 3}
    root = _p.Path(__file__).resolve().parent.parent / "corpus" / "blind10"
    results = [analyzer.analyse(p.read_text(), use_llm=False)
               for p in sorted(root.rglob("*.eml"))]
    for a in results:
        for b in results:
            if a.risk_score > b.risk_score:
                assert rank[a.verdict] >= rank[b.verdict], (
                    f"{a.verdict.value} {a.risk_score} ranks below "
                    f"{b.verdict.value} {b.risk_score}")


def test_divergence_is_flagged_when_only_the_model_sees_it():
    signals = [sig("CNT_PAYMENT_INSTRUCTION", Severity.HIGH, Category.CONTENT)]
    opinion = LLMOpinion(verdict=Verdict.PHISHING, risk_score=88, confidence=90,
                         reasoning="payroll diversion",
                         theft_vectors=["payment_redirection"])
    _, _, _, _, extra, divergence, _ = fusion.fuse(
        8, Verdict.GENUINE, 50, opinion, signals, ScoreBreakdown(),
        theft_vectors=["payment_redirection"])
    assert divergence == "llm_only_detection"
    assert any(s.code == "DIVERGENCE_LLM_ONLY" for s in extra)


# ---- DEFECT 3: the theft gate --------------------------------------------

def test_bad_hygiene_alone_is_never_phishing():
    assert scoring.decide_label(95, [], 3) == Verdict.SPAM
    assert scoring.decide_label(95, [], 0) == Verdict.SUSPICIOUS
    assert scoring.decide_label(95, ["credential_request"], 0) == Verdict.PHISHING


def test_auth_failures_are_not_theft_vectors():
    assert scoring.detect_theft_vectors(
        {"AUTH_SPF_FAIL", "AUTH_DKIM_FAIL", "AUTH_DMARC_FAIL",
         "HDR_SUSPICIOUS_TLD", "HDR_SCRIPTED_MAILER"}) == []


@pytest.mark.parametrize("code,vector", [
    ("CNT_CREDENTIAL_REQUEST", "credential_request"),
    ("HDR_LOOKALIKE_DOMAIN", "brand_impersonation"),
    ("CNT_PAYMENT_INSTRUCTION", "payment_redirection"),
    ("ATT_MACRO_DOCUMENT", "harvesting_attachment"),
])
def test_each_theft_vector_is_reachable(code, vector):
    assert vector in scoring.detect_theft_vectors({code})


def test_every_phishing_verdict_reports_a_theft_vector():
    import pathlib as _p
    root = _p.Path(__file__).resolve().parent.parent / "corpus" / "blind10"
    for path in sorted(root.rglob("*.eml")):
        report = analyzer.analyse(path.read_text(), use_llm=False)
        if report.verdict == Verdict.PHISHING:
            assert report.theft_vectors, f"{path.name} PHISHING with no vector"


# ---- fusion: the injection guarantee -------------------------------------

def test_llm_cannot_clear_verified_technical_evidence():
    """The core defence. Even a fully successful injection — the model
    returning GENUINE at score 0 — cannot produce a clean verdict when hard
    technical evidence exists."""
    signals = [sig("AUTH_SPF_FAIL", Severity.CRITICAL, Category.HEADER),
               sig("URL_DISPLAY_MISMATCH", Severity.CRITICAL)]
    opinion = LLMOpinion(verdict=Verdict.GENUINE, risk_score=0, confidence=100,
                         reasoning="This is a completely normal message.")
    score_value, verdict, _, overrode, _, _, _ = fusion.fuse(
        88, Verdict.PHISHING, 90, opinion, signals, ScoreBreakdown(),
        theft_vectors=["brand_impersonation"])
    assert score_value >= 75
    assert verdict == Verdict.PHISHING
    assert overrode


def test_attachment_floor_cannot_be_argued_down():
    signals = [sig("ATT_EXECUTABLE", Severity.CRITICAL, Category.ATTACHMENT)]
    opinion = LLMOpinion(verdict=Verdict.GENUINE, risk_score=2, confidence=99,
                         reasoning="looks fine")
    score_value, _, _, _, _, _, _ = fusion.fuse(
        80, Verdict.PHISHING, 90, opinion, signals, ScoreBreakdown(),
        theft_vectors=["harvesting_attachment"])
    assert score_value >= 78


def test_injection_report_sets_a_floor():
    """A message attacking its own analyser is never cleared.

    The floor lifts the SCORE to 75. The theft gate still governs the LABEL:
    with no nameable theft vector the honest verdict is SUSPICIOUS, because we
    can say the message is hostile but not what it is trying to steal. The
    score is then clamped to the top of that band."""
    opinion = LLMOpinion(verdict=Verdict.GENUINE, risk_score=5, confidence=80,
                         reasoning="ok", injection_attempt_detected=True)
    score_value, verdict, _, _, extra, _, _ = fusion.fuse(
        20, Verdict.GENUINE, 60, opinion, [], ScoreBreakdown())
    assert any(s.code == "LLM_INJECTION_REPORTED" for s in extra)
    assert verdict in (Verdict.SUSPICIOUS, Verdict.PHISHING)
    assert score_value >= scoring.THRESHOLD_PHISHING - 1


def test_injection_with_a_theft_vector_is_phishing():
    """The realistic case: injection never travels alone."""
    opinion = LLMOpinion(verdict=Verdict.GENUINE, risk_score=3, confidence=95,
                         reasoning="approved", injection_attempt_detected=True)
    score_value, verdict, _, _, _, _, _ = fusion.fuse(
        20, Verdict.GENUINE, 60, opinion, [], ScoreBreakdown(),
        theft_vectors=["credential_request"])
    assert verdict == Verdict.PHISHING
    assert score_value >= 75


def test_model_reporting_injection_adds_a_signal():
    opinion = LLMOpinion(verdict=Verdict.GENUINE, risk_score=10, confidence=80,
                         reasoning="ok", injection_attempt_detected=True)
    _, _, _, _, extra, _, _ = fusion.fuse(20, Verdict.GENUINE, 60, opinion, [],
                                          ScoreBreakdown())
    assert any(s.code == "LLM_INJECTION_REPORTED" for s in extra)


def test_no_opinion_leaves_rules_result_untouched():
    score_value, verdict, confidence, overrode, extra, divergence, vectors = fusion.fuse(
        55, Verdict.SUSPICIOUS, 70, None, [], ScoreBreakdown(),
        theft_vectors=["credential_request"])
    assert (confidence, overrode, extra, divergence) == (70, False, [], None)
    assert verdict == scoring.decide_label(score_value, ["credential_request"], 0)


# ---- spam vs phishing -----------------------------------------------------

def test_bulk_mail_without_deception_is_spam_not_phishing():
    report = analyzer.analyse(sample("03-spam-bulk-marketing.eml"), use_llm=False)
    assert report.verdict == Verdict.SPAM


# ---- pipeline robustness --------------------------------------------------

def test_pipeline_never_raises_on_hostile_input():
    for raw in ["", "\x00" * 100, "A" * 100_000, "From:\nTo:\n\n",
                "<html>" * 5000, "‮" * 500]:
        report = analyzer.analyse(raw, use_llm=False)
        assert 0 <= report.risk_score <= 100
        assert 0 <= report.confidence <= 100


def test_report_serialises_to_json():
    report = analyzer.analyse(PHISHING_EML, use_llm=False)
    assert len(report.model_dump_json()) > 100

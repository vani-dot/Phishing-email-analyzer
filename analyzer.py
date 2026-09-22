# analyzer.py
# The pipeline. Everything else in this project is a component; this is the
# order they run in and the one place a caller needs.
#
#   raw text
#      -> parser            structure
#      -> rule modules      evidence (offline, deterministic)
#      -> netcheck          enrichment (optional, opt-in, SSRF-guarded)
#      -> scoring           evidence -> score + verdict + written assessment
#      -> llm               language reading (optional, needs a key)
#      -> fusion            combine, with technical evidence taking precedence
#      -> Report
#
# The pipeline is complete and useful at the scoring step. The two layers after
# it are enrichment: with no API key and no network the analyser still produces
# a full, explainable, reproducible verdict, which is what makes the result
# defensible and the evaluation numbers stable.

import time
from typing import List, Optional

import attachments_check
import content_check
import fusion
import headers_check
import llm as llm_module
import netcheck
import parser as email_parser
import scoring
import urls_check
from config import config
from models import Category, Report, Severity, Signal


def analyse(raw_text: str, source: str = "paste", filename: Optional[str] = None,
            use_llm: bool = True, use_network: bool = False) -> Report:
    """Run the full pipeline. Never raises on hostile input."""
    started = time.monotonic()

    email = email_parser.parse_email(raw_text, filename=filename)

    # ---- deterministic evidence -----------------------------------------
    signals: List[Signal] = []
    # Each module is isolated: a crash inside one check must not lose the
    # findings of the others. A partial report with a note beats no report.
    # Established before the rules run: several of them are disabled rather
    # than down-weighted when the sender is cryptographically authenticated,
    # because the behaviour they describe (envelope mismatch, click-tracking
    # redirects) is standard for mail sent through a commercial provider.
    authenticated, signing_domain = email_parser.dkim_alignment(email)
    authenticated = authenticated and "dmarc=pass" in (email.auth_results or "").lower()

    for name, func in (
        ("header", lambda e: headers_check.analyse_headers(e, authenticated)),
        ("url", lambda e: urls_check.analyse_urls(e, authenticated)),
        ("content", lambda e: content_check.analyse_content(e, authenticated)),
        ("attachment", attachments_check.analyse_attachments),
    ):
        try:
            signals.extend(func(email))
        except Exception as exc:  # noqa: BLE001 - deliberately broad
            signals.append(Signal(
                code=f"ERR_{name.upper()}_CHECK",
                title=f"The {name} checks did not complete",
                category=Category.CONTENT, severity=Severity.INFO,
                detail=f"An internal error occurred during {name} analysis "
                       f"({type(exc).__name__}). Other checks completed normally, but "
                       f"this report is incomplete.",
            ))

    # ---- optional network enrichment ------------------------------------
    if use_network and config.ENABLE_URL_EXPANSION and email.links:
        signals.extend(_expand_links(email))

    # ---- score -----------------------------------------------------------
    (breakdown, verdict, confidence, assessment, derived,
     theft_vectors, spam_markers, authenticated) = scoring.score(email, signals)
    signals.extend(derived)

    # ---- optional language layer ----------------------------------------
    opinion = None
    llm_status = "disabled"
    trail = []
    if use_llm and config.llm_configured and config.AGENT_MODE:
        # Agent mode: the model investigates with tools. It is given a thin
        # index card and has to go looking, which is what lets it find things
        # the rules were never written to catch.
        import agent as agent_module
        opinion, llm_status, trail = agent_module.investigate(email, authenticated)
    elif use_llm and config.llm_configured:
        # The model is shown only the deterministic findings, not the
        # correlations or trust credits — those are conclusions, and anchoring
        # it on our conclusion defeats the point of a second opinion.
        primary = [s for s in signals if not s.code.startswith(("CORR_", "TRUST_"))]
        opinion, llm_status = llm_module.analyse_with_llm(
            email, primary, authenticated=authenticated, theft_vectors=theft_vectors)
    if trail:
        signals.append(Signal(
            code="AGENT_INVESTIGATION",
            title=f"Agent ran {len([t for t in trail if t['tool'] != 'submit_assessment'])} "
                  f"investigative checks",
            category=Category.LLM, severity=Severity.INFO,
            detail="The analyst gathered its own evidence rather than being handed a "
                   "summary: " + ", ".join(
                       t["tool"] for t in trail if t["tool"] != "submit_assessment") + ".",
        ))

    (final_score, final_verdict, final_confidence, overrode, extra,
     divergence, theft_vectors) = fusion.fuse(
        breakdown.rules_score, verdict, confidence, opinion, signals, breakdown,
        theft_vectors=theft_vectors, spam_markers=spam_markers,
        authenticated=authenticated,
    )
    signals.extend(extra)

    if opinion is not None and opinion.reasoning:
        assessment += (
            f" Language assessment: {opinion.reasoning.strip()[:400]}"
        )

    signals.sort(key=lambda s: (-s.points, s.category.value, s.code))

    return Report(
        verdict=final_verdict,
        risk_score=final_score,
        confidence=final_confidence,
        summary=assessment,
        signals=signals,
        breakdown=breakdown,
        email=email,
        llm=opinion,
        llm_status=llm_status,
        authenticated_sender=authenticated,
        theft_vectors=theft_vectors,
        divergence=divergence,
        investigation=trail,
        rules_overrode_llm=overrode,
        duration_ms=int((time.monotonic() - started) * 1000),
        source=source,
        filename=filename,
    )


def _expand_links(email) -> List[Signal]:
    """Follow redirect chains for the most suspicious links only.

    Bounded by config, and every hop passes the SSRF guard in netcheck. Only
    shortened or otherwise opaque links are worth the outbound request — there
    is no value in resolving a link whose destination is already visible.
    """
    import intel

    signals: List[Signal] = []
    candidates = [
        l for l in email.links
        if l.registered_domain in intel.URL_SHORTENERS
        or l.is_mismatch
        or (l.registered_domain and l.registered_domain.rsplit(".", 1)[-1] in intel.SUSPICIOUS_TLDS)
    ][: config.URL_EXPANSION_MAX_URLS]

    for link in candidates:
        chain, status = netcheck.expand_redirects(link.url)
        if not chain:
            if status.startswith("blocked"):
                signals.append(Signal(
                    code="NET_EXPANSION_BLOCKED",
                    title="Redirect expansion stopped by the SSRF guard",
                    category=Category.URL, severity=Severity.HIGH,
                    detail=f"Following '{link.url[:100]}' was refused: {status}. A link in "
                           f"an email resolving to non-public address space is either a "
                           f"leaked internal reference or an attempt to use this analyser "
                           f"as a proxy into its own network.",
                    evidence=f"{link.url[:120]} — {status}",
                ))
            continue

        link.redirect_chain = chain[:10]
        final = chain[-1]
        final_domain = email_parser.domain_of("x@" + (
            __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(final).hostname or ""
        ))

        if len(chain) >= 3:
            signals.append(Signal(
                code="NET_LONG_REDIRECT_CHAIN",
                title=f"Link passes through {len(chain)} redirects",
                category=Category.URL, severity=Severity.MEDIUM,
                detail=f"'{link.url[:80]}' hops {len(chain)} times before landing on "
                       f"'{final[:80]}'. Chains this long are used to break referrer "
                       f"tracking and to keep the final destination out of any scan that "
                       f"only inspects the link as written.",
                evidence=" -> ".join(c[:60] for c in chain[:5]),
            ))

        lookalike = intel.lookalike_brand(final_domain)
        if lookalike:
            brand, legit, score_value = lookalike
            signals.append(Signal(
                code="NET_REDIRECT_TO_LOOKALIKE",
                title="Redirect chain ends at a lookalike domain",
                category=Category.URL, severity=Severity.CRITICAL,
                detail=f"After {len(chain)} redirect(s) the link arrives at "
                       f"'{final_domain}', which imitates '{legit}' ({brand.title()}). The "
                       f"link as written in the email reveals none of this.",
                evidence=f"{link.url[:80]} -> {final[:100]}",
            ))

    return signals

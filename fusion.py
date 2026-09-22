# fusion.py
# Combines the deterministic score with the model's opinion.
#
# TWO RULES THIS FILE EXISTS TO ENFORCE:
#
#   1. ONE SCORING PATH. Whoever produces the score produces the label. The
#      label is always decide_label(final_score, ...) — never emitted
#      separately by anything. An earlier version let the model override the
#      label while leaving the number alone, which produced "PHISHING 22": a
#      correct verdict carrying a score any downstream threshold would have
#      released.
#
#   2. THE MODEL IS THE PRIMARY JUDGE; THE RULES ARE THE FLOOR.
#      The model's score is taken as the assessment. The rules engine can only
#      RAISE it, never lower it, and only on conclusive technical evidence.
#
#      This inverts the earlier design, and the reason is measurement: with the
#      model contributing a +/-15 weight to a rules score, it changed the
#      verdict in 0 of 10 cases. The rules decided everything, and hand-written
#      rules tuned on a small corpus do not generalise — they scored 10/10 on
#      the set they were tuned against and 1/5 on unseen mail.
#
#      A language model reasoning from the same evidence generalises far
#      better. So it judges, and the rules do the two things it cannot: supply
#      facts it has no way to compute (DKIM alignment, magic bytes, homoglyph
#      distance), and hold a floor that no amount of persuasive text can argue
#      below. An attacker who fully compromises the model's judgement still
#      cannot get a clean verdict past verified technical evidence.
#
# The asymmetry is the whole point. If the model spots a pretext the rules
# missed, that is new information and the score should move. If the model says
# a message is fine, that is an opinion about language which cannot overturn a
# server-stamped SPF failure or an attached executable — and treating it as
# though it could is precisely what a prompt-injection payload is trying to
# achieve. An attacker who fully compromises the model's judgement still cannot
# get a clean verdict out of this function.

from typing import List, Optional, Tuple

from models import (Category, LLMOpinion, ScoreBreakdown, Severity, Signal,
                    Verdict)

# Fallback weights, used only when the model returns a verdict without a
# usable score. Normal operation takes the model's own risk_score.
VERDICT_FALLBACK_SCORE = {
    Verdict.PHISHING: 85,
    Verdict.SUSPICIOUS: 60,
    Verdict.SPAM: 35,
    Verdict.GENUINE: 8,
}

HIGH_CONFIDENCE = 70

# Below this rule score, a model phishing verdict means the deterministic layer
# found essentially nothing — the business email compromise shape.
DIVERGENCE_RULE_SCORE = 20

# Technical findings no amount of reassuring prose can clear. These are floors
# on the FINAL score: the model may score above them, never below.
HARD_EVIDENCE_FLOORS = {
    "AUTH_SPF_FAIL": 55,
    "AUTH_DKIM_FAIL": 50,
    "AUTH_DMARC_FAIL": 55,
    "ATT_EXECUTABLE": 78,
    "ATT_HIDDEN_EXECUTABLE": 80,
    "ATT_DOUBLE_EXTENSION": 78,
    "ATT_RLO_FILENAME": 78,
    "ATT_SHORTCUT": 75,
    "ATT_DISK_IMAGE": 72,
    # Deception by construction — there is no innocent reading of mislabelling
    # a link with someone else's domain, or registering a homoglyph of a bank.
    "URL_DISPLAY_MISMATCH": 75,
    "URL_USERINFO_TRICK": 75,
    "URL_LOOKALIKE_DOMAIN": 75,
    "HDR_LOOKALIKE_DOMAIN": 75,
    "HDR_MIXED_SCRIPT_DOMAIN": 75,
    "HDR_DISPLAY_NAME_SPOOF": 75,
    "CNT_EMBEDDED_FORM": 75,
    "CNT_PROMPT_INJECTION": 75,
    "CNT_REPLY_WITH_SECRET": 75,
    "CNT_GIFT_CARD_REQUEST": 78,
}

VERDICT_RANK = {
    Verdict.GENUINE: 0,
    Verdict.SPAM: 1,
    Verdict.SUSPICIOUS: 2,
    Verdict.PHISHING: 3,
}


def fuse(rules_score: int, rules_verdict: Verdict, rules_confidence: int,
         opinion: Optional[LLMOpinion], signals: List[Signal],
         breakdown: ScoreBreakdown, theft_vectors: Optional[List[str]] = None,
         spam_markers: int = 0, authenticated: bool = False
         ) -> Tuple[int, Verdict, int, bool, List[Signal], Optional[str], List[str]]:
    """Combine the analyst's assessment with the rules engine's floor.

    Returns:
        score           0-100, the model's assessment raised to any floor
        verdict         from decide_label(score, ...), never emitted separately
        confidence      adjusted for agreement between the two layers
        rules_overrode  True when a floor lifted the model's score
        extra_signals   findings produced by this step
        divergence      "llm_only_detection" when only the model saw the attack
        theft_vectors   the union of rules-detected and model-identified
    """
    from scoring import clamp_score_to_label, decide_label

    theft_vectors = list(theft_vectors or [])
    extra: List[Signal] = []
    codes = {s.code for s in signals}
    divergence = None

    if opinion is None:
        # No model: the rules engine stands alone. Same label function, so the
        # two paths agree by construction.
        verdict = decide_label(rules_score, theft_vectors, spam_markers)
        final = clamp_score_to_label(rules_score, verdict)
        breakdown.final_score = final
        return final, verdict, rules_confidence, False, extra, None, theft_vectors

    floor = max((v for k, v in HARD_EVIDENCE_FLOORS.items() if k in codes), default=0)

    if opinion.injection_attempt_detected and "CNT_PROMPT_INJECTION" not in codes:
        extra.append(Signal(
            code="LLM_INJECTION_REPORTED",
            title="Analyser reported an attempt to manipulate it",
            category=Category.LLM, severity=Severity.CRITICAL,
            detail="The analyst reported that the message contained text directed at "
                   "it rather than at the human recipient. An email attempting to "
                   "influence the tool inspecting it is hostile by construction.",
        ))
        floor = max(floor, 75)

    # The model can name theft vectors the rules cannot see — a payroll
    # diversion in plain business English matches no keyword. Union, never
    # replace: a vector either layer found is a vector.
    model_vectors = [v for v in opinion.theft_vectors if v not in theft_vectors]
    if model_vectors:
        theft_vectors = sorted(set(theft_vectors) | set(opinion.theft_vectors))
        extra.append(Signal(
            code="LLM_THEFT_VECTOR",
            title=f"Analyst identified: {', '.join(v.replace('_', ' ') for v in model_vectors)}",
            category=Category.LLM, severity=Severity.HIGH,
            detail=f"The language analysis identified theft intent the deterministic "
                   f"checks did not match: {', '.join(model_vectors)}. Intent expressed "
                   f"in ordinary prose has no keyword to trigger on, which is exactly "
                   f"the gap this layer exists to close.",
            evidence=opinion.reasoning[:200] if opinion.reasoning else None,
        ))

    # ---- the model's score IS the assessment ----------------------------
    model_score = opinion.risk_score
    if model_score is None or model_score < 0:
        model_score = VERDICT_FALLBACK_SCORE.get(opinion.verdict, 50)
        extra.append(Signal(
            code="LLM_SCORE_INFERRED", title="Score inferred from the analyst's verdict",
            category=Category.LLM, severity=Severity.INFO,
            detail=f"The model returned {opinion.verdict.value} without a usable score, "
                   f"so {model_score} was taken from the band that verdict occupies.",
        ))

    if (opinion.verdict == Verdict.PHISHING
            and opinion.confidence >= HIGH_CONFIDENCE
            and rules_score < DIVERGENCE_RULE_SCORE):
        divergence = "llm_only_detection"
        extra.append(Signal(
            code="DIVERGENCE_LLM_ONLY",
            title="Attack identified by language analysis alone",
            category=Category.LLM, severity=Severity.HIGH,
            detail=(
                f"The deterministic checks scored this {rules_score}/100 — they found "
                f"almost nothing, because the sender authenticates correctly and the "
                f"message carries no links, attachments or lookalike domains. The "
                f"analyst identified an attack anyway. This is the business email "
                f"compromise shape: a genuine mailbox making an illegitimate request, "
                f"where there is no technical artefact to catch."
            ),
            evidence=opinion.reasoning[:200] if opinion.reasoning else None,
        ))

    final_score = max(0, min(100, model_score))

    overrode = False
    if final_score < floor:
        final_score = floor
        overrode = True
        blocking = sorted(k for k in HARD_EVIDENCE_FLOORS if k in codes)
        extra.append(Signal(
            code="FUSION_FLOOR_APPLIED",
            title="Analyst's score raised by verified technical evidence",
            category=Category.LLM, severity=Severity.HIGH,
            detail=(
                f"The analyst scored this {model_score}/100, but verified technical "
                f"findings ({', '.join(blocking[:4])}) do not permit a score below "
                f"{floor}. Deterministic evidence takes precedence over a reading of "
                f"the language — this is the control that stops a message talking its "
                f"own analyser into clearing it."
            ),
            evidence=", ".join(blocking[:6]),
        ))

    if opinion.reasoning:
        extra.append(Signal(
            code="LLM_ASSESSMENT", title=f"Analyst assessment: {opinion.verdict.value}",
            category=Category.LLM,
            severity=Severity.INFO if opinion.verdict == Verdict.GENUINE else Severity.MEDIUM,
            detail=opinion.reasoning[:600],
            evidence=", ".join(opinion.social_engineering_tactics[:5]) or None,
        ))
    if opinion.counter_argument:
        extra.append(Signal(
            code="LLM_COUNTER_ARGUMENT", title="The case against this verdict",
            category=Category.LLM, severity=Severity.INFO,
            detail=opinion.counter_argument[:400],
        ))

    # THE LABEL. Derived from the final score and the theft gate, nothing else.
    final_verdict = decide_label(final_score, theft_vectors, spam_markers,
                                 analyst_says_spam=(opinion.verdict == Verdict.SPAM))
    final_score = clamp_score_to_label(final_score, final_verdict)

    confidence = opinion.confidence
    if opinion.verdict == final_verdict:
        confidence = min(98, confidence + 8)
    elif abs(VERDICT_RANK[opinion.verdict] - VERDICT_RANK[final_verdict]) >= 2:
        confidence = max(15, confidence - 15)
    # Agreement between two independent methods is genuine corroboration.
    if opinion.verdict == rules_verdict:
        confidence = min(98, confidence + 6)

    breakdown.final_score = final_score
    breakdown.llm_points = final_score - rules_score
    return (final_score, final_verdict, confidence, overrode, extra,
            divergence, theft_vectors)

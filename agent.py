# agent.py
# The investigating analyst.
#
# WHY THIS EXISTS
# The previous design handed the model one fixed summary and asked for a
# verdict. Measured across the test corpus, that model changed the outcome in
# ZERO cases — the hand-written rules decided everything, and hand-written
# rules tuned on a small corpus do not generalise. They scored 10/10 on the set
# they were tuned against and 1/5 on unseen mail.
#
# A fixed summary can only ever surface what its author thought to include.
# This agent instead starts from a deliberately thin brief and has to go
# looking: read the headers it cares about, decompose the links it finds
# suspicious, search the full body for a hypothesis it has formed, decode
# something that looks encoded. It follows the thread.
#
# What that buys is generalisation. The agent does not need me to have
# anticipated a technique — it needs to be able to ask the right question, and
# the tools let it ask.
#
# WHAT IS STILL DETERMINISTIC
#   * Every tool returns a fact computed by code, not by the model.
#   * Tool results carrying message content are sanitised on the way back in,
#     so read_body() is not a clean route around the injection defence.
#   * The rules engine still sets hard floors in fusion.py. An agent that is
#     talked into clearing a message cannot clear verified technical evidence.
#   * Turn and tool-call budgets are bounded, so a confused run costs a known
#     amount rather than an open one.

import json
import warnings
from typing import Any, Dict, List, Optional, Tuple

warnings.filterwarnings("ignore", message=".*OpenSSL.*")

import requests
from pydantic import ValidationError

from config import config
from llm import SYSTEM_PROMPT, _classify, sanitise_for_model
from models import LLMOpinion, ParsedEmail
from tools import Investigation

# Bounds. A determined investigation is worth paying for; an infinite one is
# not, and a model that has not reached a conclusion in eight rounds of
# evidence gathering is not going to.
MAX_TURNS = 8
MAX_TOOL_CALLS = 18
# An agent that answers from the index card is a classifier wearing a tool
# call. Observed directly: given a preview of the body, the model went straight
# to submit_assessment on turn one having looked at nothing. A floor on
# investigative calls forces it to actually check who sent the message and
# where the links go before it is allowed to conclude.
MIN_TOOL_CALLS = 3

INVESTIGATION_BRIEF = """
================================================================================
YOU ARE INVESTIGATING, NOT CLASSIFYING
================================================================================
You have not been given the message. You have been given a summary card and a
set of tools. Go and look at whatever you need.

Do not answer from the summary alone. The summary is what a previous version of
this system got wrong: it could only show what its author thought to include,
and it missed attacks nobody had anticipated. You can ask your own questions.

A competent investigation nearly always includes:
  - check_sender_alignment()   is this really from who it says?
  - list_links()               where do the links actually go?
  - inspect_url() / inspect_domain()  on anything that looks off
  - read_body()                read what it actually says
  - search_body()              test a specific hypothesis against the FULL text
  - inspect_attachments()      what are the files, by content not by name
  - compare_to_brand()         would this brand really send from here?
  - decode()                   anything base64, percent-encoded or punycode

Follow the thread. If the sender claims to be a bank, compare_to_brand. If a
link looks strange, inspect_url it. If the body mentions an account change,
search_body for the details. If something is encoded, decode it.

Stop investigating when you can answer these, and not before:
  1. Who does this claim to be from, and do the facts support that?
  2. What is it asking the reader to do?
  3. Where do the links actually go?
  4. Can you name a theft vector?

Then call submit_assessment exactly once. That is the only way to finish.
Do not write your conclusion as prose — it will be discarded.
"""


def _tool_specs() -> List[Dict[str, Any]]:
    def spec(name, description, properties=None, required=None):
        return {"type": "function", "function": {
            "name": name, "description": description,
            "parameters": {"type": "object",
                           "properties": properties or {},
                           "required": required or []}}}

    return [
        spec("check_sender_alignment",
             "Whether DKIM is aligned with the From domain and DMARC passed — "
             "cryptographic proof of who sent this. Always worth calling first."),
        spec("list_links",
             "Every link in the message with its real destination domain, the text "
             "shown to the reader, and whether it is the sender's own domain, a "
             "click tracker, a known brand, or a lookalike."),
        spec("read_headers",
             "Raw header values and the Received routing chain.",
             {"names": {"type": "array", "items": {"type": "string"},
                        "description": "Header names to fetch, e.g. ['reply-to','x-mailer']. "
                                       "Omit for a general dump."}}),
        spec("read_body",
             "Read a window of the message body. Use for long messages.",
             {"start": {"type": "integer", "description": "character offset, default 0"},
              "length": {"type": "integer", "description": "how many characters, max 4000"},
              "part": {"type": "string", "enum": ["text", "html"],
                       "description": "which part to read"}}),
        spec("search_body",
             "Search the FULL body for a word, phrase or pattern and return matches "
             "with surrounding context. Use this to test a hypothesis.",
             {"pattern": {"type": "string", "description": "what to look for"},
              "regex": {"type": "boolean", "description": "treat pattern as a regex"}},
             ["pattern"]),
        spec("inspect_domain",
             "Analyse a domain: registrable owner, TLD reputation, whether it is a "
             "genuine brand domain, lookalike similarity, mixed scripts, punycode, "
             "shortener, free webmail, or an email provider's click tracker.",
             {"domain": {"type": "string", "description": "domain or hostname"}},
             ["domain"]),
        spec("inspect_url",
             "Full decomposition of one URL: scheme, host, path, port, redirect "
             "parameters, the @ userinfo trick, encoding, whether the anchor text "
             "matches the destination, plus domain analysis.",
             {"url": {"type": "string", "description": "the URL to inspect"}},
             ["url"]),
        spec("compare_to_brand",
             "Would this brand legitimately send from this sender domain, and do any "
             "links point at the brand's real domains?",
             {"brand": {"type": "string", "description": "brand name, e.g. 'paypal'"}},
             ["brand"]),
        spec("inspect_attachments",
             "What the attached files actually are, identified by their file headers "
             "rather than their names. Flags double extensions and disguises."),
        spec("decode",
             "Decode base64, percent-encoding or punycode, and fold homoglyphs to "
             "their ASCII shape.",
             {"text": {"type": "string", "description": "the text to decode"},
              "method": {"type": "string", "enum": ["auto", "base64", "url", "punycode"]}},
             ["text"]),
        spec("lookup_dns",
             "Live DNS for a domain: MX, SPF, DMARC. A domain with no MX cannot "
             "receive replies. May be disabled by configuration.",
             {"domain": {"type": "string"}}, ["domain"]),
        spec("expand_url",
             "Follow a redirect chain to its real destination. May be disabled by "
             "configuration.",
             {"url": {"type": "string"}}, ["url"]),
        spec("submit_assessment",
             "Submit your final assessment. Call this exactly once, when your "
             "investigation is complete. This is the only way to finish.",
             {
                 "verdict": {"type": "string",
                             "enum": ["PHISHING", "SPAM", "SUSPICIOUS", "GENUINE"]},
                 "risk_score": {"type": "integer",
                                "description": "0-100, consistent with the verdict"},
                 "confidence": {"type": "integer", "description": "0-100"},
                 "theft_vectors": {"type": "array", "items": {"type": "string",
                     "enum": ["credential_request", "brand_impersonation",
                              "payment_redirection", "harvesting_attachment"]},
                     "description": "empty unless PHISHING or SUSPICIOUS"},
                 "social_engineering_tactics": {"type": "array",
                                                "items": {"type": "string"}},
                 "reasoning": {"type": "string",
                               "description": "3-5 sentences citing what you FOUND"},
                 "counter_argument": {"type": "string",
                                      "description": "the strongest case against your verdict"},
                 "injection_attempt_detected": {"type": "boolean"},
             },
             ["verdict", "risk_score", "confidence", "reasoning"]),
    ]


def _opening_brief(email: ParsedEmail, authenticated: bool) -> str:
    """A deliberately thin summary. Enough to orient, not enough to conclude."""
    lines = ["A message has been reported for analysis. Here is the index card.",
             "Investigate it with your tools before reaching any conclusion.", ""]
    if not email.headers_present:
        lines.append("HEADERS: none supplied — body only. Sender checks are unavailable.")
    else:
        lines.append(f"From   : {email.from_display or ''} <{email.from_address or 'unknown'}>")
        lines.append(f"To     : {(email.to or '(none)')[:120]}")
        lines.append(f"Sender authentication: "
                     f"{'VERIFIED (aligned DKIM + DMARC)' if authenticated else 'NOT verified'}")
    lines.append(f"Subject: {(email.subject or '(none)')[:200]}")
    lines.append(f"Links  : {len(email.links)}")
    lines.append(f"Attachments: {len(email.attachments)}")
    body_len = len(email.body_text or "")
    lines.append(f"Body   : {body_len:,} characters"
                 + (" (read it with read_body)" if body_len else " — empty"))
    # Deliberately NO body preview. A preview is enough for the model to
    # pattern-match a conclusion without looking at anything, which is the
    # behaviour this whole design exists to replace. If it wants to know what
    # the message says, it can call read_body.
    lines.append("")
    lines.append("You have not been shown the body. Use your tools.")
    lines.append(f"Begin. You must make at least {MIN_TOOL_CALLS} investigative tool "
                 f"calls before submit_assessment will be accepted.")
    return "\n".join(lines)


def _post(provider: Dict[str, Any], messages: List[Dict[str, Any]],
          tools: List[Dict[str, Any]]) -> Tuple[Optional[Dict], str]:
    try:
        response = requests.post(
            f"{provider['base_url']}/chat/completions",
            headers={"Authorization": f"Bearer {provider['key']}",
                     "Content-Type": "application/json"},
            json={"model": provider["model"], "messages": messages,
                  "tools": tools, "tool_choice": "auto",
                  # Zero, not 0.1. This feeds a security verdict, and at 0.1 the same
        # email could come back GENUINE on one run and SUSPICIOUS on the
        # next — observed directly across evaluation runs. A score that
        # moves between identical runs cannot be measured, defended, or
        # used to tell a real improvement from a lucky one.
        "temperature": 0, "max_tokens": 1400},
            timeout=config.LLM_TIMEOUT,
        )
    except requests.Timeout:
        return None, "timeout"
    except requests.RequestException:
        return None, "connection"
    if response.status_code != 200:
        reason = _classify(response.status_code)
        try:
            code = (response.json().get("error") or {}).get("code", "")
            if code in ("allowance_exhausted", "daily_limit_reached", "weekly_limit_reached"):
                reason = "quota"
            elif code == "model_not_in_plan":
                reason = "forbidden"
        except (ValueError, AttributeError):
            pass
        return None, reason
    try:
        return response.json()["choices"][0]["message"], "ok"
    except (ValueError, KeyError, IndexError, TypeError):
        return None, "invalid_response"


def _build_opinion(payload: Dict[str, Any]) -> Optional[LLMOpinion]:
    try:
        score = payload.get("risk_score", payload.get("score", -1))
        try:
            score = max(-1, min(100, int(score)))
        except (TypeError, ValueError):
            score = -1
        return LLMOpinion(
            verdict=str(payload.get("verdict", "SUSPICIOUS")).upper(),
            risk_score=score,
            confidence=max(0, min(100, int(payload.get("confidence", 50)))),
            reasoning=str(payload.get("reasoning", ""))[:1500],
            social_engineering_tactics=[str(t) for t in
                                        (payload.get("social_engineering_tactics") or [])][:10],
            theft_vectors=[str(t) for t in (payload.get("theft_vectors") or [])][:4],
            counter_argument=str(payload.get("counter_argument", ""))[:600],
            injection_attempt_detected=bool(payload.get("injection_attempt_detected", False)),
        )
    except (ValidationError, ValueError, TypeError):
        return None


def investigate(email: ParsedEmail, authenticated: bool = False
                ) -> Tuple[Optional[LLMOpinion], str, List[Dict[str, Any]]]:
    """Run the agent. Returns (opinion, status, investigation trail).

    Providers are tried in order; a failure part-way through one restarts the
    investigation on the next rather than resuming a half-finished
    conversation the other model never had.
    """
    providers = config.llm_providers
    if not config.LLM_ENABLED or not providers:
        return None, "disabled", []

    tools = _tool_specs()
    attempts = []

    for provider in providers:
        session = Investigation(email, authenticated)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT + INVESTIGATION_BRIEF},
            {"role": "user", "content": _opening_brief(email, authenticated)},
        ]
        calls_made = 0
        failure = None

        for _turn in range(MAX_TURNS):
            message, status = _post(provider, messages, tools)
            if message is None:
                failure = status
                break

            tool_calls = message.get("tool_calls") or []
            if not tool_calls:
                # The model answered in prose. Push it back to the tool.
                messages.append({"role": "assistant",
                                 "content": message.get("content") or ""})
                messages.append({"role": "user", "content":
                                 "You must finish by calling submit_assessment. "
                                 "Do that now with your conclusion."})
                continue

            messages.append({
                "role": "assistant",
                "content": message.get("content") or "",
                "tool_calls": tool_calls,
            })

            finished = None
            for call in tool_calls:
                function = call.get("function", {})
                name = function.get("name", "")
                try:
                    args = json.loads(function.get("arguments") or "{}")
                    if not isinstance(args, dict):
                        args = {}
                except json.JSONDecodeError:
                    args = {}

                if name == "submit_assessment":
                    if calls_made < MIN_TOOL_CALLS:
                        result = (
                            f"REJECTED: you have made {calls_made} investigative tool "
                            f"call(s). You must make at least {MIN_TOOL_CALLS} before "
                            f"submitting. You have not yet established who sent this, "
                            f"where its links go, or what it says. Investigate first — "
                            f"start with check_sender_alignment, list_links and read_body "
                            f"— then submit."
                        )
                        session.trail.append({"tool": "submit_assessment",
                                              "args": {}, "result": "rejected: too early"})
                    else:
                        session.trail.append({"tool": "submit_assessment",
                                              "args": {"verdict": args.get("verdict")},
                                              "result": "assessment submitted"})
                        finished = _build_opinion(args)
                        result = "Assessment recorded."
                elif calls_made >= MAX_TOOL_CALLS:
                    result = ("Tool budget exhausted. Call submit_assessment now "
                              "with your best conclusion from what you have found.")
                else:
                    calls_made += 1
                    result = session.dispatch(name, args)

                messages.append({"role": "tool",
                                 "tool_call_id": call.get("id", name),
                                 "name": name,
                                 "content": result})

            if finished is not None:
                label = provider["name"]
                if provider["role"] == "fallback" and attempts:
                    return finished, f"ok:{label} (fallback; {attempts[0]})", session.trail
                return finished, f"ok:{label}", session.trail
            submitted = any(c.get("function", {}).get("name") == "submit_assessment"
                            for c in tool_calls)
            if finished is None and submitted and calls_made >= MIN_TOOL_CALLS:
                failure = "invalid_assessment"
                break

        if failure is None:
            failure = "no_conclusion"
        attempts.append(f"{provider['name']}={failure}")
        if failure not in ("timeout", "connection", "rate_limited", "quota",
                           "server_error", "unauthorized", "forbidden",
                           "invalid_response", "no_conclusion", "invalid_assessment"):
            break

    return None, "error:" + ", ".join(attempts), []

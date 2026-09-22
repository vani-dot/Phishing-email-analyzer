# Phishing Email Analyzer — project guide for Claude Code

Analyses an email and returns PHISHING / SPAM / SUSPICIOUS / GENUINE, a 0-100 risk
score and a written explanation. FastAPI web app + CLI. Runs fully offline
(rules only); an LLM layer is optional.

## Commands
    pip install -r requirements.txt -r requirements-dev.txt
    python -m pytest tests/ -q                     # must stay green (297 tests)
    python regression.py                           # 10 emails, 5 acceptance criteria
    python evaluate.py corpus/eval50 --no-llm      # 50 labelled emails, confusion matrix
    # corpus/blind10 is regression.py's acceptance set (same 10 emails, thresholds
    # tuned to them), NOT a held-out evaluation set — never cite its accuracy as a metric.
    python main.py samples/01-phishing-credential-harvest.eml -v   # see the reasoning
    python app.py                                  # http://127.0.0.1:8000  (Vani / Vani)

## Pipeline (read in this order)
models.py (schemas) -> parser.py -> headers_check / urls_check / content_check /
attachments_check (each returns Signals) -> scoring.py (score + verdict) ->
llm.py / agent.py + tools.py (optional) -> fusion.py -> analyzer.py wires it together.

## Design rules — do not break these
1. Deterministic rules first, LLM second. The LLM may raise the score freely,
   lower it by at most 12, never below the floor set by verified technical findings.
2. A message is only PHISHING if it has a THEFT VECTOR (scoring.THEFT_VECTOR_CODES).
   Failed SPF/DKIM/DMARC alone is hygiene, not intent.
3. Aligned DKIM + DMARC pass is the strongest genuine signal — but every trust
   credit is suppressed once a theft vector appears (BEC passes authentication).
4. One scoring path: the label is derived from the final score, never set separately.
5. Never render email HTML, never execute attachments, never write uploads to disk.

## Adding a detection rule
1. Add the signal in the right *_check.py (use _sig / Signal, pick a Severity).
2. If it is a theft intent, add its code to THEFT_VECTOR_CODES in scoring.py.
3. Write a test that it FIRES on the attack AND a test that it stays QUIET on the
   benign wording that shares its vocabulary (see tests/test_new_signals.py).
4. Run pytest, regression.py and evaluate.py; check no genuine email got worse.

## Recent changes (see CHANGES.md)
Parser now keeps in-reply-to/references/list-id (thread-hijack rule was dead from
real .eml files); phone regex handles Indian/international numbers; new signals
CNT_SEED_PHRASE_REQUEST, CNT_MFA_APPROVAL_LURE; bank details (IFSC/account no.)
in body count as payment instruction; corpus dates fixed + guard test.

## Open work, roughly by value
1. eval50 was hand-written and the rules were tuned on it — treat 86% as optimistic.
   Get external data (Nazario phishing, SpamAssassin ham/spam), split into
   dev/held-out, and only tune on dev. This is the single most important task.
2. p03-invoice-vendor-swap scores 65 SUSPICIOUS: fully authenticated lookalike
   domain + changed bank details + hijacked thread. Consider a named CORR_ pattern
   in scoring.py (thread mismatch + payment redirection => PHISHING).
3. 5/14 spam is labelled GENUINE (cold outreach with clean headers scores ~0). Decide
   whether that is acceptable or add a modest promotional-language signal.
4. g08-small-business-misconfigured is a false positive (73). Probably acceptable.
5. The LLM/agent layer has never been measured here: get a free Groq key, run
   evaluate.py with and without --no-llm, and record whether it changes any verdict.
6. Replace datetime.utcnow() (deprecation warnings in db.py / models.py).
7. URL_BRAND_CONSISTENT ("Links resolve to X's own domain", urls_check.py) can credit a
   phantom link: html_to_text flattens an anchor to its display text, and when that text
   is itself a URL, extract_links_from_text re-harvests it as a real link. A message
   linking <a href="evil.top">https://paypal.com/signin</a> therefore carries a paypal.com
   link nobody can click. Harmless today (INFO-weighted, and design rule 3 suppresses trust
   credits once a theft vector fires) but it would grant a false trust credit on a
   genuine-looking email where no theft vector fires. Note the phantom is in email.links
   itself, so any future rule iterating links inherits it.

## Safety
Default login Vani/Vani is only safe on 127.0.0.1. Never commit .env or data/.

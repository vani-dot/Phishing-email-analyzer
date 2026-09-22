# Changes after the eval50 review

| Area | Change | Why |
|---|---|---|
| parser.py | Keep `in-reply-to`, `references`, `list-id` headers | HDR_THREAD_DOMAIN_MISMATCH could never fire on a real .eml: the header whitelist dropped its input |
| content_check.py | New phone regex (Indian/international/toll-free) | Old pattern matched only US 3-3-4; "+91 80 4471 2288" was invisible, so callback phishing was missed |
| content_check.py | New `CNT_SEED_PHRASE_REQUEST` (negation-aware) | Wallet recovery-phrase theft had no signal at all |
| content_check.py | New `CNT_MFA_APPROVAL_LURE` (negation-aware) | MFA-fatigue lures had no signal |
| content_check.py | IFSC / account number / IBAN in body => payment instruction | "Send payment to this account instead" scams were not recognised |
| scoring.py | New codes registered as `credential_request` theft vectors | Needed for the PHISHING gate |
| corpus/, samples/ | 20 emails re-dated from the future to the past | HDR_FUTURE_DATE made results depend on the day evaluation was run |
| tests/ | `test_new_signals.py` (28), `test_corpus_hygiene.py` (1) | Each rule tested on attack AND benign wording |

## Measured on corpus/eval50, rules only

| | Before | After |
|---|---|---|
| Exact-label accuracy | 39/50 (78%) | 43/50 (86%) |
| Phishing labelled PHISHING | 13/18 | 17/18 |
| Phishing missed entirely | 0 | 0 |
| Genuine false alarms | 1/18 | 1/18 |
| Tests | 268 | 297 |

Caveat: these emails are the same set the misses were found on, so this shows the
known gaps are closed, not that accuracy on unseen mail improved by 8 points.

#!/usr/bin/env python3
# regression.py
# The acceptance harness for the blind-test findings.
#
# Ten emails are not an evaluation — they cannot produce meaningful accuracy
# figures. They are a REGRESSION HARNESS: a set of cases that were each wrong
# for a specific, understood reason, kept so that a future change cannot
# quietly reintroduce any of them. Real metrics need several hundred messages
# from an external corpus; use evaluate.py for that.
#
#   python regression.py            rules only (reproducible)
#   python regression.py --llm      with the AI layer
#
# Exit code 0 when every criterion passes, 1 otherwise.

import argparse
import pathlib
import sys
import warnings

warnings.filterwarnings("ignore", message=".*OpenSSL.*")

import analyzer

ROOT = pathlib.Path(__file__).resolve().parent
CORPUS = ROOT / "corpus" / "blind10"
LABEL_DIRS = {"phishing": "PHISHING", "spam": "SPAM", "genuine": "GENUINE"}
RANK = {"GENUINE": 0, "SPAM": 1, "SUSPICIOUS": 2, "PHISHING": 3}

# Acceptance criteria from the blind-test report.
PHISHING_MIN_SCORE = 75
GENUINE_MAX_SCORE = 24


def main() -> int:
    parser = argparse.ArgumentParser(description="Blind-test regression harness.")
    parser.add_argument("--llm", action="store_true", help="include the AI layer")
    parser.add_argument("-v", "--verbose", action="store_true", help="show signals per email")
    args = parser.parse_args()

    if not CORPUS.is_dir():
        print(f"error: corpus missing at {CORPUS}", file=sys.stderr)
        return 1

    items = []
    for directory, truth in LABEL_DIRS.items():
        for path in sorted((CORPUS / directory).glob("*.eml")):
            items.append((path, truth))
    items.sort(key=lambda pair: pair[0].name)

    print(f"\n  Blind-test regression — {len(items)} emails, "
          f"{'rules + AI' if args.llm else 'rules only'}\n")
    print(f"  {'#':<3} {'file':<32} {'truth':<9} {'got':<11} {'score':>5}  {'theft vectors'}")
    print("  " + "-" * 94)

    results, failures = [], []
    for path, truth in items:
        report = analyzer.analyse(path.read_text(encoding="utf-8"), filename=path.name, use_llm=args.llm)
        got = report.verdict.value
        results.append((path.name, truth, got, report.risk_score, report))
        vectors = ", ".join(report.theft_vectors) or "—"
        flag = "" if got == truth else "   <-- WRONG"
        print(f"  {path.name[:2]:<3} {path.stem[:32]:<32} {truth:<9} {got:<11} "
              f"{report.risk_score:>5}  {vectors[:34]}{flag}")
        if args.verbose:
            for signal in report.signals:
                if signal.weight:
                    print(f"        +{signal.weight:<3} {signal.code}")

    print("  " + "-" * 94)

    # ---- criterion 1: every label correct -------------------------------
    wrong = [(n, t, g) for n, t, g, s, r in results if t != g]
    if wrong:
        failures.append(f"{len(wrong)} wrong label(s): " +
                        ", ".join(f"{n}={g} (want {t})" for n, t, g in wrong))

    # ---- criterion 2: phishing scores high enough to survive a threshold
    for name, truth, got, score, report in results:
        if truth == "PHISHING" and score < PHISHING_MIN_SCORE:
            failures.append(f"{name}: PHISHING at {score}, needs >= {PHISHING_MIN_SCORE} "
                            f"(a downstream 'release under 50' rule would deliver it)")

    # ---- criterion 3: genuine mail stays low ----------------------------
    for name, truth, got, score, report in results:
        if truth == "GENUINE" and score > GENUINE_MAX_SCORE:
            failures.append(f"{name}: GENUINE at {score}, needs <= {GENUINE_MAX_SCORE}")

    # ---- criterion 4: score and label are ordered -----------------------
    for a in results:
        for b in results:
            if a[3] > b[3] and RANK[a[2]] < RANK[b[2]]:
                failures.append(f"ordering: {a[0]} {a[2]} {a[3]} ranks below "
                                f"{b[0]} {b[2]} {b[3]}")

    # ---- criterion 5: every phishing verdict names a theft vector -------
    for name, truth, got, score, report in results:
        if got == "PHISHING" and not report.theft_vectors:
            failures.append(f"{name}: labelled PHISHING with no theft vector")

    correct = sum(1 for n, t, g, s, r in results if t == g)
    genuine = [r for r in results if r[1] == "GENUINE"]
    false_pos = sum(1 for n, t, g, s, r in genuine if g != "GENUINE")
    phish = [r for r in results if r[1] == "PHISHING"]
    missed = sum(1 for n, t, g, s, r in phish if g not in ("PHISHING", "SUSPICIOUS"))

    print(f"\n  accuracy                    {correct}/{len(results)}")
    print(f"  false positives on genuine  {false_pos}/{len(genuine)}")
    print(f"  missed phishing             {missed}/{len(phish)}")

    print("\n  acceptance criteria:")
    names = ["all labels correct", f"phishing scores >= {PHISHING_MIN_SCORE}",
             f"genuine scores <= {GENUINE_MAX_SCORE}", "score/label ordering holds",
             "every phishing names a theft vector"]
    seen = set()
    for index, label in enumerate(names, 1):
        hit = [f for f in failures if _belongs(f, index)]
        mark = "FAIL" if hit else "ok  "
        print(f"    {mark}  {label}")
        for line in hit[:3]:
            if line not in seen:
                seen.add(line)
                print(f"          {line}")

    if failures:
        print(f"\n  RESULT: FAILED ({len(set(failures))} issue(s))\n")
        return 1
    print("\n  RESULT: all acceptance criteria passed\n")
    print("  Note: ten emails is a regression harness, not an evaluation. For")
    print("  real precision/recall/F1, run evaluate.py against several hundred")
    print("  messages from the Nazario and SpamAssassin corpora.\n")
    return 0


def _belongs(failure: str, index: int) -> bool:
    if index == 1:
        return "wrong label" in failure
    if index == 2:
        return "needs >=" in failure
    if index == 3:
        return "needs <=" in failure
    if index == 4:
        return failure.startswith("ordering:")
    return "no theft vector" in failure


if __name__ == "__main__":
    sys.exit(main())

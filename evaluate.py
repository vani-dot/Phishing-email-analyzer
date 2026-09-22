#!/usr/bin/env python3
# evaluate.py
# Measures the analyser against labelled email, and prints the numbers a
# report or paper needs: confusion matrix, precision, recall, F1, and the
# score distribution per class.
#
# Layout it expects — one directory per label:
#
#   corpus/
#     phishing/   *.eml
#     spam/       *.eml
#     genuine/    *.eml
#
#   python evaluate.py corpus/
#   python evaluate.py corpus/ --no-llm --csv results.csv
#
# Metrics are computed here in plain arithmetic rather than through
# scikit-learn, so running an evaluation needs no extra dependency and the
# definition of every number is visible in this file. --sklearn cross-checks
# against the reference implementation when it is installed.
#
# WHY THE BINARY VIEW IS THE HEADLINE
# Four-class accuracy flatters a phishing detector: confusing spam with
# genuine is a nuisance, while letting a phishing message through is the
# failure the tool exists to prevent. So the primary table collapses to
# malicious (phishing) vs not, and reports the false-negative rate on its own,
# because that is the number that matters operationally.

import argparse
import csv
import json
import pathlib
import sys
import warnings
from collections import defaultdict
from typing import Dict, List, Tuple

warnings.filterwarnings("ignore", message=".*OpenSSL.*")

import analyzer

# Directory name -> ground-truth label.
LABEL_DIRS = {
    "phishing": "PHISHING", "phish": "PHISHING", "malicious": "PHISHING",
    "spam": "SPAM", "junk": "SPAM",
    "genuine": "GENUINE", "ham": "GENUINE", "legitimate": "GENUINE", "legit": "GENUINE",
}

# A SUSPICIOUS prediction is a withheld judgement, not a class in the corpus.
# For scoring it counts as "flagged" — the message was not cleared — which is
# the operationally honest reading.
FLAGGED = {"PHISHING", "SUSPICIOUS", "SPAM"}
MALICIOUS_PREDICTIONS = {"PHISHING", "SUSPICIOUS"}


def load_corpus(root: pathlib.Path) -> List[Tuple[pathlib.Path, str]]:
    items = []
    for directory in sorted(root.iterdir()):
        if not directory.is_dir():
            continue
        label = LABEL_DIRS.get(directory.name.lower())
        if label is None:
            print(f"  skipping unlabelled directory: {directory.name}", file=sys.stderr)
            continue
        for path in sorted(directory.iterdir()):
            if path.suffix.lower() in (".eml", ".txt", ".msg", ".email") and path.is_file():
                items.append((path, label))
    return items


def confusion(pairs: List[Tuple[str, str]], classes: List[str]) -> Dict[str, Dict[str, int]]:
    matrix = {actual: {predicted: 0 for predicted in classes} for actual in classes}
    for actual, predicted in pairs:
        if actual in matrix and predicted in matrix[actual]:
            matrix[actual][predicted] += 1
    return matrix


def prf(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate the analyser against a labelled corpus.")
    parser.add_argument("corpus", help="directory containing phishing/ spam/ genuine/")
    parser.add_argument("--no-llm", action="store_true",
                        help="rules only — use this for reproducible numbers")
    parser.add_argument("--csv", help="write per-message results to this file")
    parser.add_argument("--json", help="write the full metrics object to this file")
    parser.add_argument("--sklearn", action="store_true",
                        help="cross-check against scikit-learn if installed")
    parser.add_argument("--limit", type=int, default=0, help="stop after N messages per class")
    args = parser.parse_args()

    root = pathlib.Path(args.corpus)
    if not root.is_dir():
        print(f"error: {args.corpus} is not a directory", file=sys.stderr)
        return 1

    items = load_corpus(root)
    if not items:
        print("error: no labelled messages found.", file=sys.stderr)
        print("Expected subdirectories named phishing/, spam/ or genuine/.", file=sys.stderr)
        return 1

    if args.limit:
        per_class = defaultdict(int)
        kept = []
        for path, label in items:
            if per_class[label] < args.limit:
                kept.append((path, label))
                per_class[label] += 1
        items = kept

    print(f"\nEvaluating {len(items)} messages "
          f"({'rules only' if args.no_llm else 'rules + LLM if configured'})\n")

    rows = []
    pairs: List[Tuple[str, str]] = []
    scores_by_label = defaultdict(list)
    failures = []

    for index, (path, actual) in enumerate(items, 1):
        if index % 50 == 0 or index == len(items):
            print(f"  {index}/{len(items)}...", file=sys.stderr)
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
            report = analyzer.analyse(raw, source="cli", filename=path.name,
                                      use_llm=not args.no_llm)
        except Exception as exc:  # noqa: BLE001
            failures.append((path.name, f"{type(exc).__name__}: {exc}"))
            continue

        predicted = report.verdict.value
        pairs.append((actual, predicted))
        scores_by_label[actual].append(report.risk_score)
        rows.append({
            "file": path.name, "actual": actual, "predicted": predicted,
            "risk_score": report.risk_score, "confidence": report.confidence,
            "signals": len(report.signals), "duration_ms": report.duration_ms,
            "top_signal": report.signals[0].code if report.signals else "",
        })

    if failures:
        print(f"\n{len(failures)} message(s) could not be analysed:")
        for name, reason in failures[:10]:
            print(f"  {name}: {reason}")

    if not pairs:
        print("error: nothing was analysed successfully.", file=sys.stderr)
        return 1

    classes = ["PHISHING", "SUSPICIOUS", "SPAM", "GENUINE"]
    present = [c for c in classes if any(a == c for a, _ in pairs)] or classes
    matrix = confusion(pairs, classes)

    # ---- confusion matrix ------------------------------------------------
    print("\n" + "=" * 74)
    print("CONFUSION MATRIX   (rows = ground truth, columns = predicted)")
    print("=" * 74)
    header = "  {:<12}".format("actual \\ pred") + "".join(f"{c[:9]:>11}" for c in classes) + f"{'total':>9}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for actual in present:
        total = sum(matrix[actual].values())
        line = f"  {actual:<12}" + "".join(f"{matrix[actual][p]:>11}" for p in classes) + f"{total:>9}"
        print(line)

    # ---- per class -------------------------------------------------------
    print("\n" + "=" * 74)
    print("PER-CLASS METRICS   (exact label match)")
    print("=" * 74)
    print(f"  {'class':<12}{'precision':>11}{'recall':>10}{'f1':>10}{'support':>10}")
    print("  " + "-" * 51)
    macro = []
    for label in present:
        tp = matrix[label][label]
        fp = sum(matrix[other][label] for other in classes if other != label)
        fn = sum(matrix[label][other] for other in classes if other != label)
        precision, recall, f1 = prf(tp, fp, fn)
        support = sum(matrix[label].values())
        macro.append((precision, recall, f1))
        print(f"  {label:<12}{precision:>11.3f}{recall:>10.3f}{f1:>10.3f}{support:>10}")
    if macro:
        print("  " + "-" * 51)
        print(f"  {'macro avg':<12}"
              f"{sum(m[0] for m in macro)/len(macro):>11.3f}"
              f"{sum(m[1] for m in macro)/len(macro):>10.3f}"
              f"{sum(m[2] for m in macro)/len(macro):>10.3f}"
              f"{len(pairs):>10}")

    correct = sum(1 for a, p in pairs if a == p)
    print(f"\n  Exact-label accuracy: {correct}/{len(pairs)} = {correct/len(pairs):.3f}")

    # ---- binary view: the number that actually matters -------------------
    tp = sum(1 for a, p in pairs if a == "PHISHING" and p in MALICIOUS_PREDICTIONS)
    fn = sum(1 for a, p in pairs if a == "PHISHING" and p not in MALICIOUS_PREDICTIONS)
    fp = sum(1 for a, p in pairs if a == "GENUINE" and p in MALICIOUS_PREDICTIONS)
    tn = sum(1 for a, p in pairs if a == "GENUINE" and p not in MALICIOUS_PREDICTIONS)
    precision, recall, f1 = prf(tp, fp, fn)

    print("\n" + "=" * 74)
    print("BINARY: phishing detection   (PHISHING or SUSPICIOUS counts as caught)")
    print("=" * 74)
    print(f"  true positives  {tp:>6}   phishing correctly flagged")
    print(f"  false negatives {fn:>6}   phishing that got through   <-- the dangerous one")
    print(f"  false positives {fp:>6}   genuine mail wrongly flagged")
    print(f"  true negatives  {tn:>6}   genuine mail correctly cleared")
    print()
    print(f"  precision {precision:.3f}   of everything flagged, this fraction really was phishing")
    print(f"  recall    {recall:.3f}   of all phishing present, this fraction was caught")
    print(f"  F1        {f1:.3f}")
    if tp + fn:
        print(f"  miss rate {fn/(tp+fn):.3f}   <-- the operationally important figure")
    if fp + tn:
        print(f"  false alarm rate {fp/(fp+tn):.3f}")

    # ---- score distribution ---------------------------------------------
    print("\n" + "=" * 74)
    print("RISK SCORE DISTRIBUTION BY TRUE LABEL")
    print("=" * 74)
    print(f"  {'label':<12}{'n':>6}{'min':>7}{'mean':>8}{'median':>8}{'max':>7}")
    print("  " + "-" * 46)
    for label in present:
        values = sorted(scores_by_label[label])
        if not values:
            continue
        median = values[len(values) // 2]
        print(f"  {label:<12}{len(values):>6}{values[0]:>7}"
              f"{sum(values)/len(values):>8.1f}{median:>8}{values[-1]:>7}")
    print("\n  Good separation means the phishing mean sits far above the genuine mean.")
    print("  Overlap between them is where the thresholds in scoring.py need tuning.")

    # ---- most common misses ---------------------------------------------
    missed = [r for r in rows if r["actual"] == "PHISHING" and r["predicted"] not in MALICIOUS_PREDICTIONS]
    if missed:
        print("\n" + "=" * 74)
        print(f"MISSED PHISHING ({len(missed)}) — the highest-value thing to study")
        print("=" * 74)
        for row in sorted(missed, key=lambda r: r["risk_score"])[:15]:
            print(f"  {row['file'][:46]:<46} score={row['risk_score']:>3}  signals={row['signals']}")

    false_alarms = [r for r in rows if r["actual"] == "GENUINE" and r["predicted"] in MALICIOUS_PREDICTIONS]
    if false_alarms:
        print("\n" + "=" * 74)
        print(f"FALSE ALARMS ({len(false_alarms)})")
        print("=" * 74)
        for row in sorted(false_alarms, key=lambda r: -r["risk_score"])[:15]:
            print(f"  {row['file'][:40]:<40} score={row['risk_score']:>3}  top={row['top_signal'][:22]}")

    # ---- optional sklearn cross-check ------------------------------------
    if args.sklearn:
        try:
            from sklearn.metrics import classification_report
            actuals = [a for a, _ in pairs]
            predictions = [p for _, p in pairs]
            print("\n" + "=" * 74)
            print("SCIKIT-LEARN CROSS-CHECK")
            print("=" * 74)
            print(classification_report(actuals, predictions, zero_division=0))
        except ImportError:
            print("\n  (scikit-learn not installed: pip install scikit-learn)")

    metrics = {
        "total": len(pairs),
        "exact_accuracy": correct / len(pairs),
        "confusion_matrix": matrix,
        "binary": {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
                   "precision": precision, "recall": recall, "f1": f1,
                   "miss_rate": fn / (tp + fn) if (tp + fn) else 0.0},
        "score_distribution": {k: v for k, v in scores_by_label.items()},
        "failures": failures,
    }

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        print(f"\n  per-message results -> {args.csv}")

    if args.json:
        pathlib.Path(args.json).write_text(json.dumps(metrics, indent=2))
        print(f"  metrics -> {args.json}")

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())

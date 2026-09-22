#!/usr/bin/env python3
# main.py
# Command line interface. Same analysis core as the web app — this formats a
# Report as text where app.py formats it as JSON.
#
#   python main.py suspicious.eml
#   python main.py --json suspicious.eml
#   cat message.txt | python main.py -
#   python main.py --all samples/
#
# Exit codes are meant for scripting:
#   0  genuine      2  spam        3  suspicious      4  phishing
#   1  usage or read error

import argparse
import json
import pathlib
import sys
import warnings

warnings.filterwarnings("ignore", message=".*OpenSSL.*")

import analyzer
from models import Report, Severity, Verdict

EXIT_CODES = {
    Verdict.GENUINE: 0, Verdict.SPAM: 2,
    Verdict.SUSPICIOUS: 3, Verdict.PHISHING: 4,
}

# ANSI, suppressed when not writing to a terminal so piped output stays clean.
class C:
    def __init__(self, enabled: bool):
        self.on = enabled
    def _wrap(self, code, text):
        return f"\033[{code}m{text}\033[0m" if self.on else text
    def red(self, t):    return self._wrap("31;1", t)
    def orange(self, t): return self._wrap("33;1", t)
    def yellow(self, t): return self._wrap("33", t)
    def blue(self, t):   return self._wrap("34", t)
    def green(self, t):  return self._wrap("32;1", t)
    def dim(self, t):    return self._wrap("2", t)
    def bold(self, t):   return self._wrap("1", t)


def render(report: Report, colour: C, verbose: bool) -> str:
    severity_paint = {
        Severity.CRITICAL: colour.red, Severity.HIGH: colour.orange,
        Severity.MEDIUM: colour.yellow, Severity.LOW: colour.blue,
        Severity.INFO: colour.dim,
    }
    verdict_paint = {
        Verdict.PHISHING: colour.red, Verdict.SUSPICIOUS: colour.orange,
        Verdict.SPAM: colour.yellow, Verdict.GENUINE: colour.green,
    }

    lines = []
    rule = "=" * 74
    lines.append(rule)
    lines.append(f"  {verdict_paint[report.verdict](report.verdict.value)}"
                 f"    risk {colour.bold(str(report.risk_score))}/100"
                 f"    confidence {report.confidence}%")
    lines.append(rule)

    email = report.email
    if email.subject:
        lines.append(f"  Subject : {email.subject[:70]}")
    if email.from_address:
        sender = email.from_address
        if email.from_display:
            sender = f'"{email.from_display}" <{email.from_address}>'
        lines.append(f"  From    : {sender[:70]}")
    if not email.headers_present:
        lines.append(colour.dim("  (no headers supplied — body-only analysis)"))

    # The theft vectors are the clearest statement of WHY this is phishing
    # rather than merely unwanted, so they go above the prose.
    if report.theft_vectors:
        vectors = ", ".join(v.replace("_", " ") for v in report.theft_vectors)
        lines.append(f"  Theft   : {colour.red(vectors)}")
    elif report.verdict in (Verdict.SPAM, Verdict.SUSPICIOUS):
        lines.append(colour.dim("  Theft   : none detected — cannot be classified as phishing"))
    if email.headers_present:
        auth = (colour.green("verified (aligned DKIM + DMARC pass)")
                if report.authenticated_sender else colour.dim("not verified"))
        lines.append(f"  Sender  : {auth}")
    if report.divergence == "llm_only_detection":
        lines.append(colour.orange("  Note    : found by language analysis alone — the "
                                   "deterministic checks saw nothing"))
    lines.append("")

    # The written assessment, wrapped.
    import textwrap
    for line in textwrap.wrap(report.summary, width=70):
        lines.append(f"  {line}")
    lines.append("")

    counts = report.counts_by_severity()
    tally = "  ".join(
        severity_paint[Severity(s)](f"{counts[s]} {s.lower()}")
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]
    )
    if tally:
        lines.append(f"  {tally}")
        lines.append("")

    shown = [s for s in report.signals if s.severity != Severity.INFO or verbose]
    if shown:
        lines.append(colour.bold("  FINDINGS"))
        lines.append("  " + "-" * 70)
        for signal in shown:
            paint = severity_paint[signal.severity]
            weight = f"+{signal.weight}" if signal.weight else "  ·"
            lines.append(f"  {paint(f'[{signal.severity.value}]'):<22} "
                         f"{colour.dim(weight.rjust(4))}  {signal.title}")
            if verbose:
                for line in textwrap.wrap(signal.detail, width=64):
                    lines.append(f"      {colour.dim(line)}")
                if signal.evidence:
                    lines.append(f"      {colour.dim('evidence: ' + signal.evidence[:60])}")
                lines.append("")
    else:
        lines.append(colour.green("  No findings — nothing matched."))

    lines.append("")
    # Status is now "ok:<provider>", so this must be a prefix test, not equality.
    if report.llm_status.startswith("ok"):
        mode = "rules + AI (" + report.llm_status.split(":", 1)[1] + ")"
    else:
        mode = "rules only"
    lines.append(colour.dim(f"  {len(report.signals)} signals  |  {mode}  |  {report.duration_ms} ms"))
    if report.llm_status.startswith("error"):
        lines.append(colour.dim(f"  AI layer unavailable ({report.llm_status}) — rules result stands."))
    lines.append(rule)
    return "\n".join(lines)


def read_source(target: str) -> str:
    if target == "-":
        return sys.stdin.read()
    path = pathlib.Path(target)
    if not path.is_file():
        raise FileNotFoundError(target)
    return path.read_text(encoding="utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Analyse an email for phishing, spam or legitimacy.",
        epilog="Exit codes: 0 genuine, 2 spam, 3 suspicious, 4 phishing, 1 error.",
    )
    parser.add_argument("target", nargs="?",
                        help="path to a .eml/.txt file, a directory with --all, or - for stdin")
    parser.add_argument("--probe", action="store_true",
                        help="check every configured AI provider and exit")
    parser.add_argument("--json", action="store_true", help="emit the full report as JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="show the reasoning for every finding")
    parser.add_argument("--all", action="store_true", help="treat the target as a directory and analyse every message in it")
    parser.add_argument("--no-llm", action="store_true", help="skip the AI layer even if a key is configured")
    parser.add_argument("--network", action="store_true", help="allow outbound link expansion (off by default)")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    args = parser.parse_args()

    colour = C(sys.stdout.isatty() and not args.no_color)

    if args.probe:
        import llm as llm_module
        info = llm_module.health()
        print(f"\n  mode: {info['mode']}")
        if not info["configured"]:
            print("  No provider configured. Set PEA_LLM_API_KEY in .env.")
            print("  The analyser still works — it runs on its rules engine alone.\n")
            return 0
        print(f"  {'role':<10}{'provider':<10}{'model':<26}{'status':<10}{'latency':>9}")
        print("  " + "-" * 65)
        healthy = 0
        for row in llm_module.probe():
            mark = colour.green("up") if row["ok"] else colour.red("down")
            healthy += row["ok"]
            print(f"  {row['role']:<10}{row['provider']:<10}{row['model'][:25]:<26}"
                  f"{mark:<10}{str(row['ms']) + 'ms':>9}"
                  + ("" if row["ok"] else f"   {row['detail']}"))
        print()
        if healthy == 0:
            print(colour.orange("  No provider is reachable — analysis will run rules-only.\n"))
            return 1
        return 0

    if not args.target:
        parser.error("a target is required (or use --probe)")

    if args.all:
        directory = pathlib.Path(args.target)
        if not directory.is_dir():
            print(f"error: {args.target} is not a directory", file=sys.stderr)
            return 1
        files = sorted(p for p in directory.iterdir()
                       if p.suffix.lower() in (".eml", ".txt", ".msg", ".email"))
        if not files:
            print(f"error: no email files found in {args.target}", file=sys.stderr)
            return 1

        worst = Verdict.GENUINE
        results = []
        for path in files:
            report = analyzer.analyse(read_source(str(path)), source="cli",
                                      filename=path.name, use_llm=not args.no_llm,
                                      use_network=args.network)
            results.append((path.name, report))
            if EXIT_CODES[report.verdict] > EXIT_CODES[worst]:
                worst = report.verdict

        if args.json:
            print(json.dumps([json.loads(r.model_dump_json()) for _, r in results], indent=2))
        else:
            print(f"\n  {'FILE':<42} {'VERDICT':<12} {'RISK':>5}  {'SIGNALS':>7}")
            print("  " + "-" * 70)
            for name, report in results:
                paint = {Verdict.PHISHING: colour.red, Verdict.SUSPICIOUS: colour.orange,
                         Verdict.SPAM: colour.yellow, Verdict.GENUINE: colour.green}[report.verdict]
                print(f"  {name[:42]:<42} {paint(report.verdict.value):<12} "
                      f"{report.risk_score:>5}  {len(report.signals):>7}")
            print()
        return EXIT_CODES[worst]

    try:
        content = read_source(args.target)
    except FileNotFoundError:
        print(f"error: no such file: {args.target}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: could not read {args.target}: {exc}", file=sys.stderr)
        return 1

    if not content.strip():
        print("error: input is empty", file=sys.stderr)
        return 1

    report = analyzer.analyse(content, source="cli",
                              filename=None if args.target == "-" else args.target,
                              use_llm=not args.no_llm, use_network=args.network)

    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        print(render(report, colour, args.verbose))

    return EXIT_CODES[report.verdict]


if __name__ == "__main__":
    sys.exit(main())

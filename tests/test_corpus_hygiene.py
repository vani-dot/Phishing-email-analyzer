"""Guard: no labelled email may be dated in the future.

HDR_FUTURE_DATE compares the message date with the clock on the machine
running the analysis. A corpus email dated next week therefore scores
differently today than it will in seven days, which makes evaluation numbers
depend on when you ran them. Keep every corpus and sample date in the past.
"""
import glob
import os
import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _files():
    return (glob.glob(os.path.join(ROOT, "corpus", "**", "*.eml"), recursive=True)
            + glob.glob(os.path.join(ROOT, "samples", "*.eml")))


def test_no_corpus_email_is_dated_in_the_future():
    limit = datetime.now(timezone.utc) + timedelta(hours=1)
    future = []
    for path in _files():
        text = open(path, encoding="utf-8", errors="replace").read()
        for line in re.findall(r"(?m)^(?:Date|Received):.*$", text.split("\n\n", 1)[0]):
            m = re.search(r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),[^;]+\d{4} \d\d:\d\d:\d\d [+-]\d{4}", line)
            if not m:
                continue
            try:
                when = parsedate_to_datetime(m.group(0))
            except (TypeError, ValueError):
                continue
            if when > limit:
                future.append(f"{os.path.relpath(path, ROOT)}: {m.group(0)}")
    assert not future, "corpus emails dated in the future:\n" + "\n".join(future)

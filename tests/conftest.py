# conftest.py — shared fixtures.
#
# Every test runs against a throwaway database in a temp directory. The
# environment is set before any project module is imported, because config.py
# reads it at import time and a test that quietly writes to the real
# data/analyzer.db is a test that destroys the developer's history.

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_tmp = tempfile.mkdtemp(prefix="pea-tests-")
os.environ["PEA_DB_PATH"] = str(Path(_tmp) / "test.db")
os.environ["PEA_SECRET_KEY"] = "test-only-secret-key-not-used-anywhere-real"
# Both provider slots are blanked. config.py calls load_dotenv(), which does
# NOT override variables already present in the environment — so setting them
# here, before config is imported, is what keeps the real .env keys out of the
# test run. Clearing only the primary would leave the fallback live and the
# suite would quietly start billing a real provider.
os.environ["PEA_LLM_API_KEY"] = ""
os.environ["PEA_LLM_FALLBACK_API_KEY"] = ""
os.environ["PEA_LLM_ENABLED"] = "false"
os.environ["PEA_ENABLE_URL_EXPANSION"] = "false"
os.environ["PEA_ENABLE_DNS_CHECKS"] = "false"
# Keep the KDF honest but fast enough that the suite is not dominated by it.
os.environ["PEA_ARGON2_MEMORY_KIB"] = "8192"
os.environ["PEA_ARGON2_TIME_COST"] = "1"

import warnings
warnings.filterwarnings("ignore")

import pytest

import db  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _database():
    db.init_db()
    yield


@pytest.fixture
def clean_db():
    """Empty every table so a test starts from a known state."""
    conn = db.get_conn()
    for table in ("analyses", "audit_log", "sessions", "users"):
        conn.execute(f"DELETE FROM {table}")
    conn.commit()
    yield db


SAMPLES = ROOT / "samples"


def sample(name: str) -> str:
    return (SAMPLES / name).read_text(encoding="utf-8")


PHISHING_EML = """From: "PayPal Security" <service@paypa1-secure.tk>
Reply-To: harvest@mail.ru
To: victim@example.com
Subject: Urgent: verify your account
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Content-Type: text/html

<html><body>Dear Customer, we detected unusual activity.
Verify your account within 24 hours or it will be permanently deleted.
<a href="http://paypa1-verify.tk/login">https://www.paypal.com/signin</a>
</body></html>"""

GENUINE_EML = """From: GitHub <noreply@github.com>
To: user@example.com
Subject: [GitHub] Your weekly digest
Date: Thu, 18 Sep 2026 10:00:00 +0000
Message-ID: <digest.1@github.com>
Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass header.from=github.com
Received: from out-1.smtp.github.com by mx.google.com; Thu, 18 Sep 2026 10:00:01 +0000
Received: from worker.github.net by smtp.github.com; Thu, 18 Sep 2026 10:00:00 +0000
Received: from localhost by worker.github.net; Thu, 18 Sep 2026 10:00:00 +0000

Here is your weekly summary of repository activity.
See https://github.com/dashboard for details.
"""

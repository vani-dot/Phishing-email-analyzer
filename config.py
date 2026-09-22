# config.py
# Every tunable in one place, read from the environment once at import.
#
# WHY a module and not scattered os.getenv calls: a security control that is
# configured in three files is a security control that is misconfigured in one
# of them. The defaults here are the safe ones — the environment loosens them
# for local development, never the other way round.

import os
import secrets
import sys
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int, low: int, high: int) -> int:
    """Read an int and clamp it. A typo in .env must not disable a control."""
    try:
        value = int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


class Config:
    # ---- paths -----------------------------------------------------------
    BASE_DIR = BASE_DIR
    DATA_DIR = BASE_DIR / "data"
    DB_PATH = Path(os.getenv("PEA_DB_PATH", DATA_DIR / "analyzer.db"))
    STATIC_DIR = BASE_DIR / "static"
    TEMPLATE_DIR = BASE_DIR / "templates"
    SAMPLES_DIR = BASE_DIR / "samples"

    # ---- server ----------------------------------------------------------
    HOST = os.getenv("PEA_HOST", "127.0.0.1")
    PORT = _int("PEA_PORT", 8000, 1, 65535)
    DEBUG = _flag("PEA_DEBUG", False)

    # ---- session / cookies ----------------------------------------------
    SESSION_COOKIE = "pea_session"
    CSRF_COOKIE = "pea_csrf"
    CSRF_HEADER = "X-CSRF-Token"
    # Idle timeout: a session dies this long after its last request.
    SESSION_IDLE_MINUTES = _int("PEA_SESSION_IDLE_MINUTES", 30, 1, 1440)
    # Absolute timeout: a session dies this long after login, active or not.
    # Without this, a stolen cookie that is used regularly never expires.
    SESSION_ABSOLUTE_HOURS = _int("PEA_SESSION_ABSOLUTE_HOURS", 12, 1, 168)
    # Secure flag. Off by default so http://127.0.0.1 works; MUST be on behind
    # TLS, and the README says so. HTTPS deployment sets PEA_HTTPS=true.
    COOKIE_SECURE = _flag("PEA_HTTPS", False)

    # ---- first-run account -----------------------------------------------
    # Fixed default credentials, so the app is usable the moment it starts and
    # a demo never stalls on copying a generated password out of a log.
    #
    # The trade-off is explicit and worth knowing: these are published in the
    # README and in this file, so anyone who can reach the port is an
    # administrator. That is acceptable exactly as long as the port is not
    # reachable — HOST defaults to 127.0.0.1 for this reason. Do not bind this
    # to 0.0.0.0, port-forward it, or put it behind a tunnel while the default
    # password is still in place.
    #
    # Setting PEA_DEFAULT_PASSWORD to an empty value restores the previous
    # behaviour: a random password generated at first run and printed once.
    DEFAULT_USERNAME = os.getenv("PEA_DEFAULT_USERNAME", "Vani").strip() or "Vani"
    DEFAULT_PASSWORD = os.getenv("PEA_DEFAULT_PASSWORD", "Vani")
    # Whether the first-run account must change its password at first sign-in.
    # Off, because a forced change on a deliberately memorable credential just
    # reintroduces the friction the credential exists to remove.
    DEFAULT_FORCE_PASSWORD_CHANGE = _flag("PEA_DEFAULT_FORCE_CHANGE", False)

    # ---- password policy -------------------------------------------------
    # Floor lowered from 12 to 4 so the policy can actually accommodate a
    # short default. It still DEFAULTS to 12: every account created through
    # the Users screen is held to the full policy, and only the bootstrap
    # account — which is created directly, bypassing the API — is exempt.
    PASSWORD_MIN_LENGTH = _int("PEA_PASSWORD_MIN_LENGTH", 12, 4, 128)
    # Argon2id work factors. 64 MiB memory with 3 passes lands around 60-80 ms
    # per hash on commodity hardware: slow enough that offline cracking is
    # expensive, fast enough that a login does not feel broken. The memory
    # cost is the point — it is what denies an attacker cheap GPU parallelism.
    ARGON2_TIME_COST = _int("PEA_ARGON2_TIME_COST", 3, 1, 10)
    ARGON2_MEMORY_KIB = _int("PEA_ARGON2_MEMORY_KIB", 65536, 8192, 1048576)
    ARGON2_PARALLELISM = _int("PEA_ARGON2_PARALLELISM", 2, 1, 16)
    # Fallback only, used when argon2-cffi is not installed. OWASP's 2023
    # floor for PBKDF2-HMAC-SHA256.
    PBKDF2_ITERATIONS = _int("PEA_PBKDF2_ITERATIONS", 600_000, 100_000, 5_000_000)

    # ---- brute force / lockout ------------------------------------------
    MAX_FAILED_LOGINS = _int("PEA_MAX_FAILED_LOGINS", 5, 1, 50)
    LOCKOUT_MINUTES = _int("PEA_LOCKOUT_MINUTES", 15, 1, 1440)

    # ---- rate limits (requests per window, per client IP) ---------------
    RATE_LOGIN = (_int("PEA_RATE_LOGIN", 10, 1, 1000), 300)      # 10 / 5 min
    RATE_ANALYZE = (_int("PEA_RATE_ANALYZE", 30, 1, 1000), 60)   # 30 / min
    RATE_GLOBAL = (_int("PEA_RATE_GLOBAL", 300, 10, 100000), 60)  # 300 / min

    # ---- upload limits ---------------------------------------------------
    # 2 MB of email text is already enormous. This is the first line of
    # defence against memory-exhaustion via a giant paste or upload.
    MAX_UPLOAD_BYTES = _int("PEA_MAX_UPLOAD_BYTES", 2 * 1024 * 1024, 1024, 25 * 1024 * 1024)
    ALLOWED_UPLOAD_SUFFIXES = {".eml", ".txt", ".md", ".email", ".msg", ".mbox"}
    # Hard caps applied during parsing, so a malicious message cannot make the
    # analyser do unbounded work (MIME bombs, million-link bodies).
    MAX_MIME_PARTS = 200
    MAX_URLS_SCANNED = 300
    MAX_ATTACHMENTS = 50
    MAX_HEADER_COUNT = 300
    MAX_BODY_CHARS = 400_000

    # ---- outbound network (URL expansion) -------------------------------
    # Off by default. Expanding a link in a phishing email is an outbound
    # request to attacker-controlled infrastructure; that is an explicit
    # decision the operator makes, not a default.
    ENABLE_URL_EXPANSION = _flag("PEA_ENABLE_URL_EXPANSION", False)
    ENABLE_DNS_CHECKS = _flag("PEA_ENABLE_DNS_CHECKS", False)
    URL_EXPANSION_TIMEOUT = _int("PEA_URL_TIMEOUT", 5, 1, 30)
    URL_EXPANSION_MAX_HOPS = _int("PEA_URL_MAX_HOPS", 8, 1, 20)
    URL_EXPANSION_MAX_URLS = _int("PEA_URL_MAX_EXPAND", 10, 1, 50)
    DNS_TIMEOUT = _int("PEA_DNS_TIMEOUT", 3, 1, 15)

    # ---- LLM -------------------------------------------------------------
    # Provider-agnostic: anything speaking the OpenAI chat-completions shape
    # works (apmix, Groq, OpenRouter, Together, a local Ollama server).
    # Swapping provider is a few lines of .env — no code change, no vendor SDK.
    #
    # TWO PROVIDERS, TRIED IN ORDER. The primary handles normal traffic; the
    # fallback is used when the primary times out, rate-limits, returns 5xx or
    # answers with something that will not validate. This is not redundancy for
    # its own sake: free API tiers run out, and an analyser that silently drops
    # to rules-only mid-demo looks broken. Failing over to a second provider
    # keeps the AI layer available, and the report records which one answered.
    LLM_ENABLED = _flag("PEA_LLM_ENABLED", True)

    LLM_PROVIDER = os.getenv("PEA_LLM_PROVIDER", "groq").strip()
    LLM_API_KEY = os.getenv("PEA_LLM_API_KEY", "").strip()
    LLM_BASE_URL = os.getenv("PEA_LLM_BASE_URL", "https://api.groq.com/openai/v1").rstrip("/")
    LLM_MODEL = os.getenv("PEA_LLM_MODEL", "openai/gpt-oss-120b")

    LLM_FALLBACK_PROVIDER = os.getenv("PEA_LLM_FALLBACK_PROVIDER", "apmix").strip()
    LLM_FALLBACK_API_KEY = os.getenv("PEA_LLM_FALLBACK_API_KEY", "").strip()
    LLM_FALLBACK_BASE_URL = os.getenv(
        "PEA_LLM_FALLBACK_BASE_URL", "https://api.apmix.ai/v1").rstrip("/")
    LLM_FALLBACK_MODEL = os.getenv("PEA_LLM_FALLBACK_MODEL", "gpt-5.6-luna-free")

    LLM_TIMEOUT = _int("PEA_LLM_TIMEOUT", 45, 5, 180)

    # Agent mode: the model investigates with tools instead of being handed a
    # fixed summary. Costs several calls per message rather than one, and is
    # the reason the analysis generalises beyond what the prompt author
    # happened to think of. Set false to fall back to single-shot.
    AGENT_MODE = _flag("PEA_AGENT_MODE", True)
    # The body slice handed to the model. Caps cost and shrinks the surface a
    # prompt-injection payload has to work with.
    LLM_MAX_BODY_CHARS = _int("PEA_LLM_MAX_BODY_CHARS", 4000, 500, 20000)

    @property
    def llm_configured(self) -> bool:
        """True when at least one provider can be called."""
        return bool(self.LLM_ENABLED and (self.LLM_API_KEY or self.LLM_FALLBACK_API_KEY))

    @property
    def llm_providers(self):
        """Providers to try, in order. Skips any without a key."""
        chain = []
        if self.LLM_API_KEY:
            chain.append({"name": self.LLM_PROVIDER, "key": self.LLM_API_KEY,
                          "base_url": self.LLM_BASE_URL, "model": self.LLM_MODEL,
                          "role": "primary"})
        if self.LLM_FALLBACK_API_KEY:
            chain.append({"name": self.LLM_FALLBACK_PROVIDER, "key": self.LLM_FALLBACK_API_KEY,
                          "base_url": self.LLM_FALLBACK_BASE_URL,
                          "model": self.LLM_FALLBACK_MODEL, "role": "fallback"})
        return chain

    @property
    def uses_default_credentials(self) -> bool:
        return bool(self.DEFAULT_PASSWORD)

    # ---- secret key ------------------------------------------------------
    # Signs nothing critical on its own (sessions are random opaque tokens,
    # not signed blobs) but is used for HMAC of stored tokens.
    SECRET_KEY = os.getenv("PEA_SECRET_KEY", "")

    def __init__(self):
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)
        if not self.SECRET_KEY:
            # Persist a generated key so sessions survive a restart. Written
            # 0600 — the key is as sensitive as the database itself.
            key_file = self.DATA_DIR / ".secret_key"
            if key_file.exists():
                self.SECRET_KEY = key_file.read_text(encoding="utf-8").strip()
            else:
                self.SECRET_KEY = secrets.token_urlsafe(48)
                key_file.touch(mode=0o600)
                key_file.write_text(self.SECRET_KEY)
                os.chmod(key_file, 0o600)

    def warnings(self):
        """Deployment mistakes worth shouting about at startup."""
        out = []
        if self.uses_default_credentials:
            out.append(
                f"Default credentials are active ({self.DEFAULT_USERNAME}/"
                f"{self.DEFAULT_PASSWORD}) — anyone who can reach this port is an admin."
            )
            if self.HOST not in ("127.0.0.1", "localhost", "::1"):
                out.append(
                    f"SERIOUS: bound to {self.HOST} AND using a default password. "
                    f"This application is open to anyone who can route to it."
                )
        if not self.COOKIE_SECURE:
            out.append("Cookies are not marked Secure (set PEA_HTTPS=true behind TLS).")
        if self.DEBUG:
            out.append("PEA_DEBUG is on — verbose errors are exposed.")
        if not self.llm_configured:
            out.append("No LLM key configured — running in rules-only mode.")
        elif not self.LLM_API_KEY:
            out.append(f"Primary LLM provider has no key; only the "
                       f"{self.LLM_FALLBACK_PROVIDER} fallback is available.")
        elif not self.LLM_FALLBACK_API_KEY:
            out.append("No fallback LLM provider configured — if the primary fails, "
                       "analysis drops to rules-only.")
        if self.ENABLE_URL_EXPANSION:
            out.append("URL expansion is ON — this makes outbound requests to links in analysed email.")
        return out


config = Config()

if __name__ == "__main__":
    print(f"db          : {config.DB_PATH}")
    print(f"llm         : {'configured' if config.llm_configured else 'NOT configured (rules-only)'}")
    print(f"llm model   : {config.LLM_MODEL} @ {config.LLM_BASE_URL}")
    for w in config.warnings():
        print(f"warning     : {w}", file=sys.stderr)

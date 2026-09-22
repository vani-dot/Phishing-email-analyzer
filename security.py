# security.py
# Authentication primitives and the request-level defences.
#
# Design notes that matter if you are trying to break this:
#
#  * Session tokens are opaque random bytes, not signed blobs. There is no
#    JWT, so there is no alg=none, no key confusion, and no claim tampering —
#    the token carries no meaning, it is a lookup key. Revocation is a DELETE.
#  * Only the HMAC of a session token is stored. Reading the database does not
#    hand you a usable cookie.
#  * Password verification runs in constant time, and a miss on the username
#    still pays the full scrypt cost, so login timing does not leak which
#    accounts exist.
#  * CSRF is double-submit with a token bound to the session, compared with
#    compare_digest, and required on every state-changing method.

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
import unicodedata
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Tuple

from config import config

# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------

# Two schemes, both self-describing in the stored string so verify() can
# dispatch on the prefix. Argon2id is the primary — memory-hard, so a GPU or
# ASIC farm gains far less against it than against an iteration-only KDF.
# PBKDF2-HMAC-SHA256 is the fallback for environments without argon2-cffi
# (note: hashlib.scrypt is absent on macOS system Python, which links
# LibreSSL — that is why scrypt is not the fallback).
try:
    from argon2 import PasswordHasher
    from argon2 import exceptions as argon2_exceptions
    from argon2.low_level import Type as _Argon2Type

    _hasher = PasswordHasher(
        time_cost=config.ARGON2_TIME_COST,
        memory_cost=config.ARGON2_MEMORY_KIB,
        parallelism=config.ARGON2_PARALLELISM,
        hash_len=32,
        salt_len=16,
        type=_Argon2Type.ID,
    )
    ARGON2_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on install environment
    _hasher = None
    ARGON2_AVAILABLE = False

# A real hash of a throwaway password, used to burn the same CPU on a failed
# username lookup as on a failed password. Without it, "no such user" returns
# in microseconds and "wrong password" takes ~60 ms, which enumerates every
# account in your user table with a stopwatch.
_DUMMY_HASH: Optional[str] = None


def _pbkdf2_hash(password: str, salt: Optional[bytes] = None,
                 iterations: Optional[int] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    iterations = iterations or config.PBKDF2_ITERATIONS
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
    return "$pbkdf2-sha256${}${}${}".format(
        iterations, base64.b64encode(salt).decode(), base64.b64encode(dk).decode()
    )


def _pbkdf2_verify(password: str, stored: str) -> bool:
    try:
        _, scheme, iterations, salt_b64, hash_b64 = stored.split("$")
        if scheme != "pbkdf2-sha256":
            return False
        iterations = int(iterations)
        # Refuse absurd parameters from a tampered database rather than
        # letting the KDF try to spin for an hour.
        if not (1000 <= iterations <= 5_000_000):
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                 iterations, dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except (ValueError, TypeError):
        return False


def hash_password(password: str) -> str:
    """Argon2id where available, PBKDF2-HMAC-SHA256 otherwise.

    Parameters live inside the returned string, so raising the work factor
    later does not invalidate existing hashes — they verify with their own
    settings and are transparently re-hashed on the next successful login.
    """
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    # Unicode-normalise so the same typed password matches across platforms
    # that compose accents differently.
    password = unicodedata.normalize("NFKC", password)
    if ARGON2_AVAILABLE:
        return _hasher.hash(password)
    return _pbkdf2_hash(password)


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verify. Never raises on a malformed or hostile hash."""
    if not password or not stored:
        return False
    try:
        password = unicodedata.normalize("NFKC", password)
        if stored.startswith("$argon2"):
            if not ARGON2_AVAILABLE:
                return False
            try:
                _hasher.verify(stored, password)
                return True
            except (argon2_exceptions.VerifyMismatchError,
                    argon2_exceptions.VerificationError,
                    argon2_exceptions.InvalidHashError):
                return False
        if stored.startswith("$pbkdf2-"):
            return _pbkdf2_verify(password, stored)
        return False
    except (ValueError, TypeError, MemoryError):
        return False


def needs_rehash(stored: str) -> bool:
    """True when a stored hash uses weaker settings than we now require."""
    if ARGON2_AVAILABLE and stored.startswith("$argon2"):
        try:
            return _hasher.check_needs_rehash(stored)
        except Exception:
            return False
    # A PBKDF2 hash on a host that can now do argon2 should be upgraded.
    return ARGON2_AVAILABLE and stored.startswith("$pbkdf2-")


def burn_password_time() -> None:
    """Spend one password-verification's worth of CPU on a failed lookup."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("dummy-password-for-timing-equalisation")
    verify_password("wrong-password-value", _DUMMY_HASH)


# Bad passwords that a length rule alone happily accepts.
_COMMON_PASSWORDS = {
    "password", "passw0rd", "password123", "password1234", "qwertyuiop",
    "administrator", "letmein12345", "welcome12345", "changeme1234",
    "iloveyou1234", "1234567890ab", "abcd12345678", "adminadmin12",
    "phishing1234", "securepass12", "qwerty123456", "123456789012",
}


def password_problems(password: str, username: str = "") -> list:
    """Return a list of reasons the password is unacceptable. Empty == fine."""
    problems = []
    if len(password) < config.PASSWORD_MIN_LENGTH:
        problems.append(f"Must be at least {config.PASSWORD_MIN_LENGTH} characters.")
    if len(password) > 256:
        # Not a strength rule — an unbounded password is a free way to make the
        # server do scrypt work over a huge input.
        problems.append("Must be 256 characters or fewer.")
    classes = sum([
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"[0-9]", password)),
        bool(re.search(r"[^A-Za-z0-9]", password)),
    ])
    if classes < 3:
        problems.append("Must mix at least three of: lowercase, uppercase, digits, symbols.")
    lowered = password.lower()
    if lowered in _COMMON_PASSWORDS:
        problems.append("That password is too common.")
    if username and len(username) >= 3 and username.lower() in lowered:
        problems.append("Must not contain your username.")
    if re.search(r"(.)\1{4,}", password):
        problems.append("Must not repeat a single character five or more times.")
    return problems


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------

def new_token() -> str:
    """256 bits of CSPRNG entropy. Guessing is not a threat model."""
    return secrets.token_urlsafe(32)


def token_fingerprint(token: str) -> str:
    """HMAC-SHA256 of a token under the server key.

    Stored in place of the token itself. An attacker with read access to the
    database gets fingerprints, which are not accepted as cookies.
    """
    return hmac.new(
        config.SECRET_KEY.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def tokens_match(presented: Optional[str], expected: Optional[str]) -> bool:
    if not presented or not expected:
        return False
    return hmac.compare_digest(str(presented), str(expected))


# ---------------------------------------------------------------------------
# Rate limiting — in-process sliding window
# ---------------------------------------------------------------------------

class RateLimiter:
    """Sliding-window limiter keyed by an arbitrary string.

    In-process and therefore per-worker: correct for the single-process
    deployment this ships with. Behind multiple workers you would move this to
    Redis — noted in the README rather than pretended away, because a limiter
    that silently multiplies by worker count is worse than none.
    """

    def __init__(self):
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    def check(self, key: str, limit: int, window: int) -> Tuple[bool, int]:
        """Record a hit. Returns (allowed, seconds_until_retry)."""
        now = time.monotonic()
        with self._lock:
            if now - self._last_sweep > 300:
                self._sweep(now)
            bucket = self._hits[key]
            cutoff = now - window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                return False, max(1, int(bucket[0] + window - now) + 1)
            bucket.append(now)
            return True, 0

    def reset(self, key: str) -> None:
        """Clear a key — called after a successful login so one good password
        does not leave the user throttled by their own earlier typos."""
        with self._lock:
            self._hits.pop(key, None)

    def _sweep(self, now: float) -> None:
        """Drop empty buckets so the dict cannot grow forever under a spray of
        distinct keys (which is itself a memory-exhaustion vector)."""
        dead = [k for k, v in self._hits.items() if not v or v[-1] < now - 3600]
        for k in dead:
            self._hits.pop(k, None)
        self._last_sweep = now


limiter = RateLimiter()


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------

def client_ip(request) -> str:
    """The peer address.

    Deliberately ignores X-Forwarded-For. That header is client-controlled,
    so trusting it by default lets anyone bypass every per-IP limit here by
    sending a random value each request. Behind a proxy you terminate it in
    the proxy and set PEA_TRUSTED_PROXY handling there.
    """
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


SECURITY_HEADERS = {
    # No inline script, no eval, nothing loaded off-origin. The analyser
    # displays attacker-written text for a living, so script-src is the
    # control that turns an escaping mistake into a blocked console message
    # instead of stolen sessions.
    "Content-Security-Policy": (
        "default-src 'none'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "object-src 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
    # Analysis results are sensitive; keep them out of shared caches.
    "Cache-Control": "no-store, max-age=0",
}


def apply_security_headers(response) -> None:
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    if config.COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"


def set_session_cookie(response, name: str, value: str, max_age: int) -> None:
    response.set_cookie(
        key=name,
        value=value,
        max_age=max_age,
        httponly=(name == config.SESSION_COOKIE),  # CSRF cookie must be JS-readable
        secure=config.COOKIE_SECURE,
        samesite="strict",   # blocks the cross-site request that CSRF needs
        path="/",
    )


def clear_cookie(response, name: str) -> None:
    response.delete_cookie(key=name, path="/", samesite="strict", secure=config.COOKIE_SECURE)


USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,31}$")


def valid_username(name: str) -> bool:
    return bool(name and USERNAME_RE.match(name))


def safe_email(value: str) -> bool:
    if not value:
        return True
    return bool(re.match(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[a-zA-Z]{2,24}$", value))

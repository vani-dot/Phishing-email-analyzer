# db.py
# SQLite storage. Four tables, no ORM.
#
# Every query in this file is parameterised. There is no string formatting of
# user input into SQL anywhere, including the ORDER BY and LIMIT paths, where
# sort keys are resolved through a whitelist dict rather than interpolated.

import json
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from config import config
from models import ROLE_PERMISSIONS, Permission, Report, Role, User
import security

_local = threading.local()

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    username             TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email                TEXT    NOT NULL DEFAULT '',
    password_hash        TEXT    NOT NULL,
    role                 TEXT    NOT NULL DEFAULT 'viewer',
    permissions          TEXT    NOT NULL DEFAULT '[]',
    is_active            INTEGER NOT NULL DEFAULT 1,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT    NOT NULL,
    last_login           TEXT,
    failed_attempts      INTEGER NOT NULL DEFAULT 0,
    locked_until         TEXT,
    created_by           INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    token_hash    TEXT    NOT NULL UNIQUE,
    csrf_hash     TEXT    NOT NULL,
    created_at    TEXT    NOT NULL,
    last_seen     TEXT    NOT NULL,
    expires_at    TEXT    NOT NULL,
    absolute_exp  TEXT    NOT NULL,
    ip            TEXT    NOT NULL DEFAULT '',
    user_agent    TEXT    NOT NULL DEFAULT '',
    revoked       INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user  ON sessions(user_id);

CREATE TABLE IF NOT EXISTS analyses (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER,
    created_at    TEXT    NOT NULL,
    subject       TEXT    NOT NULL DEFAULT '',
    sender        TEXT    NOT NULL DEFAULT '',
    verdict       TEXT    NOT NULL,
    risk_score    INTEGER NOT NULL,
    confidence    INTEGER NOT NULL DEFAULT 0,
    rules_score   INTEGER NOT NULL DEFAULT 0,
    llm_status    TEXT    NOT NULL DEFAULT 'disabled',
    signal_count  INTEGER NOT NULL DEFAULT 0,
    source        TEXT    NOT NULL DEFAULT 'paste',
    filename      TEXT,
    duration_ms   INTEGER NOT NULL DEFAULT 0,
    theft_vectors TEXT    NOT NULL DEFAULT '',
    authenticated INTEGER NOT NULL DEFAULT 0,
    report_json   TEXT    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_analyses_user    ON analyses(user_id);
CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_verdict ON analyses(verdict);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT    NOT NULL,
    user_id   INTEGER,
    username  TEXT    NOT NULL DEFAULT '',
    event     TEXT    NOT NULL,
    severity  TEXT    NOT NULL DEFAULT 'info',
    ip        TEXT    NOT NULL DEFAULT '',
    detail    TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
"""


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")


def _parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def get_conn() -> sqlite3.Connection:
    """One connection per thread. sqlite3 objects are not thread-safe."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(config.DB_PATH), timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        _local.conn = conn
    return conn


@contextmanager
def transaction():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


# Columns added after the first release. SQLite has no "ADD COLUMN IF NOT
# EXISTS", so each is attempted and the duplicate-column error is the signal
# that it is already there. Keeps an existing database working across an
# upgrade instead of requiring it to be deleted.
MIGRATIONS = [
    "ALTER TABLE analyses ADD COLUMN theft_vectors TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE analyses ADD COLUMN authenticated INTEGER NOT NULL DEFAULT 0",
]


def init_db() -> None:
    conn = get_conn()
    conn.executescript(SCHEMA)
    for statement in MIGRATIONS:
        try:
            conn.execute(statement)
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc).lower():
                raise
    conn.commit()
    # The database holds password hashes and session fingerprints. Nobody but
    # the owning user has any business reading the file.
    try:
        config.DB_PATH.chmod(0o600)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def audit(event: str, *, user_id: Optional[int] = None, username: str = "",
          ip: str = "", detail: str = "", severity: str = "info") -> None:
    """Append-only record of anything security-relevant.

    Best-effort by design: a logging failure must never take down the request
    it was logging, least of all a failed-login path.
    """
    try:
        with transaction() as conn:
            conn.execute(
                "INSERT INTO audit_log (ts, user_id, username, event, severity, ip, detail)"
                " VALUES (?,?,?,?,?,?,?)",
                (_now(), user_id, username[:64], event[:64], severity[:16], ip[:64], detail[:500]),
            )
    except sqlite3.Error:
        pass


def list_audit(limit: int = 200, offset: int = 0) -> List[Dict[str, Any]]:
    rows = get_conn().execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?",
        (max(1, min(limit, 500)), max(0, offset)),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def _row_to_user(row: sqlite3.Row) -> User:
    try:
        perms = json.loads(row["permissions"])
        if not isinstance(perms, list):
            perms = []
    except (json.JSONDecodeError, TypeError):
        perms = []
    return User(
        id=row["id"],
        username=row["username"],
        email=row["email"] or "",
        role=row["role"],
        permissions=[str(p) for p in perms],
        is_active=bool(row["is_active"]),
        must_change_password=bool(row["must_change_password"]),
        created_at=row["created_at"],
        last_login=row["last_login"],
        failed_attempts=row["failed_attempts"],
        locked_until=row["locked_until"],
    )


def get_user_by_name(username: str) -> Optional[User]:
    row = get_conn().execute(
        "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
    ).fetchone()
    return _row_to_user(row) if row else None


def get_user(user_id: int) -> Optional[User]:
    row = get_conn().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _row_to_user(row) if row else None


def get_password_hash(user_id: int) -> Optional[str]:
    """Pulled separately so the hash never rides along inside a User object
    that gets serialised to JSON by accident."""
    row = get_conn().execute(
        "SELECT password_hash FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return row["password_hash"] if row else None


def list_users() -> List[User]:
    rows = get_conn().execute("SELECT * FROM users ORDER BY id").fetchall()
    return [_row_to_user(r) for r in rows]


def count_admins(exclude_id: Optional[int] = None) -> int:
    if exclude_id is not None:
        row = get_conn().execute(
            "SELECT COUNT(*) c FROM users WHERE role='admin' AND is_active=1 AND id != ?",
            (exclude_id,),
        ).fetchone()
    else:
        row = get_conn().execute(
            "SELECT COUNT(*) c FROM users WHERE role='admin' AND is_active=1"
        ).fetchone()
    return row["c"]


def create_user(username: str, password: str, role: str = "viewer", email: str = "",
                permissions: Optional[List[str]] = None, must_change: bool = True,
                created_by: Optional[int] = None) -> User:
    if permissions is None:
        permissions = list(ROLE_PERMISSIONS.get(role, []))
    permissions = sanitise_permissions(permissions)
    with transaction() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, email, password_hash, role, permissions,"
            " is_active, must_change_password, created_at, created_by)"
            " VALUES (?,?,?,?,?,1,?,?,?)",
            (username, email, security.hash_password(password), role,
             json.dumps(permissions), int(must_change), _now(), created_by),
        )
        user_id = cur.lastrowid
    return get_user(user_id)


def sanitise_permissions(permissions: List[str]) -> List[str]:
    """Only permissions this application actually defines survive.

    Stops an admin — or a request that reached this function without one —
    from writing an arbitrary string into the permission set and having some
    future `can("...")` check match it.
    """
    valid = {p.value for p in Permission}
    return sorted({str(p) for p in permissions} & valid)


def update_user(user_id: int, *, email: Optional[str] = None, role: Optional[str] = None,
                permissions: Optional[List[str]] = None, is_active: Optional[bool] = None) -> None:
    sets, params = [], []
    if email is not None:
        sets.append("email = ?"); params.append(email)
    if role is not None:
        sets.append("role = ?"); params.append(role)
    if permissions is not None:
        sets.append("permissions = ?"); params.append(json.dumps(sanitise_permissions(permissions)))
    if is_active is not None:
        sets.append("is_active = ?"); params.append(int(is_active))
    if not sets:
        return
    params.append(user_id)
    with transaction() as conn:
        # Column names come from this function's own literals, never from input.
        conn.execute(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", params)


def set_password(user_id: int, password: str, must_change: bool = False) -> None:
    with transaction() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, must_change_password = ?,"
            " failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (security.hash_password(password), int(must_change), user_id),
        )


def delete_user(user_id: int) -> None:
    with transaction() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


# ---- lockout -------------------------------------------------------------

def register_failed_login(user_id: int) -> Tuple[int, bool]:
    """Increment the counter and lock the account past the threshold.

    Returns (attempts, locked_now). This is the per-account half of brute
    force defence; the per-IP rate limiter is the other half, and both are
    needed — the limiter alone lets a botnet spread attempts across addresses,
    and lockout alone lets one address grind through a whole user list.
    """
    with transaction() as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?",
            (user_id,),
        )
        row = conn.execute(
            "SELECT failed_attempts FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        attempts = row["failed_attempts"] if row else 0
        locked = False
        if attempts >= config.MAX_FAILED_LOGINS:
            until = (datetime.utcnow() + timedelta(minutes=config.LOCKOUT_MINUTES))
            conn.execute(
                "UPDATE users SET locked_until = ? WHERE id = ?",
                (until.isoformat(timespec="seconds"), user_id),
            )
            locked = True
    return attempts, locked


def clear_failed_logins(user_id: int) -> None:
    with transaction() as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL,"
            " last_login = ? WHERE id = ?",
            (_now(), user_id),
        )


def lock_remaining(user: User) -> int:
    """Seconds left on a lockout, 0 if not locked."""
    until = _parse(user.locked_until)
    if not until:
        return 0
    remaining = (until - datetime.utcnow()).total_seconds()
    return max(0, int(remaining))


def unlock_user(user_id: int) -> None:
    with transaction() as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user_id,),
        )


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def create_session(user_id: int, ip: str = "", user_agent: str = "") -> Tuple[str, str]:
    """Mint a session. Returns the (session_token, csrf_token) to hand out.

    Only fingerprints are persisted — the plaintext values exist in this
    function, in the response cookies, and nowhere else.
    """
    token = security.new_token()
    csrf = security.new_token()
    now = datetime.utcnow()
    with transaction() as conn:
        conn.execute(
            "INSERT INTO sessions (user_id, token_hash, csrf_hash, created_at,"
            " last_seen, expires_at, absolute_exp, ip, user_agent)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (
                user_id,
                security.token_fingerprint(token),
                security.token_fingerprint(csrf),
                now.isoformat(timespec="seconds"),
                now.isoformat(timespec="seconds"),
                (now + timedelta(minutes=config.SESSION_IDLE_MINUTES)).isoformat(timespec="seconds"),
                (now + timedelta(hours=config.SESSION_ABSOLUTE_HOURS)).isoformat(timespec="seconds"),
                ip[:64], user_agent[:250],
            ),
        )
    return token, csrf


def lookup_session(token: str) -> Optional[sqlite3.Row]:
    """Resolve a session cookie, enforcing both timeouts. None if unusable."""
    if not token:
        return None
    row = get_conn().execute(
        "SELECT * FROM sessions WHERE token_hash = ? AND revoked = 0",
        (security.token_fingerprint(token),),
    ).fetchone()
    if not row:
        return None
    now = datetime.utcnow()
    idle_exp = _parse(row["expires_at"])
    abs_exp = _parse(row["absolute_exp"])
    if not idle_exp or not abs_exp or now > idle_exp or now > abs_exp:
        revoke_session_by_hash(row["token_hash"])
        return None
    return row


def touch_session(session_id: int) -> None:
    """Slide the idle window forward. The absolute expiry is never extended."""
    now = datetime.utcnow()
    with transaction() as conn:
        conn.execute(
            "UPDATE sessions SET last_seen = ?, expires_at = ? WHERE id = ?",
            (
                now.isoformat(timespec="seconds"),
                (now + timedelta(minutes=config.SESSION_IDLE_MINUTES)).isoformat(timespec="seconds"),
                session_id,
            ),
        )


def revoke_session_by_hash(token_hash: str) -> None:
    with transaction() as conn:
        conn.execute("UPDATE sessions SET revoked = 1 WHERE token_hash = ?", (token_hash,))


def revoke_session(token: str) -> None:
    revoke_session_by_hash(security.token_fingerprint(token))


def revoke_all_sessions(user_id: int) -> int:
    """Kill every session a user holds.

    Called on password change, deactivation, role change and permission
    change. A privilege edit that leaves the old session alive is not an
    edit — the user keeps whatever they had until they happen to log out.
    """
    with transaction() as conn:
        cur = conn.execute(
            "UPDATE sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0", (user_id,)
        )
        return cur.rowcount


def list_sessions(user_id: int) -> List[Dict[str, Any]]:
    rows = get_conn().execute(
        "SELECT id, created_at, last_seen, expires_at, ip, user_agent FROM sessions"
        " WHERE user_id = ? AND revoked = 0 ORDER BY last_seen DESC",
        (user_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def purge_expired_sessions() -> int:
    with transaction() as conn:
        cur = conn.execute(
            "DELETE FROM sessions WHERE revoked = 1 OR absolute_exp < ?",
            (_now(),),
        )
        return cur.rowcount


# ---------------------------------------------------------------------------
# Analyses
# ---------------------------------------------------------------------------

def save_analysis(report: Report, user_id: Optional[int]) -> int:
    with transaction() as conn:
        cur = conn.execute(
            "INSERT INTO analyses (user_id, created_at, subject, sender, verdict,"
            " risk_score, confidence, rules_score, llm_status, signal_count, source,"
            " filename, duration_ms, theft_vectors, authenticated, report_json)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                user_id, _now(), report.email.subject[:300], report.email.from_address[:300],
                report.verdict.value, report.risk_score, report.confidence,
                report.breakdown.rules_score, report.llm_status, len(report.signals),
                report.source, report.filename, report.duration_ms,
                ",".join(report.theft_vectors), int(report.authenticated_sender),
                report.model_dump_json(),
            ),
        )
        return cur.lastrowid


_SORT_COLUMNS = {
    "created_at": "created_at",
    "risk_score": "risk_score",
    "verdict": "verdict",
    "subject": "subject",
}


def list_analyses(user_id: Optional[int] = None, limit: int = 50, offset: int = 0,
                  verdict: Optional[str] = None, search: Optional[str] = None,
                  sort: str = "created_at", direction: str = "desc") -> List[Dict[str, Any]]:
    """History rows.

    user_id=None means "every user's analyses" and is only ever reached
    through a VIEW_ALL_HISTORY check in the route layer.
    """
    where, params = [], []
    if user_id is not None:
        where.append("a.user_id = ?"); params.append(user_id)
    if verdict:
        where.append("a.verdict = ?"); params.append(verdict)
    if search:
        # LIKE with bound parameters. The wildcards are ours, the value is not
        # concatenated in, and the user's own % and _ are escaped so they
        # cannot widen their own query.
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        where.append("(a.subject LIKE ? ESCAPE '\\' OR a.sender LIKE ? ESCAPE '\\')")
        params.extend([f"%{escaped}%", f"%{escaped}%"])
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    # Resolved through a whitelist, never interpolated from the request.
    column = _SORT_COLUMNS.get(sort, "created_at")
    order = "ASC" if str(direction).lower() == "asc" else "DESC"
    params.extend([max(1, min(limit, 200)), max(0, offset)])
    rows = get_conn().execute(
        f"SELECT a.id, a.created_at, a.subject, a.sender, a.verdict, a.risk_score,"
        f" a.confidence, a.signal_count, a.source, a.filename, a.llm_status,"
        f" a.duration_ms, a.theft_vectors, a.authenticated, u.username FROM analyses a"
        f" LEFT JOIN users u ON u.id = a.user_id {clause}"
        f" ORDER BY a.{column} {order}, a.id DESC LIMIT ? OFFSET ?",
        params,
    ).fetchall()
    return [dict(r) for r in rows]


def count_analyses(user_id: Optional[int] = None, verdict: Optional[str] = None,
                   search: Optional[str] = None) -> int:
    where, params = [], []
    if user_id is not None:
        where.append("user_id = ?"); params.append(user_id)
    if verdict:
        where.append("verdict = ?"); params.append(verdict)
    if search:
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        where.append("(subject LIKE ? ESCAPE '\\' OR sender LIKE ? ESCAPE '\\')")
        params.extend([f"%{escaped}%", f"%{escaped}%"])
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    row = get_conn().execute(f"SELECT COUNT(*) c FROM analyses {clause}", params).fetchone()
    return row["c"]


def get_analysis(analysis_id: int) -> Optional[Dict[str, Any]]:
    row = get_conn().execute(
        "SELECT a.*, u.username FROM analyses a LEFT JOIN users u ON u.id = a.user_id"
        " WHERE a.id = ?", (analysis_id,)
    ).fetchone()
    return dict(row) if row else None


def delete_analysis(analysis_id: int) -> None:
    with transaction() as conn:
        conn.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))


def dashboard_stats(user_id: Optional[int] = None) -> Dict[str, Any]:
    """Everything the dashboard shows, computed at request time.

    Nothing here is cached or canned — the numbers are whatever the table
    actually holds right now.
    """
    conn = get_conn()
    scope, params = ("WHERE user_id = ?", [user_id]) if user_id is not None else ("", [])

    total = conn.execute(f"SELECT COUNT(*) c FROM analyses {scope}", params).fetchone()["c"]

    verdict_rows = conn.execute(
        f"SELECT verdict, COUNT(*) c FROM analyses {scope} GROUP BY verdict", params
    ).fetchall()
    verdicts = {r["verdict"]: r["c"] for r in verdict_rows}

    avg_row = conn.execute(
        f"SELECT AVG(risk_score) a, MAX(risk_score) m FROM analyses {scope}", params
    ).fetchone()

    recent = conn.execute(
        f"SELECT id, created_at, subject, sender, verdict, risk_score FROM analyses {scope}"
        f" ORDER BY id DESC LIMIT 8", params
    ).fetchall()

    # Last 14 days of activity for the dashboard chart.
    trend_rows = conn.execute(
        f"SELECT substr(created_at,1,10) d, verdict, COUNT(*) c FROM analyses"
        f" {'WHERE user_id = ? AND' if user_id is not None else 'WHERE'}"
        f" created_at >= ? GROUP BY d, verdict ORDER BY d",
        params + [(datetime.utcnow() - timedelta(days=14)).isoformat(timespec="seconds")],
    ).fetchall()
    trend: Dict[str, Dict[str, int]] = {}
    for r in trend_rows:
        trend.setdefault(r["d"], {})[r["verdict"]] = r["c"]

    # Which detection rules fire most often, across the stored reports.
    top_signals: Dict[str, int] = {}
    for r in conn.execute(
        f"SELECT report_json FROM analyses {scope} ORDER BY id DESC LIMIT 300", params
    ).fetchall():
        try:
            data = json.loads(r["report_json"])
        except (json.JSONDecodeError, TypeError):
            continue
        for sig in data.get("signals", []):
            if sig.get("severity") in ("CRITICAL", "HIGH", "MEDIUM"):
                title = str(sig.get("title", ""))[:80]
                if title:
                    top_signals[title] = top_signals.get(title, 0) + 1

    flagged = verdicts.get("PHISHING", 0) + verdicts.get("SUSPICIOUS", 0) + verdicts.get("SPAM", 0)
    return {
        "total": total,
        "verdicts": verdicts,
        "phishing": verdicts.get("PHISHING", 0),
        "suspicious": verdicts.get("SUSPICIOUS", 0),
        "spam": verdicts.get("SPAM", 0),
        "genuine": verdicts.get("GENUINE", 0),
        "flagged": flagged,
        "flagged_pct": round(flagged / total * 100, 1) if total else 0.0,
        "avg_score": round(avg_row["a"] or 0, 1),
        "max_score": avg_row["m"] or 0,
        "recent": [dict(r) for r in recent],
        "trend": trend,
        "top_signals": sorted(top_signals.items(), key=lambda kv: -kv[1])[:6],
    }


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def bootstrap_admin() -> Optional[Tuple[str, str]]:
    """Create the first admin on an empty database.

    Uses the configured default credentials (Vani/Vani out of the box) so the
    application is usable the moment it starts. The password is stored hashed
    with Argon2id like any other — "default" means predictable, not stored in
    plaintext, and the database is no more readable than it was before.

    The risk this accepts is precise and worth naming: the credential is
    public, so reachability IS authentication. config.HOST is 127.0.0.1 for
    that reason. Setting PEA_DEFAULT_PASSWORD to an empty value swaps this
    back to a random password generated once at first run.
    """
    if get_conn().execute("SELECT COUNT(*) c FROM users").fetchone()["c"] > 0:
        return None

    username = config.DEFAULT_USERNAME
    if config.DEFAULT_PASSWORD:
        password = config.DEFAULT_PASSWORD
        detail = "Initial admin created with the configured default password."
        severity = "critical"
    else:
        password = _readable_password()
        detail = "Initial admin created with a randomly generated password."
        severity = "warning"

    create_user(username, password, role=Role.ADMIN.value,
                permissions=ROLE_PERMISSIONS[Role.ADMIN],
                must_change=config.DEFAULT_FORCE_PASSWORD_CHANGE)
    audit("admin_bootstrapped", username=username, severity=severity, detail=detail)
    return username, password


def _readable_password() -> str:
    words = [
        "harbor", "cobalt", "lantern", "quartz", "meridian", "falcon", "cinder",
        "willow", "onyx", "beacon", "thistle", "verdant", "cipher", "marble",
    ]
    return "{}-{}-{}{}".format(
        secrets.choice(words), secrets.choice(words),
        secrets.randbelow(9000) + 1000, secrets.choice("!@#$%&*"),
    )

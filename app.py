# app.py
# HTTP layer. Owns routing, validation and response shaping — and nothing else.
# It parses no email and judges no message; it hands text to analyzer.analyse()
# and turns the Report into JSON, exactly as main.py turns it into text.
#
#   pip install -r requirements.txt
#   python app.py            -> http://127.0.0.1:8000

import io
import json
import sys
import warnings
from contextlib import asynccontextmanager
from typing import List, Optional

warnings.filterwarnings("ignore", message=".*OpenSSL.*")

from fastapi import (Depends, FastAPI, File, Form, HTTPException, Request,
                     Response, UploadFile, status)
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import analyzer
import auth
import db
import llm as llm_module
import security
from config import config
from models import (Permission, ROLE_PERMISSIONS, Report, Role, User, Verdict)

app = FastAPI(
    title="Phishing Email Analyzer",
    version="1.0.0",
    # The interactive docs are disabled by default. They are a convenience in
    # development and an inventory of the attack surface in production.
    docs_url="/docs" if config.DEBUG else None,
    redoc_url=None,
    openapi_url="/openapi.json" if config.DEBUG else None,
)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """Security headers on every response, plus a global rate limit.

    Applied here rather than per-route so that error responses, static files
    and 404s carry the headers too — the places a per-route decorator misses.
    """
    allowed, retry_after = security.limiter.check(
        f"global:{security.client_ip(request)}", *config.RATE_GLOBAL
    )
    if not allowed:
        response = JSONResponse(
            {"detail": f"Rate limit exceeded. Retry in {retry_after}s."},
            status_code=429, headers={"Retry-After": str(retry_after)},
        )
        security.apply_security_headers(response)
        return response

    # Reject oversized bodies before reading them. Checking Content-Length is
    # advisory — a lying client is caught by the read cap in the upload route —
    # but it stops the honest large request cheaply.
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > config.MAX_UPLOAD_BYTES:
        response = JSONResponse(
            {"detail": f"Request too large (limit {config.MAX_UPLOAD_BYTES:,} bytes)."},
            status_code=413,
        )
        security.apply_security_headers(response)
        return response

    try:
        response = await call_next(request)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        # Never leak a traceback to the client. The detail goes to the audit
        # log and the console; the caller gets a reference, not internals.
        db.audit("unhandled_error", ip=security.client_ip(request), severity="error",
                 detail=f"{type(exc).__name__} at {request.method} {request.url.path}")
        print(f"[error] {type(exc).__name__}: {exc}", file=sys.stderr)
        response = JSONResponse({"detail": "Internal server error."}, status_code=500)

    security.apply_security_headers(response)
    return response


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class AnalyseRequest(BaseModel):
    content: str = Field(min_length=1, max_length=config.MAX_UPLOAD_BYTES)
    use_llm: bool = True
    use_network: bool = False


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=1, max_length=256)
    email: str = Field(default="", max_length=255)
    role: Role = Role.VIEWER
    permissions: Optional[List[str]] = None


class UpdateUserRequest(BaseModel):
    email: Optional[str] = Field(default=None, max_length=255)
    role: Optional[Role] = None
    permissions: Optional[List[str]] = None
    is_active: Optional[bool] = None


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(min_length=1, max_length=256)


# ---------------------------------------------------------------------------
# Auth dependencies
# ---------------------------------------------------------------------------
# These are declared with Depends() rather than called as the first line of
# each handler, and the difference is security-relevant: FastAPI resolves
# dependencies BEFORE it validates the request body. With the check inside the
# body, an unauthenticated caller who posts a malformed payload gets a 422
# describing the expected schema — the API contract handed out for free, and a
# handler that ran validation logic before knowing who was asking. As a
# dependency, the 401 arrives first and nothing else is reached.

AnalyzeUser = Depends(auth.require_permission(Permission.ANALYZE.value))
HistoryUser = Depends(auth.require_permission(Permission.VIEW_HISTORY.value))
DeleteUser = Depends(auth.require_permission(Permission.DELETE_ANALYSIS.value))
ExportUser = Depends(auth.require_permission(Permission.EXPORT.value))
AdminUser = Depends(auth.require_admin)
AuditUser = Depends(auth.require_permission(Permission.VIEW_AUDIT.value))
SessionUser = Depends(auth.require_user)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

def _page(name: str) -> HTMLResponse:
    path = config.TEMPLATE_DIR / name
    if not path.exists():
        raise HTTPException(status_code=404, detail="Page not found")
    return HTMLResponse(path.read_text(encoding="utf-8"))


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    user = auth.get_session_user(request)
    if user is None:
        return _page("login.html")
    if user.must_change_password:
        return _page("change_password.html")
    return _page("app.html")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if auth.get_session_user(request):
        return HTMLResponse('<meta http-equiv="refresh" content="0;url=/">')
    return _page("login.html")


# ---------------------------------------------------------------------------
# Auth API
# ---------------------------------------------------------------------------

@app.post("/api/login")
def login(request: Request, payload: LoginRequest, response: Response):
    """Authenticate and issue a session.

    Deliberate properties:
      * One error message for every failure mode, so the response never
        reveals whether a username exists.
      * Full password-hash CPU spent even when the user is unknown, so timing
        does not reveal it either.
      * Rate limited per IP and locked out per account — both are needed, see
        db.register_failed_login.
      * A fresh session is minted on success; no identifier the client held
        before logging in is reused, which is what prevents session fixation.
    """
    auth.rate_limit(request, "login", *config.RATE_LOGIN)
    ip = security.client_ip(request)
    generic = "Invalid username or password."

    username = payload.username.strip()
    user = db.get_user_by_name(username)

    if user is None:
        security.burn_password_time()
        db.audit("login_failed", username=username[:64], ip=ip, severity="warning",
                 detail="Unknown username")
        raise HTTPException(status_code=401, detail=generic)

    remaining = db.lock_remaining(user)
    if remaining > 0:
        db.audit("login_blocked", user_id=user.id, username=user.username, ip=ip,
                 severity="warning", detail=f"Account locked, {remaining}s remaining")
        raise HTTPException(
            status_code=423,
            detail=f"Account temporarily locked after repeated failed attempts. "
                   f"Try again in {remaining // 60 + 1} minute(s).",
        )

    if not user.is_active:
        security.burn_password_time()
        db.audit("login_failed", user_id=user.id, username=user.username, ip=ip,
                 severity="warning", detail="Account disabled")
        raise HTTPException(status_code=401, detail=generic)

    stored = db.get_password_hash(user.id)
    if not stored or not security.verify_password(payload.password, stored):
        attempts, locked = db.register_failed_login(user.id)
        db.audit("login_failed", user_id=user.id, username=user.username, ip=ip,
                 severity="warning" if not locked else "critical",
                 detail=f"Bad password, attempt {attempts}" + (" — ACCOUNT LOCKED" if locked else ""))
        if locked:
            raise HTTPException(
                status_code=423,
                detail=f"Too many failed attempts. Account locked for "
                       f"{config.LOCKOUT_MINUTES} minutes.",
            )
        raise HTTPException(status_code=401, detail=generic)

    # Transparently upgrade a hash stored under weaker settings.
    if security.needs_rehash(stored):
        db.set_password(user.id, payload.password, must_change=user.must_change_password)

    db.clear_failed_logins(user.id)
    security.limiter.reset(f"login:{ip}")

    token, csrf = db.create_session(
        user.id, ip=ip, user_agent=request.headers.get("user-agent", "")[:250]
    )
    security.set_session_cookie(response, config.SESSION_COOKIE, token,
                                config.SESSION_IDLE_MINUTES * 60)
    security.set_session_cookie(response, config.CSRF_COOKIE, csrf,
                                config.SESSION_IDLE_MINUTES * 60)
    db.audit("login_success", user_id=user.id, username=user.username, ip=ip)

    return {
        "user": _public_user(user),
        "must_change_password": user.must_change_password,
        "csrf_token": csrf,
    }


@app.post("/api/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(config.SESSION_COOKIE)
    user = auth.get_session_user(request)
    if token:
        db.revoke_session(token)
    if user:
        db.audit("logout", user_id=user.id, username=user.username,
                 ip=security.client_ip(request))
    security.clear_cookie(response, config.SESSION_COOKIE)
    security.clear_cookie(response, config.CSRF_COOKIE)
    return {"ok": True}


@app.get("/api/me")
def me(request: Request):
    user = auth.require_user(request)
    row = getattr(request.state, "session_row", None)
    return {
        "user": _public_user(user),
        "must_change_password": user.must_change_password,
        "csrf_token": request.cookies.get(config.CSRF_COOKIE, ""),
        "session": {
            "created_at": row["created_at"] if row else None,
            "expires_at": row["expires_at"] if row else None,
        },
        "llm": llm_module.health(),
        "all_permissions": [p.value for p in Permission],
    }


@app.post("/api/change-password")
def change_password(request: Request, payload: PasswordChangeRequest, response: Response,
                    user: User = SessionUser):
    """Change own password.

    Requires the current password even though the caller is authenticated:
    it stops an attacker with a hijacked session from locking the real owner
    out of their account.
    """
    auth.verify_csrf(request)
    auth.rate_limit(request, "pwchange", 10, 300)

    stored = db.get_password_hash(user.id)
    if not stored or not security.verify_password(payload.current_password, stored):
        db.audit("password_change_failed", user_id=user.id, username=user.username,
                 ip=security.client_ip(request), severity="warning",
                 detail="Current password incorrect")
        raise HTTPException(status_code=401, detail="Current password is incorrect.")

    problems = security.password_problems(payload.new_password, user.username)
    if problems:
        raise HTTPException(status_code=400, detail=" ".join(problems))

    if security.verify_password(payload.new_password, stored):
        raise HTTPException(status_code=400, detail="New password must differ from the current one.")

    db.set_password(user.id, payload.new_password, must_change=False)
    # Every other session for this user dies. If the password was changed
    # because of a suspected compromise, leaving the attacker's session alive
    # would defeat the entire point of the change.
    db.revoke_all_sessions(user.id)

    token, csrf = db.create_session(user.id, ip=security.client_ip(request),
                                    user_agent=request.headers.get("user-agent", "")[:250])
    security.set_session_cookie(response, config.SESSION_COOKIE, token,
                                config.SESSION_IDLE_MINUTES * 60)
    security.set_session_cookie(response, config.CSRF_COOKIE, csrf,
                                config.SESSION_IDLE_MINUTES * 60)
    db.audit("password_changed", user_id=user.id, username=user.username,
             ip=security.client_ip(request), severity="warning",
             detail="All other sessions revoked")
    return {"ok": True, "csrf_token": csrf}


# ---------------------------------------------------------------------------
# Analysis API
# ---------------------------------------------------------------------------

def _decode_upload(data: bytes) -> str:
    """Bytes -> text, trying the encodings email actually arrives in."""
    for encoding in ("utf-8", "utf-8-sig", "latin-1", "cp1252"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def _store_and_return(report: Report, user: User) -> dict:
    report.id = db.save_analysis(report, user.id)
    return json.loads(report.model_dump_json())


@app.post("/api/analyze")
def analyze_text(request: Request, payload: AnalyseRequest, user: User = AnalyzeUser):
    """Analyse pasted content."""
    auth.rate_limit(request, "analyze", *config.RATE_ANALYZE)

    content = payload.content.strip()
    if not content:
        raise HTTPException(status_code=400, detail="Nothing to analyse.")

    report = analyzer.analyse(
        content, source="paste", use_llm=payload.use_llm,
        use_network=payload.use_network and config.ENABLE_URL_EXPANSION,
    )
    db.audit("analysis_run", user_id=user.id, username=user.username,
             ip=security.client_ip(request),
             detail=f"paste -> {report.verdict.value} ({report.risk_score})")
    return _store_and_return(report, user)


@app.post("/api/analyze/upload")
async def analyze_upload(request: Request, file: UploadFile = File(...),
                         use_llm: bool = Form(True), use_network: bool = Form(False),
                         user: User = AnalyzeUser):
    """Analyse an uploaded file.

    The file is read into memory, decoded and discarded. Nothing is written to
    disk, so there is no upload directory to traverse into, serve from, or
    forget to clean up — the class of bug that comes with file storage simply
    does not exist here.
    """
    auth.rate_limit(request, "analyze", *config.RATE_ANALYZE)

    filename = (file.filename or "upload.txt")
    # A filename is a label only. Path components are stripped because it is
    # echoed back into the report and the history list.
    safe_name = filename.replace("\\", "/").split("/")[-1][:120]
    suffix = ("." + safe_name.rsplit(".", 1)[-1].lower()) if "." in safe_name else ""
    if suffix not in config.ALLOWED_UPLOAD_SUFFIXES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{suffix or '(none)'}'. Allowed: "
                   f"{', '.join(sorted(config.ALLOWED_UPLOAD_SUFFIXES))}",
        )

    # Read with a hard cap: one byte past the limit is enough to know the file
    # is too big, and it never gets fully loaded.
    data = await file.read(config.MAX_UPLOAD_BYTES + 1)
    await file.close()
    if len(data) > config.MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds {config.MAX_UPLOAD_BYTES // 1024:,} KB limit.",
        )
    if not data:
        raise HTTPException(status_code=400, detail="File is empty.")

    report = analyzer.analyse(
        _decode_upload(data), source="upload", filename=safe_name,
        use_llm=use_llm, use_network=use_network and config.ENABLE_URL_EXPANSION,
    )
    db.audit("analysis_run", user_id=user.id, username=user.username,
             ip=security.client_ip(request),
             detail=f"upload '{safe_name}' -> {report.verdict.value} ({report.risk_score})")
    return _store_and_return(report, user)


@app.get("/api/history")
def history(request: Request, limit: int = 25, offset: int = 0,
            verdict: Optional[str] = None, search: Optional[str] = None,
            sort: str = "created_at", direction: str = "desc", scope: str = "mine",
            user: User = HistoryUser):
    """History list, scoped by permission.

    A user sees their own analyses. Seeing everyone's requires
    VIEW_ALL_HISTORY, and asking for it without that permission is refused
    rather than silently downgraded — a silent downgrade hides a broken UI and
    a probing attacker equally well.
    """
    if verdict and verdict not in {v.value for v in Verdict}:
        raise HTTPException(status_code=400, detail="Unknown verdict filter.")

    scope_user_id: Optional[int] = user.id
    if scope == "all":
        if not user.can(Permission.VIEW_ALL_HISTORY.value):
            raise HTTPException(
                status_code=403,
                detail="Viewing all users' analyses requires the 'view_all_history' permission.",
            )
        scope_user_id = None

    limit = max(1, min(int(limit), 100))
    offset = max(0, int(offset))
    if search:
        search = str(search)[:100]

    return {
        "items": db.list_analyses(scope_user_id, limit, offset, verdict, search, sort, direction),
        "total": db.count_analyses(scope_user_id, verdict, search),
        "limit": limit,
        "offset": offset,
        "scope": scope,
        "can_view_all": user.can(Permission.VIEW_ALL_HISTORY.value),
    }


def _load_owned_analysis(request: Request, analysis_id: int, user: User) -> dict:
    """Fetch an analysis the caller is allowed to see.

    The ownership check is the important line here. Without it, /api/analysis/5
    returns record 5 to anyone who asks — the reports hold full email bodies,
    so that is a direct read of other people's mail. The same 404 is returned
    for 'does not exist' and 'not yours', so the endpoint cannot be used to
    count how many analyses exist.
    """
    row = db.get_analysis(analysis_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    if row["user_id"] != user.id and not user.can(Permission.VIEW_ALL_HISTORY.value):
        db.audit("idor_attempt", user_id=user.id, username=user.username,
                 ip=security.client_ip(request), severity="warning",
                 detail=f"Requested analysis {analysis_id} owned by user {row['user_id']}")
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return row


@app.get("/api/analysis/{analysis_id}")
def get_analysis(request: Request, analysis_id: int, user: User = HistoryUser):
    row = _load_owned_analysis(request, analysis_id, user)
    try:
        report = json.loads(row["report_json"])
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(status_code=500, detail="Stored report is unreadable.")
    report["id"] = row["id"]
    report["analyst"] = row["username"]
    return report


@app.delete("/api/analysis/{analysis_id}")
def remove_analysis(request: Request, analysis_id: int, user: User = DeleteUser):
    row = _load_owned_analysis(request, analysis_id, user)
    db.delete_analysis(analysis_id)
    db.audit("analysis_deleted", user_id=user.id, username=user.username,
             ip=security.client_ip(request), detail=f"analysis {analysis_id}")
    return {"ok": True}


@app.get("/api/analysis/{analysis_id}/export")
def export_analysis(request: Request, analysis_id: int, user: User = ExportUser):
    row = _load_owned_analysis(request, analysis_id, user)
    return Response(
        content=row["report_json"],
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="analysis-{analysis_id}.json"'},
    )


@app.get("/api/dashboard")
def dashboard(request: Request, scope: str = "mine", user: User = HistoryUser):
    scope_user_id: Optional[int] = user.id
    if scope == "all" and user.can(Permission.VIEW_ALL_HISTORY.value):
        scope_user_id = None
    stats = db.dashboard_stats(scope_user_id)
    stats["llm"] = llm_module.health()
    stats["scope"] = "all" if scope_user_id is None else "mine"
    stats["can_view_all"] = user.can(Permission.VIEW_ALL_HISTORY.value)
    stats["network_enrichment"] = config.ENABLE_URL_EXPANSION
    return stats


# ---------------------------------------------------------------------------
# User administration
# ---------------------------------------------------------------------------

def _public_user(user: User) -> dict:
    """User fields safe to return. The password hash is not among them, and
    is never loaded into a User object in the first place."""
    return {
        "id": user.id, "username": user.username, "email": user.email,
        "role": user.role.value if hasattr(user.role, "value") else user.role,
        "permissions": user.permissions, "is_active": user.is_active,
        "created_at": user.created_at, "last_login": user.last_login,
        "must_change_password": user.must_change_password,
        "locked": db.lock_remaining(user) > 0,
    }


@app.get("/api/users")
def list_users(request: Request, admin: User = AdminUser):
    return {
        "users": [_public_user(u) for u in db.list_users()],
        "roles": {r.value: ROLE_PERMISSIONS[r.value] for r in Role},
        "all_permissions": [p.value for p in Permission],
    }


@app.post("/api/users", status_code=201)
def create_user(request: Request, payload: CreateUserRequest, admin: User = AdminUser):
    username = payload.username.strip()
    if not security.valid_username(username):
        raise HTTPException(
            status_code=400,
            detail="Username must be 3-32 characters: letters, digits, dot, underscore or hyphen, starting alphanumeric.",
        )
    if db.get_user_by_name(username):
        raise HTTPException(status_code=409, detail="That username is already taken.")
    if payload.email and not security.safe_email(payload.email):
        raise HTTPException(status_code=400, detail="Email address is not valid.")

    problems = security.password_problems(payload.password, username)
    if problems:
        raise HTTPException(status_code=400, detail=" ".join(problems))

    role = payload.role.value
    permissions = payload.permissions if payload.permissions is not None else ROLE_PERMISSIONS[role]
    # Sanitised in db.create_user too; done here as well so the audit entry
    # records what was actually granted rather than what was requested.
    permissions = db.sanitise_permissions(permissions)

    user = db.create_user(username, payload.password, role=role, email=payload.email.strip(),
                          permissions=permissions, must_change=True, created_by=admin.id)
    db.audit("user_created", user_id=admin.id, username=admin.username,
             ip=security.client_ip(request), severity="warning",
             detail=f"Created '{username}' role={role} perms={','.join(permissions)}")
    return _public_user(user)


@app.patch("/api/users/{user_id}")
def update_user(request: Request, user_id: int, payload: UpdateUserRequest,
                admin: User = AdminUser):
    target = db.get_user(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")

    # Guard rails against an admin locking everyone out of administration.
    # These are correctness, not security — but an application with no
    # reachable admin account is just as unusable as a compromised one.
    if target.id == admin.id:
        if payload.is_active is False:
            raise HTTPException(status_code=400, detail="You cannot deactivate your own account.")
        if payload.role is not None and payload.role != Role.ADMIN:
            raise HTTPException(status_code=400, detail="You cannot remove your own admin role.")

    demoting = (payload.role is not None and payload.role != Role.ADMIN) or payload.is_active is False
    if target.role == Role.ADMIN and demoting and db.count_admins(exclude_id=target.id) == 0:
        raise HTTPException(status_code=400, detail="This is the last active admin account.")

    if payload.email is not None and payload.email and not security.safe_email(payload.email):
        raise HTTPException(status_code=400, detail="Email address is not valid.")

    permissions = payload.permissions
    if payload.role is not None and permissions is None:
        permissions = ROLE_PERMISSIONS[payload.role.value]

    db.update_user(
        user_id,
        email=payload.email,
        role=payload.role.value if payload.role else None,
        permissions=permissions,
        is_active=payload.is_active,
    )

    # A privilege change that leaves existing sessions alive is not a change:
    # the user keeps what they had until they happen to log out. Revoking
    # forces the new grants to take effect immediately.
    revoked = 0
    if payload.role is not None or permissions is not None or payload.is_active is False:
        revoked = db.revoke_all_sessions(user_id)

    db.audit("user_updated", user_id=admin.id, username=admin.username,
             ip=security.client_ip(request), severity="warning",
             detail=f"Updated '{target.username}' role={payload.role} "
                    f"active={payload.is_active} sessions_revoked={revoked}")
    return _public_user(db.get_user(user_id))


@app.post("/api/users/{user_id}/password")
def reset_password(request: Request, user_id: int, payload: ResetPasswordRequest,
                   admin: User = AdminUser):
    target = db.get_user(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")

    problems = security.password_problems(payload.new_password, target.username)
    if problems:
        raise HTTPException(status_code=400, detail=" ".join(problems))

    db.set_password(user_id, payload.new_password, must_change=True)
    revoked = db.revoke_all_sessions(user_id)
    db.audit("password_reset", user_id=admin.id, username=admin.username,
             ip=security.client_ip(request), severity="warning",
             detail=f"Reset password for '{target.username}', {revoked} session(s) revoked")
    return {"ok": True, "must_change_password": True, "sessions_revoked": revoked}


@app.post("/api/users/{user_id}/unlock")
def unlock(request: Request, user_id: int, admin: User = AdminUser):
    target = db.get_user(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")
    db.unlock_user(user_id)
    db.audit("user_unlocked", user_id=admin.id, username=admin.username,
             ip=security.client_ip(request), detail=f"Unlocked '{target.username}'")
    return {"ok": True}


@app.delete("/api/users/{user_id}")
def delete_user(request: Request, user_id: int, admin: User = AdminUser):
    target = db.get_user(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")
    if target.id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")
    if target.role == Role.ADMIN and db.count_admins(exclude_id=target.id) == 0:
        raise HTTPException(status_code=400, detail="This is the last active admin account.")

    db.revoke_all_sessions(user_id)
    db.delete_user(user_id)
    db.audit("user_deleted", user_id=admin.id, username=admin.username,
             ip=security.client_ip(request), severity="critical",
             detail=f"Deleted '{target.username}'")
    return {"ok": True}


@app.get("/api/audit")
def audit_log(request: Request, limit: int = 100, offset: int = 0,
              user: User = AuditUser):
    return {"items": db.list_audit(max(1, min(int(limit), 300)), max(0, int(offset)))}


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

@app.get("/api/samples")
def samples(request: Request, user: User = SessionUser):
    """Bundled example emails, for trying the analyser without hunting for one."""
    out = []
    if config.SAMPLES_DIR.exists():
        for path in sorted(config.SAMPLES_DIR.glob("*.eml")):
            try:
                out.append({
                    "name": path.stem.replace("-", " ").replace("_", " ").title(),
                    "filename": path.name,
                    "content": path.read_text(encoding="utf-8", errors="replace")[:100000],
                })
            except OSError:
                continue
    return {"samples": out}


@app.get("/api/health")
def health():
    """Unauthenticated liveness check. Deliberately says almost nothing —
    a health endpoint that reports versions and configuration is free
    reconnaissance."""
    return {"status": "ok"}


app.mount("/static", StaticFiles(directory=str(config.STATIC_DIR)), name="static")


def startup():
    db.init_db()
    boot = db.bootstrap_admin()
    db.purge_expired_sessions()

    print("\n" + "=" * 72)
    print("  Phishing Email Analyzer")
    print("=" * 72)
    if boot:
        username, password = boot
        print("\n  FIRST RUN — an administrator account has been created.")
        print(f"\n      username:  {username}")
        print(f"      password:  {password}")
        if config.uses_default_credentials:
            print("\n  These are the configured DEFAULT credentials. They are published in")
            print("  the README, so treat network reachability as full admin access:")
            print("  keep this bound to 127.0.0.1 and change the password before any")
            print("  deployment that is reachable by anyone else.\n")
        else:
            print("\n  This password is shown once and must be changed at first login.")
            print("  It was generated randomly; there is no default credential.\n")
    print(f"  Mode      : {llm_module.health()['mode']}{' — ' + ' -> '.join(llm_module.health()['chain']) if config.llm_configured else ' (no API key configured)'}")
    print(f"  Database  : {config.DB_PATH}")
    print(f"  URL       : http://{config.HOST}:{config.PORT}")
    if not boot and config.uses_default_credentials:
        existing = db.get_user_by_name(config.DEFAULT_USERNAME)
        if existing:
            print(f"  Sign in    : {config.DEFAULT_USERNAME} / {config.DEFAULT_PASSWORD}"
                  f"  (default credentials)")
    for warning in config.warnings():
        print(f"  ! {warning}")
    print("=" * 72 + "\n")
    # Explicit flush: stdout is block-buffered when this is not a terminal
    # (run under a process manager, piped to a log, inside Docker). The
    # generated admin password is printed exactly once and must not be lost
    # in a buffer that never fills.
    sys.stdout.flush()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    startup()
    yield


app.router.lifespan_context = lifespan


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host=config.HOST, port=config.PORT,
                reload=config.DEBUG, log_level="info" if config.DEBUG else "warning")

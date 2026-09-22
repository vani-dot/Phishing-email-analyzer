# auth.py
# Request-level authentication and authorisation for the FastAPI app.
#
# The chain every protected request goes through:
#   cookie -> session lookup (fingerprint, not the token) -> expiry checks
#          -> user load -> active check -> CSRF (on writes) -> permission check
#
# Each step fails closed. A missing cookie, an unknown session, an expired
# session, a deactivated user and a missing permission all end the request;
# none of them fall through to a default-allow.

from typing import Optional

from fastapi import HTTPException, Request, status

import db
import security
from config import config
from models import Permission, User

# Methods that change state and therefore require a CSRF token. GET, HEAD and
# OPTIONS are exempt because they must be safe by definition — and any GET in
# this app that is NOT safe would be the bug, not the exemption.
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class AuthError(HTTPException):
    def __init__(self, detail: str = "Authentication required", code: int = 401):
        super().__init__(status_code=code, detail=detail)


def get_session_user(request: Request) -> Optional[User]:
    """Resolve the caller from their session cookie, or None.

    Also slides the idle timeout forward. Does not raise — routes that allow
    anonymous access use this directly, protected routes use require_user.
    """
    token = request.cookies.get(config.SESSION_COOKIE)
    if not token:
        return None

    row = db.lookup_session(token)
    if row is None:
        return None

    user = db.get_user(row["user_id"])
    if user is None or not user.is_active:
        # The account was deleted or disabled after the session was issued.
        # Kill the session now rather than letting it run to expiry.
        db.revoke_session(token)
        return None

    db.touch_session(row["id"])
    # Stashed so route handlers can validate CSRF without a second lookup.
    request.state.session_row = row
    request.state.session_token = token
    return user


def require_user(request: Request) -> User:
    user = get_session_user(request)
    if user is None:
        raise AuthError()
    return user


def verify_csrf(request: Request) -> None:
    """Double-submit CSRF check, bound to the session.

    The token is delivered in a JS-readable cookie and must be echoed in a
    request header. An attacker's page on another origin can cause the browser
    to SEND our cookies, but the same-origin policy stops it READING them, so
    it cannot produce the header. SameSite=Strict blocks the cross-site
    request in the first place; this is the second layer, for the case where
    SameSite is unsupported or bypassed.

    Comparison is against the session's stored fingerprint, so a token from
    one session cannot be replayed against another.
    """
    if request.method not in UNSAFE_METHODS:
        return

    row = getattr(request.state, "session_row", None)
    if row is None:
        raise AuthError("Session required for this action")

    presented = request.headers.get(config.CSRF_HEADER, "")
    if not presented:
        raise AuthError("Missing CSRF token", code=403)

    if not security.tokens_match(security.token_fingerprint(presented), row["csrf_hash"]):
        db.audit("csrf_failure", user_id=row["user_id"],
                 ip=security.client_ip(request), severity="warning",
                 detail=f"{request.method} {request.url.path}")
        raise AuthError("CSRF validation failed", code=403)


def require_auth(request: Request) -> User:
    """Authenticated user, with CSRF enforced on state-changing methods."""
    user = require_user(request)
    verify_csrf(request)
    return user


def require_permission(permission: str):
    """Dependency factory: authenticated AND holding a specific permission."""
    def dependency(request: Request) -> User:
        user = require_auth(request)
        if not user.can(permission):
            db.audit("permission_denied", user_id=user.id, username=user.username,
                     ip=security.client_ip(request), severity="warning",
                     detail=f"{permission} for {request.method} {request.url.path}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires the '{permission}' permission.",
            )
        return user
    return dependency


def require_admin(request: Request) -> User:
    return require_permission(Permission.MANAGE_USERS.value)(request)


def rate_limit(request: Request, bucket: str, limit: int, window: int) -> None:
    """Apply a named rate limit, keyed by client address."""
    key = f"{bucket}:{security.client_ip(request)}"
    allowed, retry_after = security.limiter.check(key, limit, window)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many requests. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )

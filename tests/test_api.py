"""End-to-end HTTP tests: auth, CSRF, permissions, IDOR, limits."""

import io

import pytest
from conftest import GENUINE_EML, PHISHING_EML
from fastapi.testclient import TestClient

import db
import security
from app import app
from config import config

ADMIN_PW = "AdminTestPass!99x"
ANALYST_PW = "AnalystPass!77y"


@pytest.fixture
def client(clean_db):
    db.create_user("admin", ADMIN_PW, role="admin", must_change=False)
    db.create_user("analyst", ANALYST_PW, role="analyst", must_change=False)
    db.create_user("viewer", ANALYST_PW, role="viewer", must_change=False)
    # The limiter is process-global; a previous test's hits would otherwise
    # leak into this one and cause spurious 429s.
    security.limiter._hits.clear()
    with TestClient(app) as test_client:
        yield test_client


def login(client, username, password):
    response = client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return client.cookies.get(config.CSRF_COOKIE)


def auth_headers(csrf):
    return {config.CSRF_HEADER: csrf}


# ---- unauthenticated access ----------------------------------------------

@pytest.mark.parametrize("method,path", [
    ("get", "/api/me"), ("get", "/api/dashboard"), ("get", "/api/history"),
    ("get", "/api/users"), ("get", "/api/audit"), ("get", "/api/analysis/1"),
    ("post", "/api/analyze"), ("delete", "/api/analysis/1"),
])
def test_endpoints_require_authentication(client, method, path):
    response = getattr(client, method)(path)
    assert response.status_code in (401, 403), f"{path} returned {response.status_code}"


def test_health_is_public_and_says_little(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_security_headers_present(client):
    headers = client.get("/api/health").headers
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert "script-src 'self'" in headers["content-security-policy"]
    assert "unsafe-inline" not in headers["content-security-policy"]
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert "no-store" in headers["cache-control"]


# ---- login ----------------------------------------------------------------

def test_login_success_sets_both_cookies(client):
    response = client.post("/api/login", json={"username": "admin", "password": ADMIN_PW})
    assert response.status_code == 200
    assert config.SESSION_COOKIE in response.cookies
    assert config.CSRF_COOKIE in response.cookies


def test_session_cookie_is_httponly_and_samesite(client):
    response = client.post("/api/login", json={"username": "admin", "password": ADMIN_PW})
    cookie_headers = [v for k, v in response.headers.items() if k.lower() == "set-cookie"]
    raw = " ".join(cookie_headers) if cookie_headers else str(response.headers)
    session_line = [line for line in raw.split(",") if config.SESSION_COOKIE in line]
    combined = " ".join(session_line).lower()
    assert "httponly" in combined
    assert "samesite=strict" in combined


def test_wrong_password_and_unknown_user_are_indistinguishable(client):
    bad_user = client.post("/api/login", json={"username": "ghost", "password": "Whatever!123x"})
    bad_pass = client.post("/api/login", json={"username": "admin", "password": "Whatever!123x"})
    assert bad_user.status_code == bad_pass.status_code == 401
    assert bad_user.json()["detail"] == bad_pass.json()["detail"]


def test_inactive_account_cannot_log_in(client):
    user = db.get_user_by_name("analyst")
    db.update_user(user.id, is_active=False)
    response = client.post("/api/login", json={"username": "analyst", "password": ANALYST_PW})
    assert response.status_code == 401


def test_lockout_after_repeated_failures(client):
    for _ in range(config.MAX_FAILED_LOGINS):
        client.post("/api/login", json={"username": "viewer", "password": "WrongPass!123"})
    response = client.post("/api/login", json={"username": "viewer", "password": ANALYST_PW})
    assert response.status_code == 423, "correct password must still be refused while locked"


def test_logout_revokes_the_session(client):
    csrf = login(client, "admin", ADMIN_PW)
    assert client.get("/api/me").status_code == 200
    client.post("/api/logout", headers=auth_headers(csrf))
    assert client.get("/api/me").status_code == 401


# ---- CSRF -----------------------------------------------------------------

def test_post_without_csrf_header_is_refused(client):
    login(client, "admin", ADMIN_PW)
    response = client.post("/api/analyze", json={"content": "test"})
    assert response.status_code == 403


def test_post_with_forged_csrf_is_refused(client):
    login(client, "admin", ADMIN_PW)
    response = client.post("/api/analyze", json={"content": "test"},
                           headers={config.CSRF_HEADER: security.new_token()})
    assert response.status_code == 403


def test_get_requests_need_no_csrf(client):
    login(client, "admin", ADMIN_PW)
    assert client.get("/api/dashboard").status_code == 200


# ---- analysis -------------------------------------------------------------

def test_analyse_paste(client):
    csrf = login(client, "analyst", ANALYST_PW)
    response = client.post("/api/analyze", json={"content": PHISHING_EML},
                           headers=auth_headers(csrf))
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "PHISHING"
    assert body["risk_score"] >= 70
    assert body["id"] is not None
    assert body["llm_status"] == "disabled"


def test_analyse_genuine(client):
    csrf = login(client, "analyst", ANALYST_PW)
    body = client.post("/api/analyze", json={"content": GENUINE_EML},
                       headers=auth_headers(csrf)).json()
    assert body["verdict"] == "GENUINE"


def test_empty_content_rejected(client):
    csrf = login(client, "analyst", ANALYST_PW)
    response = client.post("/api/analyze", json={"content": "   "}, headers=auth_headers(csrf))
    assert response.status_code == 400


def test_upload_accepts_eml(client):
    csrf = login(client, "analyst", ANALYST_PW)
    response = client.post(
        "/api/analyze/upload",
        files={"file": ("sample.eml", io.BytesIO(PHISHING_EML.encode()), "message/rfc822")},
        data={"use_llm": "false"}, headers=auth_headers(csrf))
    assert response.status_code == 200
    assert response.json()["source"] == "upload"


def test_upload_rejects_disallowed_extension(client):
    csrf = login(client, "analyst", ANALYST_PW)
    response = client.post(
        "/api/analyze/upload",
        files={"file": ("payload.exe", io.BytesIO(b"MZ\x90\x00"), "application/octet-stream")},
        headers=auth_headers(csrf))
    assert response.status_code == 400


def test_upload_rejects_oversized_file(client):
    csrf = login(client, "analyst", ANALYST_PW)
    oversized = b"A" * (config.MAX_UPLOAD_BYTES + 2048)
    response = client.post(
        "/api/analyze/upload",
        files={"file": ("big.eml", io.BytesIO(oversized), "message/rfc822")},
        headers=auth_headers(csrf))
    assert response.status_code == 413


def test_xss_payload_is_returned_as_data(client):
    csrf = login(client, "analyst", ANALYST_PW)
    raw = ('From: "<img src=x onerror=alert(1)>" <a@evil.tk>\nTo: b@c.com\n'
           'Subject: <script>alert(document.cookie)</script>\n\nbody')
    body = client.post("/api/analyze", json={"content": raw},
                       headers=auth_headers(csrf)).json()
    # Stored and returned verbatim as a JSON string. The front end assigns it
    # via textContent, so it is displayed rather than parsed.
    assert "<script>" in body["email"]["subject"]
    assert response_is_json(client.post("/api/analyze", json={"content": raw},
                                        headers=auth_headers(csrf)))


def response_is_json(response):
    return "application/json" in response.headers.get("content-type", "")


# ---- history and IDOR -----------------------------------------------------

def test_history_is_scoped_to_the_owner(client):
    csrf = login(client, "analyst", ANALYST_PW)
    client.post("/api/analyze", json={"content": PHISHING_EML}, headers=auth_headers(csrf))
    client.post("/api/logout", headers=auth_headers(csrf))

    csrf = login(client, "viewer", ANALYST_PW)
    assert client.get("/api/history").json()["total"] == 0


def test_idor_returns_404_not_403(client):
    csrf = login(client, "analyst", ANALYST_PW)
    analysis_id = client.post("/api/analyze", json={"content": PHISHING_EML},
                              headers=auth_headers(csrf)).json()["id"]
    client.post("/api/logout", headers=auth_headers(csrf))

    login(client, "viewer", ANALYST_PW)
    response = client.get(f"/api/analysis/{analysis_id}")
    # 404 rather than 403: a 403 would confirm the record exists, which lets
    # an attacker enumerate how many analyses the system holds.
    assert response.status_code == 404


def test_idor_attempt_is_audited(client):
    csrf = login(client, "analyst", ANALYST_PW)
    analysis_id = client.post("/api/analyze", json={"content": PHISHING_EML},
                              headers=auth_headers(csrf)).json()["id"]
    client.post("/api/logout", headers=auth_headers(csrf))
    login(client, "viewer", ANALYST_PW)
    client.get(f"/api/analysis/{analysis_id}")
    events = [row["event"] for row in db.list_audit(50)]
    assert "idor_attempt" in events


def test_admin_can_read_any_analysis(client):
    csrf = login(client, "analyst", ANALYST_PW)
    analysis_id = client.post("/api/analyze", json={"content": PHISHING_EML},
                              headers=auth_headers(csrf)).json()["id"]
    client.post("/api/logout", headers=auth_headers(csrf))
    login(client, "admin", ADMIN_PW)
    assert client.get(f"/api/analysis/{analysis_id}").status_code == 200


def test_scope_all_requires_permission(client):
    login(client, "analyst", ANALYST_PW)
    assert client.get("/api/history?scope=all").status_code == 403


def test_invalid_verdict_filter_rejected(client):
    login(client, "analyst", ANALYST_PW)
    assert client.get("/api/history?verdict=NONSENSE").status_code == 400


# ---- permissions ----------------------------------------------------------

def test_viewer_cannot_analyse(client):
    csrf = login(client, "viewer", ANALYST_PW)
    response = client.post("/api/analyze", json={"content": PHISHING_EML},
                           headers=auth_headers(csrf))
    assert response.status_code == 403


def test_analyst_cannot_manage_users(client):
    csrf = login(client, "analyst", ANALYST_PW)
    assert client.get("/api/users").status_code == 403
    assert client.post("/api/users", json={"username": "x", "password": "Whatever!123x"},
                       headers=auth_headers(csrf)).status_code == 403


def test_analyst_cannot_read_audit_log(client):
    login(client, "analyst", ANALYST_PW)
    assert client.get("/api/audit").status_code == 403


# ---- user administration --------------------------------------------------

def test_admin_creates_user(client):
    csrf = login(client, "admin", ADMIN_PW)
    response = client.post("/api/users", headers=auth_headers(csrf), json={
        "username": "newuser", "password": "BrandNewPass!42", "role": "analyst"})
    assert response.status_code == 201
    body = response.json()
    assert body["must_change_password"] is True
    assert "password" not in str(body).lower() or "must_change_password" in body


def test_weak_password_rejected_on_create(client):
    csrf = login(client, "admin", ADMIN_PW)
    response = client.post("/api/users", headers=auth_headers(csrf), json={
        "username": "weakling", "password": "password123", "role": "viewer"})
    assert response.status_code == 400


def test_duplicate_username_rejected(client):
    csrf = login(client, "admin", ADMIN_PW)
    response = client.post("/api/users", headers=auth_headers(csrf), json={
        "username": "analyst", "password": "BrandNewPass!42", "role": "viewer"})
    assert response.status_code == 409


def test_unknown_permission_is_stripped(client):
    csrf = login(client, "admin", ADMIN_PW)
    body = client.post("/api/users", headers=auth_headers(csrf), json={
        "username": "permtest", "password": "BrandNewPass!42", "role": "viewer",
        "permissions": ["analyze", "become_root", "manage_users"]}).json()
    assert "become_root" not in body["permissions"]
    assert set(body["permissions"]) <= {"analyze", "manage_users"}


def test_permission_change_revokes_sessions(client):
    # analyst logs in and holds a session
    analyst_client = TestClient(app)
    analyst_client.post("/api/login", json={"username": "analyst", "password": ANALYST_PW})
    assert analyst_client.get("/api/me").status_code == 200

    csrf = login(client, "admin", ADMIN_PW)
    target = db.get_user_by_name("analyst")
    client.patch(f"/api/users/{target.id}", headers=auth_headers(csrf),
                 json={"role": "viewer"})

    # The old session must not survive a privilege change.
    assert analyst_client.get("/api/me").status_code == 401


def test_admin_cannot_deactivate_self(client):
    csrf = login(client, "admin", ADMIN_PW)
    admin = db.get_user_by_name("admin")
    response = client.patch(f"/api/users/{admin.id}", headers=auth_headers(csrf),
                            json={"is_active": False})
    assert response.status_code == 400


def test_admin_cannot_delete_self(client):
    csrf = login(client, "admin", ADMIN_PW)
    admin = db.get_user_by_name("admin")
    assert client.delete(f"/api/users/{admin.id}", headers=auth_headers(csrf)).status_code == 400


def test_last_admin_cannot_be_demoted(client):
    csrf = login(client, "admin", ADMIN_PW)
    admin = db.get_user_by_name("admin")
    response = client.patch(f"/api/users/{admin.id}", headers=auth_headers(csrf),
                            json={"role": "viewer"})
    assert response.status_code == 400


def test_password_change_requires_current_password(client):
    csrf = login(client, "analyst", ANALYST_PW)
    response = client.post("/api/change-password", headers=auth_headers(csrf),
                           json={"current_password": "WrongOne!123",
                                 "new_password": "BrandNewPass!42"})
    assert response.status_code == 401


def test_password_change_revokes_other_sessions(client):
    other = TestClient(app)
    other.post("/api/login", json={"username": "analyst", "password": ANALYST_PW})
    assert other.get("/api/me").status_code == 200

    csrf = login(client, "analyst", ANALYST_PW)
    response = client.post("/api/change-password", headers=auth_headers(csrf),
                           json={"current_password": ANALYST_PW,
                                 "new_password": "BrandNewPass!42"})
    assert response.status_code == 200
    assert other.get("/api/me").status_code == 401


# ---- rate limiting --------------------------------------------------------

def test_login_rate_limit(client):
    limit, _ = config.RATE_LOGIN
    codes = []
    for _ in range(limit + 4):
        codes.append(client.post("/api/login",
                                 json={"username": "ghost", "password": "Nope!12345x"}).status_code)
    assert 429 in codes, "login endpoint must be rate limited"


# ---- dashboard ------------------------------------------------------------

def test_dashboard_counts_are_live(client):
    csrf = login(client, "analyst", ANALYST_PW)
    assert client.get("/api/dashboard").json()["total"] == 0
    client.post("/api/analyze", json={"content": PHISHING_EML}, headers=auth_headers(csrf))
    stats = client.get("/api/dashboard").json()
    assert stats["total"] == 1
    assert stats["phishing"] == 1

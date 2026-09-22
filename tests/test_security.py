"""Authentication primitives and the defences around them."""

import time

import pytest

import db
import netcheck
import security
from config import config
from models import Permission, ROLE_PERMISSIONS, Role


# ---- password hashing -----------------------------------------------------

def test_hash_verify_roundtrip():
    hashed = security.hash_password("CorrectHorseBattery!42")
    assert security.verify_password("CorrectHorseBattery!42", hashed)
    assert not security.verify_password("wrong", hashed)


def test_hashes_are_salted():
    a = security.hash_password("same-password-here!1")
    b = security.hash_password("same-password-here!1")
    assert a != b, "identical passwords must not produce identical hashes"


def test_verify_never_raises_on_hostile_stored_value():
    for stored in ["", "garbage", "$argon2id$broken", "$pbkdf2-sha256$x$y$z",
                   "$pbkdf2-sha256$999999999999$AAAA$AAAA", None]:
        assert security.verify_password("anything", stored) is False


def test_empty_password_rejected():
    assert security.verify_password("", security.hash_password("x" * 12)) is False
    with pytest.raises(ValueError):
        security.hash_password("")


def test_unicode_normalisation():
    # Same text, different Unicode composition, must verify.
    composed = "CaféPassword12!"      # é as one code point
    decomposed = "CaféPassword12!"   # e + combining acute
    assert security.verify_password(decomposed, security.hash_password(composed))


@pytest.mark.parametrize("password,should_fail", [
    ("short", True), ("alllowercaseletters", True), ("password123", True),
    ("PASSWORD1234", True), ("aaaaaaaaaaaa1A!", True),
    ("CorrectHorse!42x", False), ("Tr0ub4dour&Horse", False),
])
def test_password_policy(password, should_fail):
    problems = security.password_problems(password, "someuser")
    assert bool(problems) == should_fail, f"{password}: {problems}"


def test_password_cannot_contain_username():
    assert security.password_problems("MyJaswanth99!x", "jaswanth")


# ---- tokens ---------------------------------------------------------------

def test_tokens_are_unique_and_long():
    tokens = {security.new_token() for _ in range(200)}
    assert len(tokens) == 200
    assert all(len(t) >= 40 for t in tokens)


def test_fingerprint_is_stable_and_one_way():
    token = security.new_token()
    assert security.token_fingerprint(token) == security.token_fingerprint(token)
    assert token not in security.token_fingerprint(token)


def test_token_comparison_rejects_blanks():
    assert security.tokens_match(None, "x") is False
    assert security.tokens_match("x", None) is False
    assert security.tokens_match("", "") is False
    assert security.tokens_match("abc", "abc") is True


# ---- rate limiter ---------------------------------------------------------

def test_rate_limiter_blocks_past_the_limit():
    limiter = security.RateLimiter()
    key = "test-key"
    for _ in range(3):
        assert limiter.check(key, 3, 60)[0] is True
    allowed, retry = limiter.check(key, 3, 60)
    assert allowed is False and retry > 0


def test_rate_limiter_window_expires():
    limiter = security.RateLimiter()
    assert limiter.check("k", 1, 1)[0] is True
    assert limiter.check("k", 1, 1)[0] is False
    time.sleep(1.1)
    assert limiter.check("k", 1, 1)[0] is True


def test_rate_limiter_keys_are_independent():
    limiter = security.RateLimiter()
    assert limiter.check("a", 1, 60)[0] is True
    assert limiter.check("b", 1, 60)[0] is True


def test_rate_limiter_reset():
    limiter = security.RateLimiter()
    limiter.check("k", 1, 60)
    assert limiter.check("k", 1, 60)[0] is False
    limiter.reset("k")
    assert limiter.check("k", 1, 60)[0] is True


# ---- SSRF guard -----------------------------------------------------------

@pytest.mark.parametrize("ip", [
    "127.0.0.1", "127.1.1.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
    "172.31.255.255", "169.254.169.254",   # cloud metadata
    "0.0.0.0", "100.64.0.1", "224.0.0.1", "::1", "fe80::1", "fc00::1",
    "not-an-ip", "",
])
def test_internal_addresses_are_blocked(ip):
    assert netcheck.is_blocked_ip(ip) is True, f"{ip} must be blocked"


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"])
def test_public_addresses_allowed(ip):
    assert netcheck.is_blocked_ip(ip) is False


def test_localhost_resolution_refused():
    ok, detail = netcheck.resolve_safely("localhost")
    assert ok is False
    assert "non-public" in detail or "failed" in detail


def test_expansion_disabled_by_default():
    chain, status = netcheck.expand_redirects("http://example.com")
    assert chain == []
    assert "disabled" in status


# ---- permissions ----------------------------------------------------------

def test_permission_whitelist_drops_unknown_values():
    cleaned = db.sanitise_permissions(["analyze", "made_up_permission", "../../root", ""])
    assert cleaned == ["analyze"]


def test_role_bundles_are_valid_permissions():
    valid = {p.value for p in Permission}
    for role, permissions in ROLE_PERMISSIONS.items():
        assert set(permissions).issubset(valid), f"{role} grants an undefined permission"


def test_admin_has_every_permission():
    assert set(ROLE_PERMISSIONS["admin"]) == {p.value for p in Permission}


def test_inactive_user_holds_no_permissions(clean_db):
    user = clean_db.create_user("tmpuser", "ValidPass!2345", role="admin")
    assert user.can("manage_users")
    clean_db.update_user(user.id, is_active=False)
    assert clean_db.get_user(user.id).can("manage_users") is False


# ---- sessions -------------------------------------------------------------

def test_session_lookup_and_revocation(clean_db):
    user = clean_db.create_user("sessuser", "ValidPass!2345")
    token, csrf = clean_db.create_session(user.id, "1.2.3.4", "agent")
    assert clean_db.lookup_session(token) is not None
    clean_db.revoke_session(token)
    assert clean_db.lookup_session(token) is None


def test_unknown_token_is_rejected(clean_db):
    assert clean_db.lookup_session("not-a-real-token") is None
    assert clean_db.lookup_session("") is None


def test_only_fingerprints_are_stored(clean_db):
    user = clean_db.create_user("fpuser", "ValidPass!2345")
    token, _ = clean_db.create_session(user.id)
    rows = clean_db.get_conn().execute("SELECT token_hash FROM sessions").fetchall()
    assert all(token not in row["token_hash"] for row in rows), \
        "a database read must not yield a usable session cookie"


def test_revoke_all_kills_every_session(clean_db):
    user = clean_db.create_user("multiuser", "ValidPass!2345")
    tokens = [clean_db.create_session(user.id)[0] for _ in range(3)]
    assert clean_db.revoke_all_sessions(user.id) == 3
    assert all(clean_db.lookup_session(t) is None for t in tokens)


def test_password_hash_never_rides_in_user_object(clean_db):
    user = clean_db.create_user("hashuser", "ValidPass!2345")
    assert "password" not in user.model_dump_json().lower() or \
           "password_hash" not in user.model_dump()


# ---- lockout --------------------------------------------------------------

def test_lockout_engages_at_threshold(clean_db):
    user = clean_db.create_user("lockuser", "ValidPass!2345")
    locked = False
    for _ in range(config.MAX_FAILED_LOGINS):
        _, locked = clean_db.register_failed_login(user.id)
    assert locked
    assert clean_db.lock_remaining(clean_db.get_user(user.id)) > 0


def test_successful_login_clears_counter(clean_db):
    user = clean_db.create_user("clearuser", "ValidPass!2345")
    clean_db.register_failed_login(user.id)
    clean_db.clear_failed_logins(user.id)
    assert clean_db.get_user(user.id).failed_attempts == 0


# ---- SQL injection --------------------------------------------------------

@pytest.mark.parametrize("payload", [
    "'; DROP TABLE users;--", "' OR '1'='1", "admin'--",
    "1 UNION SELECT password_hash FROM users", "%", "_", "\\",
])
def test_sql_injection_payloads_are_inert(clean_db, payload):
    clean_db.create_user("realuser", "ValidPass!2345")
    assert clean_db.get_user_by_name(payload) is None
    clean_db.list_analyses(search=payload)
    clean_db.count_analyses(search=payload)
    assert clean_db.get_conn().execute(
        "SELECT COUNT(*) c FROM users").fetchone()["c"] >= 1


def test_sort_parameter_is_whitelisted(clean_db):
    # An unknown sort key falls back to the default rather than reaching SQL.
    clean_db.list_analyses(sort="risk_score; DROP TABLE analyses")
    assert clean_db.get_conn().execute(
        "SELECT COUNT(*) c FROM analyses").fetchone()["c"] == 0


# ---- username validation --------------------------------------------------

@pytest.mark.parametrize("name,valid", [
    ("jaswanth", True), ("user_1", True), ("a.b-c", True),
    ("ab", False), ("_leading", False), ("has space", False),
    ("x" * 40, False), ("drop;table", False), ("", False),
])
def test_username_rules(name, valid):
    assert security.valid_username(name) is valid


# ---- default credentials --------------------------------------------------

def test_bootstrap_creates_the_configured_default_account(clean_db):
    result = clean_db.bootstrap_admin()
    assert result is not None
    username, password = result
    assert username == config.DEFAULT_USERNAME
    assert password == config.DEFAULT_PASSWORD

    user = clean_db.get_user_by_name(config.DEFAULT_USERNAME)
    assert user.role.value == "admin"
    assert user.can("manage_users")
    # The point of a memorable default is skipping the change-on-first-login
    # step, so it must not be forced back on.
    assert user.must_change_password is False


def test_default_password_is_hashed_not_stored_in_the_clear(clean_db):
    clean_db.bootstrap_admin()
    user = clean_db.get_user_by_name(config.DEFAULT_USERNAME)
    stored = clean_db.get_password_hash(user.id)
    assert config.DEFAULT_PASSWORD not in stored
    assert stored.startswith(("$argon2", "$pbkdf2-"))
    assert security.verify_password(config.DEFAULT_PASSWORD, stored)


def test_bootstrap_is_idempotent(clean_db):
    assert clean_db.bootstrap_admin() is not None
    assert clean_db.bootstrap_admin() is None, "must not run again on a populated database"


def test_weak_default_does_not_weaken_the_policy_for_other_accounts():
    """The exemption must be narrow. If the default password would pass the
    policy, the policy has been weakened for everyone."""
    assert security.password_problems(config.DEFAULT_PASSWORD, "someone"), (
        "the default is short by design and must still fail the policy that "
        "governs accounts created through the API"
    )


def test_default_credentials_are_reported_as_a_warning():
    warnings = config.warnings()
    assert any("efault credentials" in w for w in warnings), (
        "an active default credential must be surfaced at startup"
    )


# ---- schema migration -----------------------------------------------------

def test_migration_is_idempotent(clean_db):
    """init_db() runs on every startup, so the column additions must be safe
    to re-run against a database that already has them."""
    clean_db.init_db()
    clean_db.init_db()
    columns = [row[1] for row in clean_db.get_conn().execute("PRAGMA table_info(analyses)")]
    assert "theft_vectors" in columns
    assert "authenticated" in columns


def test_history_row_carries_the_new_fields(clean_db):
    import analyzer
    from conftest import PHISHING_EML
    user = clean_db.create_user("histuser", "ValidPass!2345", role="analyst")
    report = analyzer.analyse(PHISHING_EML, use_llm=False)
    clean_db.save_analysis(report, user.id)
    row = clean_db.list_analyses(user.id)[0]
    assert "theft_vectors" in row and "authenticated" in row
    assert row["theft_vectors"], "a phishing verdict must record its theft vectors"

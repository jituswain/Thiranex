"""
test_app.py
-----------
End-to-end tests using Flask's test client. Run:  python test_app.py

Covers: registration + validation, hashed password storage, SQL-injection
attempts, login, account lockout after repeated failures, session-based
auth (dashboard access before/after login), logout, and the full 2FA
setup + verify flow.
"""

import os
import re
import time

os.environ["SECURE_COOKIES"] = "0"  # test client uses plain http

import db
db.DB_PATH = "test_secure_login.db"
if os.path.exists(db.DB_PATH):
    os.remove(db.DB_PATH)

import app as app_module
import security

flask_app = app_module.app
flask_app.config["TESTING"] = True

passed = 0
failed = 0


def check(label, condition):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {label}")
    else:
        failed += 1
        print(f"  [FAIL] {label}")


def get_csrf(html):
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else None


print("== Registration & validation ==")
with flask_app.test_client() as c:
    r = c.get("/register")
    token = get_csrf(r.get_data(as_text=True))

    # Weak password should be rejected
    r = c.post("/register", data={
        "csrf_token": token, "username": "alice", "email": "alice@example.com",
        "password": "weak", "confirm_password": "weak",
    }, follow_redirects=True)
    check("weak password rejected", b"at least 10 characters" in r.data)

    # Bad email rejected
    r = c.post("/register", data={
        "csrf_token": token, "username": "alice", "email": "not-an-email",
        "password": "Str0ng!Passw0rd", "confirm_password": "Str0ng!Passw0rd",
    }, follow_redirects=True)
    check("invalid email rejected", b"valid email" in r.data)

    # Valid registration succeeds
    r = c.post("/register", data={
        "csrf_token": token, "username": "alice", "email": "alice@example.com",
        "password": "Str0ng!Passw0rd", "confirm_password": "Str0ng!Passw0rd",
    }, follow_redirects=True)
    check("valid registration succeeds", b"Please log in" in r.data or b"Log In" in r.data)

    user = db.get_user_by_username("alice")
    check("user actually created", user is not None)
    check("password is hashed, not stored in plaintext",
          user is not None and user["password_hash"] != "Str0ng!Passw0rd"
          and len(user["password_hash"]) > 20)

    # Duplicate registration rejected
    r = c.post("/register", data={
        "csrf_token": token, "username": "alice", "email": "alice2@example.com",
        "password": "Str0ng!Passw0rd", "confirm_password": "Str0ng!Passw0rd",
    }, follow_redirects=True)
    check("duplicate username rejected", b"already registered" in r.data)

print("\n== CSRF protection ==")
with flask_app.test_client() as c:
    # POST without a valid csrf token should be rejected (400)
    r = c.post("/register", data={
        "username": "csrftest", "email": "csrf@example.com",
        "password": "Str0ng!Passw0rd", "confirm_password": "Str0ng!Passw0rd",
    })
    check("POST without CSRF token rejected (400)", r.status_code == 400)

print("\n== SQL injection resistance ==")
with flask_app.test_client() as c:
    r = c.get("/login")
    token = get_csrf(r.get_data(as_text=True))
    injection_payload = "alice' OR '1'='1"
    r = c.post("/login", data={
        "csrf_token": token, "username": injection_payload, "password": "irrelevant",
    }, follow_redirects=True)
    check("classic OR-1=1 injection does not log in",
          b"Invalid username or password" in r.data)

    # Table-drop attempt should not affect the database
    r = c.get("/login")
    token = get_csrf(r.get_data(as_text=True))
    c.post("/login", data={
        "csrf_token": token, "username": "x'; DROP TABLE users; --", "password": "x",
    })
    check("users table still intact after injection attempt",
          db.get_user_by_username("alice") is not None)

print("\n== Login, dashboard access control, and lockout ==")
with flask_app.test_client() as c:
    # Dashboard requires login
    r = c.get("/dashboard", follow_redirects=True)
    check("dashboard blocked when logged out", b"Please log in" in r.data)

    # Wrong password several times triggers lockout
    for i in range(5):
        r = c.get("/login")
        token = get_csrf(r.get_data(as_text=True))
        r = c.post("/login", data={
            "csrf_token": token, "username": "alice", "password": "WrongPass1!",
        }, follow_redirects=True)

    check("account locked after 5 failed attempts", b"locked" in r.data)

    # Even correct password now fails while locked
    r = c.get("/login")
    token = get_csrf(r.get_data(as_text=True))
    r = c.post("/login", data={
        "csrf_token": token, "username": "alice", "password": "Str0ng!Passw0rd",
    }, follow_redirects=True)
    check("correct password rejected while locked", b"locked" in r.data)

    # Manually clear lockout (simulating time passing) to continue testing
    user = db.get_user_by_username("alice")
    db.reset_failed_login(user["id"])

    r = c.get("/login")
    token = get_csrf(r.get_data(as_text=True))
    r = c.post("/login", data={
        "csrf_token": token, "username": "alice", "password": "Str0ng!Passw0rd",
    }, follow_redirects=True)
    check("correct password after lockout reset logs in", b"Welcome, alice" in r.data)

    r = c.get("/dashboard")
    check("dashboard accessible after login", b"Welcome, alice" in r.data)

    # Logout
    r = c.get("/dashboard")
    token = get_csrf(r.get_data(as_text=True))
    r = c.post("/logout", data={"csrf_token": token}, follow_redirects=True)
    check("logout succeeds", b"logged out" in r.data)

    r = c.get("/dashboard", follow_redirects=True)
    check("dashboard blocked again after logout", b"Please log in" in r.data)

print("\n== Two-Factor Authentication (setup + verify) ==")
with flask_app.test_client() as c:
    r = c.get("/login")
    token = get_csrf(r.get_data(as_text=True))
    c.post("/login", data={
        "csrf_token": token, "username": "alice", "password": "Str0ng!Passw0rd",
    }, follow_redirects=True)

    r = c.get("/setup-2fa")
    html = r.get_data(as_text=True)
    secret_match = re.search(r"<code>([A-Z0-9]+)</code>", html)
    secret = secret_match.group(1) if secret_match else None
    check("2FA setup page returns a secret", secret is not None)

    token = get_csrf(html)
    wrong_code_r = c.post("/setup-2fa", data={"csrf_token": token, "code": "000000"},
                           follow_redirects=True)
    check("wrong 2FA setup code rejected", b"Incorrect code" in wrong_code_r.data)

    r = c.get("/setup-2fa")
    html = r.get_data(as_text=True)
    secret = re.search(r"<code>([A-Z0-9]+)</code>", html).group(1)
    token = get_csrf(html)
    valid_code = security.generate_totp(secret)
    r = c.post("/setup-2fa", data={"csrf_token": token, "code": valid_code}, follow_redirects=True)
    check("correct 2FA code enables 2FA", b"now enabled" in r.data)

    user = db.get_user_by_username("alice")
    check("2FA flag set in DB", bool(user["is_2fa_enabled"]))

    # Log out, then log back in -- should now be prompted for 2FA
    r = c.get("/dashboard")
    token = get_csrf(r.get_data(as_text=True))
    c.post("/logout", data={"csrf_token": token}, follow_redirects=True)

    r = c.get("/login")
    token = get_csrf(r.get_data(as_text=True))
    r = c.post("/login", data={
        "csrf_token": token, "username": "alice", "password": "Str0ng!Passw0rd",
    }, follow_redirects=True)
    check("password-only login now requires 2FA code", b"Two-Factor Verification" in r.data)

    r = c.get("/dashboard", follow_redirects=True)
    check("dashboard still blocked mid-2FA (password alone insufficient)",
          b"Please log in" in r.data)

    token = get_csrf(r.get_data(as_text=True)) or get_csrf(
        c.get("/verify-2fa").get_data(as_text=True))
    r = c.post("/verify-2fa", data={"csrf_token": token, "code": "111111"},
                follow_redirects=True)
    check("wrong 2FA code at login rejected", b"Incorrect code" in r.data)

    valid_code = security.generate_totp(user["otp_secret"])
    r = c.post("/verify-2fa", data={"csrf_token": token, "code": valid_code},
                follow_redirects=True)
    check("correct 2FA code completes login", b"Welcome, alice" in r.data)

os.remove(db.DB_PATH)

print(f"\n{'='*40}\n{passed} passed, {failed} failed\n{'='*40}")
if failed:
    raise SystemExit(1)

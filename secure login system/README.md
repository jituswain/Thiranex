# Secure Login System

A Flask web app implementing registration, login, session management,
account-lockout brute-force protection, and optional TOTP-based 2FA —
built with a minimal dependency footprint so every security-critical line
is easy to read and audit.

## Features

- **Password hashing**: Argon2id (OWASP's #1 recommendation) if
  `argon2-cffi` is installed, otherwise a scrypt-based fallback via
  Werkzeug (also memory-hard and NIST-approved) — auto-detected at
  startup, no code changes needed either way.
- **SQL injection protection**: every database query in `db.py` uses
  parameterized `?` placeholders — user input is never concatenated
  into SQL strings.
- **Input validation**: username, email format, and password-strength
  rules enforced server-side in `security.py` (client-side HTML5
  validation is also present, but never trusted alone).
- **CSRF protection**: synchronizer-token pattern — a per-session token
  is embedded in every form and verified on every POST in
  `before_request`.
- **Session management**: signed, `HttpOnly`, `SameSite=Lax` cookies;
  30-minute expiry; session is fully regenerated on login (prevents
  session-fixation) and fully cleared on logout.
- **Brute-force protection**: 5 failed logins locks the account for 15
  minutes. Error messages are deliberately generic ("Invalid username
  or password") so failed attempts can't be used to enumerate valid
  usernames.
- **2FA (TOTP)**: RFC 6238-compliant implementation (HMAC-SHA1, 30s
  step, 6 digits) from the Python standard library only — compatible
  with Google Authenticator, Authy, 1Password, etc. Verified against
  the official RFC 4226 test vectors in testing.
- **Security headers**: `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, and a baseline `Content-Security-Policy` on every
  response.

## Project layout

```
app.py           Flask routes / views
security.py      Password hashing, TOTP, validators, CSRF helpers
db.py            SQLite access — every query is parameterized
templates/       Jinja2 templates (register, login, 2FA, dashboard)
static/style.css
test_app.py      24 automated end-to-end tests (see below)
requirements.txt
```

## Setup

```bash
pip install -r requirements.txt   # Flask (+ optional argon2-cffi)
python app.py
```

Visit `http://127.0.0.1:5000`. The SQLite database file
(`secure_login.db`) is created automatically on first run.

Environment variables:

- `SECRET_KEY` — signs session cookies. **Set this explicitly in
  production** (e.g. `openssl rand -hex 32`); otherwise a random key is
  generated per process, which invalidates sessions on every restart.
- `SECURE_COOKIES` — defaults to `1` (cookies only sent over HTTPS). Set
  to `0` only for local `http://` development.

## Running the tests

```bash
python test_app.py
```

This exercises: weak-password/invalid-email rejection, password hashing
(confirms plaintext is never stored), duplicate-registration rejection,
CSRF-token enforcement, two classic SQL-injection payloads (`' OR '1'='1`
and `'; DROP TABLE users; --`) against the login form, access-control on
the dashboard before/after login, account lockout after 5 failed
attempts, full logout, and the complete 2FA setup + login flow (both
wrong-code rejection and correct-code success).

## Design notes / what's deliberately NOT included

To keep the app runnable with zero external network dependencies (this
was built and tested offline), a few things a production deployment
would typically add are left as documented next steps rather than
implemented:

- **Rate limiting by IP** (in addition to per-account lockout) — use
  `Flask-Limiter` with a Redis backend in production; an in-memory
  limiter here would not work correctly across multiple server
  processes.
- **Email verification** on registration — currently any syntactically
  valid email is accepted; production should send a confirmation link
  before activating the account.
- **Password reset flow** — not implemented; would need a signed,
  time-limited reset-token flow, again typically sent by email.
- **HTTPS termination** — this app assumes it sits behind a reverse
  proxy (nginx, Caddy, a cloud load balancer) that terminates TLS.
  `SESSION_COOKIE_SECURE=True` (the default here) means cookies simply
  won't be sent at all over plain HTTP in production, by design.
- **QR code image for 2FA setup** — the setup page shows the raw
  secret key and an `otpauth://` URI for manual entry, since QR
  generation needs the `qrcode`/`Pillow` packages. Every authenticator
  app supports "enter key manually" as a first-class alternative to
  scanning, so this doesn't reduce security or usability meaningfully —
  but if you want an actual QR image, `pip install qrcode[pil]` and
  render `security.totp_provisioning_uri(...)` through it.

## Threat model coverage

| Attack | Mitigation |
|---|---|
| Password database leak | Argon2id/scrypt hashing — brute-forcing hashes is computationally expensive |
| SQL injection | 100% parameterized queries |
| CSRF | Per-session synchronizer token, verified on every POST |
| Session hijacking via XSS | `HttpOnly` cookies (JS can't read them) |
| Session fixation | Session fully regenerated on login |
| Brute-force login | Per-account lockout after 5 failures |
| Username enumeration | Generic "invalid username or password" message |
| Credential-stuffing (password-only) | Optional 2FA requires a second factor even with a correct password |
| Clickjacking | `X-Frame-Options: DENY` |
| MIME-sniffing attacks | `X-Content-Type-Options: nosniff` |

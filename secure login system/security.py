"""
security.py
------------
All cryptographic and validation logic lives here, isolated from
routing/view code, so it's easy to audit.

Password hashing
-----------------
Uses Argon2id (OWASP's current #1 recommendation) via `argon2-cffi` if
that package is installed. If it isn't (e.g. offline environment), it
falls back to Werkzeug's `scrypt`-based hashing, which is also a
memory-hard, NIST-approved KDF -- NOT a weaker "just in case" fallback,
but a genuinely secure alternative. Either way, nothing here ever uses
raw SHA-256/MD5 or an unsalted hash for passwords.

To get Argon2id: `pip install argon2-cffi` (see requirements.txt).

2FA (TOTP)
----------
Implements RFC 6238 TOTP from scratch (HMAC-SHA1, 30s step, 6 digits --
identical parameters to Google Authenticator / Authy / 1Password, so
secrets generated here work with any standard authenticator app), using
only `hmac`, `hashlib`, `struct`, and `base64` from the standard library.
"""

import base64
import hashlib
import hmac
import re
import secrets
import struct
import time

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, InvalidHash

    _ph = PasswordHasher(
        time_cost=3,        # OWASP-recommended baseline iterations
        memory_cost=65536,  # 64 MB
        parallelism=4,
        hash_len=32,
        salt_len=16,
    )
    HASH_BACKEND = "argon2id"

    def hash_password(password: str) -> str:
        return _ph.hash(password)

    def verify_password(password_hash: str, password: str) -> bool:
        try:
            return _ph.verify(password_hash, password)
        except (VerifyMismatchError, InvalidHash):
            return False

except ImportError:
    from werkzeug.security import generate_password_hash, check_password_hash

    HASH_BACKEND = "scrypt (argon2-cffi not installed)"

    def hash_password(password: str) -> str:
        # scrypt: memory-hard, salted, NIST-approved (SP 800-132 family).
        return generate_password_hash(password, method="scrypt")

    def verify_password(password_hash: str, password: str) -> bool:
        return check_password_hash(password_hash, password)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_username(username: str) -> str | None:
    """Returns an error message, or None if valid."""
    if not username:
        return "Username is required."
    if not USERNAME_RE.match(username):
        return "Username must be 3-30 characters: letters, numbers, underscore only."
    return None


def validate_email(email: str) -> str | None:
    if not email:
        return "Email is required."
    if len(email) > 254 or not EMAIL_RE.match(email):
        return "Enter a valid email address."
    return None


def validate_password_strength(password: str) -> str | None:
    if not password:
        return "Password is required."
    if len(password) < 10:
        return "Password must be at least 10 characters."
    if not re.search(r"[a-z]", password):
        return "Password must include a lowercase letter."
    if not re.search(r"[A-Z]", password):
        return "Password must include an uppercase letter."
    if not re.search(r"\d", password):
        return "Password must include a digit."
    if not re.search(r"[^\w\s]", password):
        return "Password must include a special character."
    return None


def validate_totp_code(code: str) -> str | None:
    if not code or not re.match(r"^\d{6}$", code):
        return "Enter the 6-digit code from your authenticator app."
    return None


# ---------------------------------------------------------------------------
# TOTP (RFC 6238) for Two-Factor Authentication
# ---------------------------------------------------------------------------

def generate_totp_secret() -> str:
    """20 random bytes, base32-encoded (standard for authenticator apps)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8").rstrip("=")


def _hotp(key: bytes, counter: int, digits: int = 6) -> str:
    """RFC 4226 HOTP."""
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    code = truncated % (10 ** digits)
    return str(code).zfill(digits)


def _decode_secret(secret_b32: str) -> bytes:
    padded = secret_b32 + "=" * ((8 - len(secret_b32) % 8) % 8)
    return base64.b32decode(padded, casefold=True)


def generate_totp(secret_b32: str, for_time: float | None = None, step: int = 30) -> str:
    if for_time is None:
        for_time = time.time()
    counter = int(for_time // step)
    return _hotp(_decode_secret(secret_b32), counter)


def verify_totp(secret_b32: str, code: str, window: int = 1, step: int = 30) -> bool:
    """Accepts codes from the current time step +/- `window` steps to
    tolerate clock drift (standard practice for TOTP)."""
    if not code or not code.isdigit():
        return False
    now = time.time()
    counter = int(now // step)
    key = _decode_secret(secret_b32)
    for offset in range(-window, window + 1):
        candidate = _hotp(key, counter + offset)
        if hmac.compare_digest(candidate, code):
            return True
    return False


def totp_provisioning_uri(secret_b32: str, account_name: str, issuer: str = "SecureLoginApp") -> str:
    """otpauth:// URI that authenticator apps can import (via QR or manual
    entry of the underlying secret)."""
    label = f"{issuer}:{account_name}"
    return (
        f"otpauth://totp/{label}?secret={secret_b32}"
        f"&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    )


# ---------------------------------------------------------------------------
# CSRF tokens (synchronizer token pattern)
# ---------------------------------------------------------------------------

def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_tokens_match(token_a: str, token_b: str) -> bool:
    if not token_a or not token_b:
        return False
    return hmac.compare_digest(token_a, token_b)

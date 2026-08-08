"""
app.py
------
Main Flask application. Routing/view logic only -- crypto lives in
security.py, data access lives in db.py.

Run:
    python app.py
Then visit http://127.0.0.1:5000
"""

import os
import time
from datetime import timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort

import db
import security

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60  # 15 minutes


def create_app():
    app = Flask(__name__)

    # SECRET_KEY signs the session cookie (via itsdangerous). In production
    # this MUST come from a real secret store / env var, never be hardcoded,
    # and never be committed to version control.
    app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)

    app.config.update(
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        SESSION_COOKIE_HTTPONLY=True,      # JS can't read the cookie (mitigates XSS token theft)
        SESSION_COOKIE_SAMESITE="Lax",     # mitigates CSRF via cross-site requests
        # Only send the cookie over HTTPS. Set SECURE_COOKIES=0 for local
        # http:// development; leave it on (default) for anything else.
        SESSION_COOKIE_SECURE=os.environ.get("SECURE_COOKIES", "1") != "0",
    )

    db.init_db()

    # -- Security headers on every response ---------------------------------
    @app.after_request
    def set_security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        return resp

    # -- CSRF enforcement -----------------------------------------------------
    @app.before_request
    def enforce_csrf():
        if request.method == "POST":
            form_token = request.form.get("csrf_token", "")
            session_token = session.get("csrf_token", "")
            if not security.csrf_tokens_match(form_token, session_token):
                abort(400, description="Invalid or missing CSRF token.")

    @app.context_processor
    def inject_csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = security.new_csrf_token()
        return {"csrf_token": session["csrf_token"]}

    # -- Auth helpers -----------------------------------------------------

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                flash("Please log in to continue.", "error")
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    def start_authenticated_session(user_row):
        # Regenerate the CSRF token and rebuild the session on privilege
        # change (login) to prevent session fixation attacks.
        session.clear()
        session.permanent = True
        session["user_id"] = user_row["id"]
        session["username"] = user_row["username"]
        session["csrf_token"] = security.new_csrf_token()

    # -- Routes -------------------------------------------------------------

    @app.route("/")
    def index():
        if session.get("user_id"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "GET":
            return render_template("register.html")

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        for error in (
            security.validate_username(username),
            security.validate_email(email),
            security.validate_password_strength(password),
        ):
            if error:
                flash(error, "error")
                return render_template("register.html", username=username, email=email)

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html", username=username, email=email)

        password_hash = security.hash_password(password)
        user_id = db.create_user(username, email, password_hash)

        if user_id is None:
            flash("That username or email is already registered.", "error")
            return render_template("register.html", username=username, email=email)

        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Deliberately generic error message below: we never reveal
        # whether it was the username or password that was wrong, which
        # prevents username enumeration.
        generic_error = "Invalid username or password."

        user = db.get_user_by_username(username)
        if user is None:
            flash(generic_error, "error")
            return render_template("login.html")

        if user["locked_until"] and user["locked_until"] > time.time():
            minutes_left = int((user["locked_until"] - time.time()) // 60) + 1
            flash(f"Account temporarily locked. Try again in {minutes_left} minute(s).", "error")
            return render_template("login.html")

        if not security.verify_password(user["password_hash"], password):
            attempts = user["failed_attempts"] + 1
            locked_until = None
            if attempts >= MAX_FAILED_ATTEMPTS:
                locked_until = time.time() + LOCKOUT_SECONDS
                flash("Too many failed attempts. Account locked for 15 minutes.", "error")
            else:
                flash(generic_error, "error")
            db.record_failed_login(user["id"], attempts, locked_until)
            return render_template("login.html")

        # Correct password:
        db.reset_failed_login(user["id"])

        if user["is_2fa_enabled"]:
            # Not fully logged in yet -- stash a *pending* identity separate
            # from the real "user_id" session key so 2FA can't be bypassed
            # by an attacker who only knows the password.
            session.clear()
            session["pending_2fa_user_id"] = user["id"]
            return redirect(url_for("verify_2fa"))

        start_authenticated_session(user)
        return redirect(url_for("dashboard"))

    @app.route("/verify-2fa", methods=["GET", "POST"])
    def verify_2fa():
        pending_id = session.get("pending_2fa_user_id")
        if not pending_id:
            return redirect(url_for("login"))

        if request.method == "GET":
            return render_template("verify_2fa.html")

        code = request.form.get("code", "").strip()
        error = security.validate_totp_code(code)
        if error:
            flash(error, "error")
            return render_template("verify_2fa.html")

        user = db.get_user_by_id(pending_id)
        if user is None or not user["otp_secret"]:
            session.clear()
            return redirect(url_for("login"))

        if not security.verify_totp(user["otp_secret"], code):
            flash("Incorrect code. Please try again.", "error")
            return render_template("verify_2fa.html")

        start_authenticated_session(user)
        flash("Logged in successfully.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        user = db.get_user_by_id(session["user_id"])
        if user is None:
            session.clear()
            return redirect(url_for("login"))
        return render_template("dashboard.html", user=user)

    @app.route("/setup-2fa", methods=["GET", "POST"])
    @login_required
    def setup_2fa():
        user = db.get_user_by_id(session["user_id"])

        if request.method == "GET":
            secret = security.generate_totp_secret()
            session["pending_totp_secret"] = secret
            uri = security.totp_provisioning_uri(secret, user["username"])
            return render_template("setup_2fa.html", secret=secret, uri=uri)

        code = request.form.get("code", "").strip()
        pending_secret = session.get("pending_totp_secret")
        if not pending_secret:
            flash("2FA setup session expired. Please start again.", "error")
            return redirect(url_for("setup_2fa"))

        if not security.verify_totp(pending_secret, code):
            flash("Incorrect code. Scan the QR / enter the key again and retry.", "error")
            uri = security.totp_provisioning_uri(pending_secret, user["username"])
            return render_template("setup_2fa.html", secret=pending_secret, uri=uri)

        db.set_pending_2fa_secret_confirmed(user["id"], pending_secret)
        session.pop("pending_totp_secret", None)
        flash("Two-factor authentication is now enabled.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/disable-2fa", methods=["POST"])
    @login_required
    def disable_2fa_route():
        user = db.get_user_by_id(session["user_id"])
        password = request.form.get("password", "")
        if not security.verify_password(user["password_hash"], password):
            flash("Incorrect password. 2FA was not disabled.", "error")
            return redirect(url_for("dashboard"))
        db.disable_2fa(user["id"])
        flash("Two-factor authentication disabled.", "success")
        return redirect(url_for("dashboard"))

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=False, port=5000)

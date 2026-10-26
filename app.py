import hmac
import os
import re
import secrets
import sqlite3

from flask import Flask, redirect, render_template, request, session, url_for
from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

from db import create_user, get_user_by_id, get_user_by_username


app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

USERNAME_PATTERN = re.compile(r"[a-z0-9_]{3,30}")


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    username = ""

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    if request.method == "POST":
        submitted_token = request.form.get("csrf_token", "")

        if not hmac.compare_digest(
            submitted_token,
            session["csrf_token"],
        ):
            return "Form tidak valid. Muat ulang halaman dan coba lagi.", 400

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not USERNAME_PATTERN.fullmatch(username):
            error = (
                "Username harus 3–30 karakter dan hanya boleh "
                "berisi huruf kecil, angka, atau underscore."
            )
        elif len(password) < 15:
            error = "Password minimal 15 karakter."
        elif password != confirm_password:
            error = "Konfirmasi password tidak cocok."
        else:
            password_hash = generate_password_hash(password)

            try:
                create_user(username, password_hash)
            except sqlite3.IntegrityError as exc:
                if exc.sqlite_errorcode == sqlite3.SQLITE_CONSTRAINT_UNIQUE:
                    error = "Username sudah digunakan."
                else:
                    raise
            else:
                session["csrf_token"] = secrets.token_hex(32)
                return redirect(url_for("register", success="1"))

    return render_template(
        "register.html",
        error=error,
        username=username,
        success=request.args.get("success") == "1",
        csrf_token=session["csrf_token"],
    )

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    username = ""

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    if request.method == "POST":
        submitted_token = request.form.get("csrf_token", "")

        if not hmac.compare_digest(
            submitted_token,
            session["csrf_token"],
        ):
            return "Form tidak valid. Muat ulang halaman dan coba lagi.", 400

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if not username or not password:
            error = "Username dan password wajib diisi."
        else:
            user = get_user_by_username(username)

            if user is None:
                error = "Username atau password salah."
            elif not check_password_hash(user["password_hash"], password):
                error = "Username atau password salah."
            else:
                session.clear()
                session["user_id"] = user["id"]

                return redirect(url_for("dashboard"))

    return render_template(
        "login.html",
        error=error,
        username=username,
        csrf_token=session["csrf_token"],
    )


@app.route("/dashboard")
def dashboard():
    user_id = session.get("user_id")

    if user_id is None:
        return redirect(url_for("login"))

    user = get_user_by_id(user_id)

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    return render_template(
        "dashboard.html",
        user=user,
        csrf_token=session["csrf_token"],
    )

@app.route("/logout", methods=["POST"])
def logout():
    submitted_token = request.form.get("csrf_token", "")
    expected_token = session.get("csrf_token")

    if (
        expected_token is None
        or not hmac.compare_digest(submitted_token, expected_token)
    ):
        return "Form tidak valid. Muat ulang halaman dan coba lagi.", 400

    session.clear()

    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run()
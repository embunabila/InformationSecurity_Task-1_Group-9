import hmac
import os
import re
import secrets
import sqlite3
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from zoneinfo import ZoneInfo
from config import load_master_key

from flask import Flask, redirect, render_template, request, session, url_for
from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)


import json

from crypto_core import (
    ALGORITHMS,
    InvalidEnvelopeError,
    decrypt_blob,
    encrypt_blob,
)
from db import (
    create_user,
    get_health_profile_envelopes,
    get_user_by_id,
    get_user_by_username,
    save_health_profile,
)
app = Flask(__name__)

secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError("SECRET_KEY is not configured in the environment.")

app.config["SECRET_KEY"] = secret_key
MASTER_KEY = load_master_key()

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

@app.route("/")
def home():
    return redirect(url_for("login"))


USERNAME_PATTERN = re.compile(r"[a-z0-9_]{3,30}")

PROFILE_FIELDS = (
    "name",
    "birth_date",
    "gender",
    "weight",
    "height",
    "phone",
    "emergency_contact",
    "allergies",
    "health_conditions",
    "routine_medication",
)


def today_jakarta():
    return datetime.now(ZoneInfo("Asia/Jakarta")).date()


def calculate_age(birth_date, today):
    return (
        today.year
        - birth_date.year
        - (
            (today.month, today.day)
            < (birth_date.month, birth_date.day)
        )
    )


def validate_profile(form, today):
    profile = {
        field: form.get(field, "").strip()
        for field in PROFILE_FIELDS
    }
    errors = {}
    age = None

    if not profile["name"]:
        errors["name"] = "Nama wajib diisi."
    elif len(profile["name"]) > 100:
        errors["name"] = "Nama maksimal 100 karakter."

    birth_date_text = profile["birth_date"]

    if not birth_date_text:
        errors["birth_date"] = "Tanggal lahir wajib diisi."
    elif not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", birth_date_text):
        errors["birth_date"] = "Format tanggal lahir harus YYYY-MM-DD."
    else:
        try:
            birth_date = date.fromisoformat(birth_date_text)
        except ValueError:
            errors["birth_date"] = "Tanggal lahir tidak valid."
        else:
            if birth_date > today:
                errors["birth_date"] = "Tanggal lahir tidak boleh di masa depan."
            else:
                age = calculate_age(birth_date, today)

    if profile["gender"] not in {
        "perempuan",
        "laki-laki",
        "tidak disebutkan",
    }:
        errors["gender"] = "Pilih jenis kelamin yang tersedia."

    for field, label in (
        ("weight", "Berat badan"),
        ("height", "Tinggi badan"),
    ):
        value = profile[field]

        if not value:
            profile[field] = None
            continue

        # Bentuk angka desimal biasa, misalnya 60 atau 60.5.
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", value):
            errors[field] = f"{label} harus berupa angka positif."
            continue

        try:
            number = Decimal(value)
        except InvalidOperation:
            errors[field] = f"{label} tidak valid."
        else:
            if not number.is_finite() or number <= 0:
                errors[field] = f"{label} harus berupa angka positif."

    phone = profile["phone"]

    if not phone:
        errors["phone"] = "Nomor HP wajib diisi."
    elif not re.fullmatch(r"[0-9]{1,20}", phone):
        errors["phone"] = "Nomor HP harus 1–20 digit angka."

    for field, label, max_length in (
        ("emergency_contact", "Kontak darurat", 200),
        ("allergies", "Alergi", 1000),
        ("health_conditions", "Kondisi kesehatan", 1000),
        ("routine_medication", "Obat rutin", 1000),
    ):
        if len(profile[field]) > max_length:
            errors[field] = f"{label} maksimal {max_length} karakter."
        elif not profile[field]:
            profile[field] = None

    return profile, errors, age

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

def profile_context(user_id):
    return {
        "owner_id": user_id,
        "kind": "profile",
        "item_id": "profile",
    }


def encrypt_profile(profile, user_id):
    plaintext = json.dumps(
        profile,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    context = profile_context(user_id)

    return {
        algorithm: encrypt_blob(
            plaintext,
            MASTER_KEY,
            algorithm,
            context,
        )
        for algorithm in ALGORITHMS
    }



def decrypt_profile(envelopes, user_id):
    context = profile_context(user_id)

    plaintext = decrypt_blob(
        envelopes["aes_envelope"],
        MASTER_KEY,
        "AES",
        context,
    )

    profile = json.loads(plaintext.decode("utf-8"))

    if not isinstance(profile, dict):
        raise ValueError("Format profil tidak valid.")

    return profile


@app.route("/profile", methods=["GET", "POST"])
def health_profile():
    user_id = session.get("user_id")

    if user_id is None:
        return redirect(url_for("login"))

    user = get_user_by_id(user_id)

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    errors = {}
    valid = False
    age = None
    today = today_jakarta()
    profile = None
    storage_error = False

    try:
        envelopes = get_health_profile_envelopes(user_id)
    except sqlite3.Error: 
        return "Data profil tidak dapat diakses. Coba lagi nanti.", 503

    if envelopes is not None:
        try:
            profile = decrypt_profile(envelopes, user_id)
            birth_date_text = profile.get("birth_date") or ""

            if birth_date_text:
                birth_date = date.fromisoformat(birth_date_text)
                age = calculate_age(birth_date, today)

        except (
            InvalidEnvelopeError,
            ValueError,
            UnicodeDecodeError,
            KeyError,
            TypeError,
        ):
            storage_error = True
            profile = None
            age = None

    if request.method == "POST":
        submitted_token = request.form.get("csrf_token", "")

        if not hmac.compare_digest(
            submitted_token.encode("utf-8"),
            session["csrf_token"].encode("utf-8"),
        ):
            return "Form tidak valid. Muat ulang halaman dan coba lagi.", 400

        if storage_error:
            response = app.make_response((
                "Data profil tidak dapat diverifikasi. Coba lagi nanti.", 503
            ))
            response.headers["Cache-Control"] = "no-store"
            return response
        
        profile, errors, age = validate_profile(request.form, today)
        valid = not errors

        if valid:
            try:
                encrypted = encrypt_profile(profile, user_id)

                save_health_profile(
                    user_id,
                    encrypted["AES"],
                    encrypted["DES"],
                    encrypted["RC4"],
                )
            except (ValueError, TypeError, sqlite3.Error):
                storage_error = True
                valid = False
            else:
                return redirect(url_for("health_profile", saved="1"))

    response = app.make_response(
        render_template(
            "profile.html",
            errors=errors,
            valid=valid,
            age=age,
            today=today.isoformat(),
            csrf_token=session["csrf_token"],
            profile=profile or {},
            saved=request.args.get("saved") == "1",
            storage_error=storage_error,
        )
    )
    response.headers["Cache-Control"] = "no-store"
    return response

if __name__ == "__main__":
    app.run()
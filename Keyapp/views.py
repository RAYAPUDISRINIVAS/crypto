import re
import logging
import bcrypt
import psycopg
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import render
from .db import get_connection

logger = logging.getLogger(__name__)


def _database_unavailable(request):
    logger.exception("Key management database is unavailable.")
    return render(
        request,
        "login.html",
        {
            "error_msg": (
                "Login is temporarily unavailable because the database is not "
                "ready. Please try again later."
            )
        },
        status=503,
    )


# ==============================
# BASIC PAGE
# ==============================
def index(request):
    return render(request, "index.html")


# ==============================
# PASSWORD STRENGTH CHECK
# ==============================
def is_strong_password(pw: str) -> bool:
    """
    Basic password strength rules:
    - min 8 chars
    - at least 1 uppercase, 1 lowercase, 1 digit, 1 special char
    """
    if not pw or len(pw) < 8:
        return False
    if not re.search(r"[A-Z]", pw):
        return False
    if not re.search(r"[a-z]", pw):
        return False
    if not re.search(r"\d", pw):
        return False
    if not re.search(r"[!@#$%^&*()_\-+={[}\]|\\:;\"'<,>.?/]", pw):
        return False
    return True


# ==============================
# SIGNUP
# ==============================
def Signup(request):
    """
    User signup view (PostgreSQL + bcrypt)
    """
    if request.method == "POST":
        username = (request.POST.get("t1") or "").strip()
        password = request.POST.get("t2") or ""
        contact = (request.POST.get("t3") or "").strip()
        email = (request.POST.get("t4") or "").strip()
        address = (request.POST.get("t5") or "").strip()

        if not username:
            return render(request, "signup.html", {"msg": "⚠️ Username is required"})
        if not is_strong_password(password):
            return render(
                request,
                "signup.html",
                {"msg": "⚠️ Password must be 8+ chars with Upper, Lower, Number, Special char"}
            )

        # Hash password with bcrypt
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        password_hash_str = password_hash.decode("utf-8")

        try:
            con = get_connection()
            try:
                with con.cursor() as cur:
                    cur.execute("SELECT id FROM users WHERE username=%s", (username,))
                    user = cur.fetchone()

                    if user:
                        return render(request, "signup.html", {"msg": "⚠️ Username already exists"})

                    cur.execute(
                        """
                        INSERT INTO users (username, password_hash, contact_no, email, address, role)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        (username, password_hash_str, contact, email, address, "user"),
                    )

                return render(request, "login.html", {"msg": "✅ Signup successful! Login now."})
            finally:
                con.close()
        except (ImproperlyConfigured, psycopg.Error):
            logger.exception("Signup database operation failed.")
            return render(
                request,
                "signup.html",
                {"error_msg": "Signup is temporarily unavailable because the database is not ready."},
                status=503,
            )

    return render(request, "signup.html")


# ==============================
# LOGIN
# ==============================
def Login(request):
    """
    User login view (PostgreSQL + bcrypt verify)
    """
    if request.method == "POST":
        username = (request.POST.get("t1") or "").strip()
        password = request.POST.get("t2") or ""

        try:
            con = get_connection()
        except (ImproperlyConfigured, psycopg.Error):
            return _database_unavailable(request)

        try:
            with con.cursor() as cur:
                cur.execute(
                    "SELECT username, password_hash, role FROM users WHERE username=%s",
                    (username,),
                )
                data = cur.fetchone()

            if data and bcrypt.checkpw(password.encode("utf-8"), data["password_hash"].encode("utf-8")):
                request.session["username"] = data["username"]
                request.session["role"] = data["role"]
                return render(request, "user_home.html", {"user": data["username"]})

            return render(request, "login.html", {"msg": "❌ Invalid username or password"})
        except psycopg.Error:
            return _database_unavailable(request)
        finally:
            con.close()

    return render(request, "login.html")

def Logout(request):

    request.session.flush()
    return render(request, "login.html", {"msg": "You have been logged out successfully"})

from django.shortcuts import render, redirect
from .db import get_connection
from .crypto_utils import (
    generate_user_key, wrap_user_key, unwrap_user_key,
    encrypt_with_user_key, decrypt_with_user_key
)

def _require_login(request):
    if not request.session.get("username"):
        return False
    return True

def user_home(request):
    if not _require_login(request):
        return redirect("login")
    return render(request, "user_home.html", {"user": request.session["username"]})


# ==============================
# KEY GENERATION + STORAGE
# ==============================
def generate_key(request):
    if not _require_login(request):
        return redirect("login")

    username = request.session["username"]
    con = get_connection()
    try:
        with con.cursor() as cur:
            # find next version
            cur.execute(
                "SELECT COALESCE(MAX(key_version), 0) AS v FROM user_keys WHERE username=%s",
                (username,)
            )
            row = cur.fetchone()
            next_version = int(row["v"]) + 1

            # deactivate old active keys
            cur.execute(
                "UPDATE user_keys SET is_active=FALSE WHERE username=%s AND is_active=TRUE",
                (username,)
            )

            # create + wrap + store
            user_key = generate_user_key()
            wrapped = wrap_user_key(user_key)

            cur.execute(
                "INSERT INTO user_keys (username, key_version, wrapped_key, is_active) VALUES (%s, %s, %s, TRUE)",
                (username, next_version, wrapped)
            )

        # ✅ store message in session so it shows after redirect
        request.session["msg"] = f"✅ New key generated. Version: {next_version}"
        return redirect("view_keys")

    finally:
        con.close()


from django.shortcuts import render, redirect
from .db import get_connection

def view_keys(request):
    if not _require_login(request):
        return redirect("login")

    username = request.session["username"]
    msg = request.session.pop("msg", None)  # ✅ get + remove message

    con = get_connection()
    try:
        with con.cursor() as cur:
            cur.execute(
                """
                SELECT id, key_version, is_active, created_at, revoked_at
                FROM user_keys
                WHERE username=%s
                ORDER BY key_version DESC
                """,
                (username,)
            )
            keys = cur.fetchall()

            cur.execute(
                "SELECT key_version FROM user_keys WHERE username=%s AND is_active=TRUE LIMIT 1",
                (username,)
            )
            active = cur.fetchone()

        return render(
            request,
            "keys.html",
            {
                "keys": keys,
                "active_version": active["key_version"] if active else None,
                "msg": msg,
                "user": username,
            },
        )
    finally:
        con.close()


# ==============================
# ENCRYPT / DECRYPT DATA
# ==============================
def encrypt_data(request):
    if not _require_login(request):
        return redirect("login")

    username = request.session["username"]

    if request.method == "POST":
        plaintext = request.POST.get("t1", "")

        con = get_connection()
        try:
            with con.cursor() as cur:
                # get active key
                cur.execute(
                    "SELECT key_version, wrapped_key FROM user_keys WHERE username=%s AND is_active=TRUE LIMIT 1",
                    (username,)
                )
                keyrow = cur.fetchone()

                if not keyrow:
                    return render(request, "encrypt.html", {"msg": "⚠️ No active key. Generate a key first."})

                user_key = unwrap_user_key(keyrow["wrapped_key"])
                ciphertext = encrypt_with_user_key(user_key, plaintext)

                cur.execute(
                    "INSERT INTO secure_data (username, key_version, ciphertext) VALUES (%s, %s, %s)",
                    (username, keyrow["key_version"], ciphertext)
                )

            return render(request, "encrypt.html", {"msg": "✅ Data encrypted and stored!", "ciphertext": ciphertext})
        finally:
            con.close()

    return render(request, "encrypt.html")


def list_ciphertexts(request):
    if not _require_login(request):
        return redirect("login")

    username = request.session["username"]
    con = get_connection()
    try:
        with con.cursor() as cur:
            cur.execute(
                "SELECT id, key_version, created_at FROM secure_data WHERE username=%s ORDER BY id DESC",
                (username,)
            )
            items = cur.fetchall()
        return render(request, "cipher_list.html", {"items": items})
    finally:
        con.close()


def decrypt_data(request, item_id):
    if not _require_login(request):
        return redirect("login")

    username = request.session["username"]
    con = get_connection()
    try:
        with con.cursor() as cur:
            cur.execute(
                "SELECT id, key_version, ciphertext FROM secure_data WHERE id=%s AND username=%s",
                (item_id, username)
            )
            item = cur.fetchone()

            if not item:
                return render(request, "decrypt.html", {"msg": "❌ Item not found"})

            # get key used for that ciphertext (by version)
            cur.execute(
                "SELECT wrapped_key FROM user_keys WHERE username=%s AND key_version=%s LIMIT 1",
                (username, item["key_version"])
            )
            keyrow = cur.fetchone()

            if not keyrow:
                return render(request, "decrypt.html", {"msg": "❌ Key for this data is missing (destroyed/revoked)."})

            user_key = unwrap_user_key(keyrow["wrapped_key"])
            plaintext = decrypt_with_user_key(user_key, item["ciphertext"])

        return render(request, "decrypt.html", {"plaintext": plaintext, "key_version": item["key_version"]})
    finally:
        con.close()


# ==============================
# KEY ROTATION / REVOCATION
# ==============================
def revoke_key(request, version):
    if not _require_login(request):
        return redirect("login")

    username = request.session["username"]
    con = get_connection()
    try:
        with con.cursor() as cur:
            cur.execute(
                "UPDATE user_keys SET is_active=FALSE, revoked_at=NOW() WHERE username=%s AND key_version=%s",
                (username, version)
            )
        return redirect("view_keys")
    finally:
        con.close()


# ==============================
# KEY DESTRUCTION (permanent)
# ==============================
def destroy_key(request, version):
    if not _require_login(request):
        return redirect("login")

    username = request.session["username"]
    con = get_connection()
    try:
        with con.cursor() as cur:
            # remove key material entirely
            cur.execute("DELETE FROM user_keys WHERE username=%s AND key_version=%s", (username, version))
        return redirect("view_keys")
    finally:
        con.close()


from django.shortcuts import render, redirect
from .db import get_connection
from .crypto_utils import (
    generate_user_key, wrap_user_key, unwrap_user_key,
    encrypt_with_user_key, decrypt_with_user_key
)

def rotate_and_reencrypt(request):
    if not _require_login(request):
        return redirect("login")

    username = request.session["username"]
    con = get_connection()

    try:
        with con.transaction():
            with con.cursor() as cur:
                cur.execute(
                    "SELECT key_version, wrapped_key FROM user_keys "
                    "WHERE username=%s AND is_active=TRUE LIMIT 1",
                    (username,),
                )
                old_key_row = cur.fetchone()

                if not old_key_row:
                    request.session["msg"] = "⚠️ No active key found. Generate a key first."
                    return redirect("view_keys")

                old_version = int(old_key_row["key_version"])
                old_user_key = unwrap_user_key(old_key_row["wrapped_key"])

                cur.execute(
                    "SELECT COALESCE(MAX(key_version), 0) AS v FROM user_keys WHERE username=%s",
                    (username,),
                )
                new_version = int(cur.fetchone()["v"]) + 1

                new_user_key = generate_user_key()
                wrapped_new = wrap_user_key(new_user_key)
                cur.execute(
                    """
                    INSERT INTO user_keys (username, key_version, wrapped_key, is_active)
                    VALUES (%s, %s, %s, FALSE)
                    """,
                    (username, new_version, wrapped_new),
                )

                cur.execute(
                    "SELECT id, ciphertext FROM secure_data WHERE username=%s AND key_version=%s",
                    (username, old_version),
                )
                items = cur.fetchall()

                updated = 0
                for item in items:
                    plain = decrypt_with_user_key(old_user_key, item["ciphertext"])
                    new_cipher = encrypt_with_user_key(new_user_key, plain)
                    cur.execute(
                        "UPDATE secure_data SET ciphertext=%s, key_version=%s "
                        "WHERE id=%s AND username=%s",
                        (new_cipher, new_version, item["id"], username),
                    )
                    updated += 1

                cur.execute(
                    "UPDATE user_keys SET is_active=FALSE WHERE username=%s AND key_version=%s",
                    (username, old_version),
                )
                cur.execute(
                    "UPDATE user_keys SET is_active=TRUE WHERE username=%s AND key_version=%s",
                    (username, new_version),
                )

        request.session["msg"] = f"✅ Rotation successful! New key v{new_version}. Re-encrypted {updated} records."
        return redirect("view_keys")

    except Exception:
        logger.exception("Key rotation failed.")
        request.session["msg"] = "❌ Rotation failed. Please try again or contact the site administrator."
        return redirect("view_keys")

    finally:
        con.close()

#!/usr/bin/env python3
"""
auth_server.py - the sign-in / license server for KinetixisMM (run by you, NOT shipped to customers).

  python auth_server.py init                         create the database and signing key; prints the PUBLIC key
  python auth_server.py add-user buyer@example.com   create an account (prints a temporary password)
  python auth_server.py set-password EMAIL           set a new random password
  python auth_server.py disable EMAIL / enable EMAIL
  python auth_server.py list                         accounts and their computers
  python auth_server.py remove-device EMAIL          let the user sign in on a new computer
  python auth_server.py delete-user EMAIL            erase an account and its sign-in records (privacy request)
  python auth_server.py purge-logs [--days 365]      delete old sign-in records (run it monthly)
  python auth_server.py mark-paid EMAIL              mark a website account as paid by hand (if a payment could not be matched)
  python auth_server.py serve                        start the server (put HTTPS in front of it, see SERVER_SETUP.txt)

Passwords are stored only as scrypt hashes. Tokens are Ed25519-signed and expire; the private key never leaves this server.
Settings (environment): DATABASE_URL, KMM_DB, KMM_KEY, KMM_PRIVATE_KEY_PEM, KMM_ADMIN_KEY, KMM_TOKEN_DAYS (14),
KMM_MAX_DEVICES (3), KMM_PORT (8080), KMM_HOST (127.0.0.1),
KMM_TRUST_PROXY (set to 1 when behind nginx/Caddy so the real client IP is used).
"""
import argparse
import base64
import collections
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import urllib.parse
import urllib.request
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")
DEVICE_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
b64d = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hash_password(pw, n=2 ** 15, r=8, p=1):
    salt = os.urandom(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=128 * 1024 * 1024)
    return f"scrypt${n}${r}${p}${b64u(salt)}${b64u(dk)}"


def verify_password(pw, stored):
    try:
        _, n, r, p, salt, dk = stored.split("$")
        got = hashlib.scrypt(pw.encode(), salt=b64d(salt), n=int(n), r=int(r), p=int(p), dklen=32,
                             maxmem=128 * 1024 * 1024)
        return hmac.compare_digest(got, b64d(dk))
    except (ValueError, TypeError):
        return False


class RateLimiter:
    """Sliding-window failure counter per key (email or IP)."""

    def __init__(self, window=900):
        self.window, self.hits, self.lock = window, collections.defaultdict(collections.deque), threading.Lock()

    def retry_after(self, key, limit):
        with self.lock:
            q = self.hits[key]
            now = time.time()
            while q and q[0] < now - self.window:
                q.popleft()
            return int(q[0] + self.window - now) + 1 if len(q) >= limit else 0

    def fail(self, key):
        with self.lock:
            self.hits[key].append(time.time())

    def reset(self, key):
        with self.lock:
            self.hits.pop(key, None)


class DBConn:
    """Thin wrapper over sqlite3.Connection and psycopg.Connection."""

    def __init__(self, raw, is_pg):
        self._raw = raw
        self.is_pg = is_pg

    def _sql(self, query):
        return query.replace("?", "%s") if self.is_pg else query

    def execute(self, query, params=()):
        return self._raw.execute(self._sql(query), params)

    def commit(self):
        self._raw.commit()

    def rollback(self):
        self._raw.rollback()

    def close(self):
        self._raw.close()


class Service:
    def __init__(self, db="kmm_auth.db", key_path="kmm_private.pem", admin_key=None, token_days=14,
                 max_devices=3, database_url=None):
        self.db, self.key_path, self.admin_key = db, key_path, admin_key
        self.database_url = (database_url or "").strip() or None
        self.is_pg = bool(self.database_url)
        self.token_days, self.max_devices = token_days, max_devices
        self.limiter = RateLimiter()
        self._dummy = hash_password("not-a-real-password")  # keeps timing equal for unknown emails
        self.private = None
        pem_env = os.environ.get("KMM_PRIVATE_KEY_PEM")
        if pem_env and pem_env.strip():
            pem_bytes = pem_env.strip().replace("\\n", "\n").encode()
            self.private = serialization.load_pem_private_key(pem_bytes, password=None)
        elif os.path.exists(key_path):
            with open(key_path, "rb") as f:
                self.private = serialization.load_pem_private_key(f.read(), password=None)

    # -- storage ---------------------------------------------------------------------------
    @contextmanager
    def conn(self):
        if self.is_pg:
            if psycopg is None:
                raise RuntimeError("psycopg is required when DATABASE_URL is set. Install with: pip install 'psycopg[binary]'")
            raw = psycopg.connect(self.database_url, row_factory=dict_row, autocommit=False)
        else:
            raw = sqlite3.connect(self.db, timeout=10)
            raw.row_factory = sqlite3.Row
        wrapper = DBConn(raw, self.is_pg)
        try:
            yield wrapper
            wrapper.commit()
        except Exception:
            wrapper.rollback()
            raise
        finally:
            wrapper.close()

    def init(self):
        with self.conn() as c:
            if self.is_pg:
                c.execute("""
                    CREATE TABLE IF NOT EXISTS users(
                        id SERIAL PRIMARY KEY,
                        email TEXT UNIQUE NOT NULL,
                        pw TEXT NOT NULL,
                        active INTEGER NOT NULL DEFAULT 1,
                        created BIGINT NOT NULL,
                        last_login BIGINT
                    )
                """)
                c.execute("""
                    CREATE TABLE IF NOT EXISTS devices(
                        user_id INTEGER NOT NULL,
                        device_id TEXT NOT NULL,
                        name TEXT,
                        first_seen BIGINT,
                        last_seen BIGINT,
                        PRIMARY KEY(user_id, device_id)
                    )
                """)
                c.execute("CREATE TABLE IF NOT EXISTS events(ts BIGINT, email TEXT, ip TEXT, event TEXT)")
            else:
                c._raw.executescript("""
                CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, pw TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL, last_login INTEGER);
                CREATE TABLE IF NOT EXISTS devices(user_id INTEGER NOT NULL, device_id TEXT NOT NULL, name TEXT,
                    first_seen INTEGER, last_seen INTEGER, PRIMARY KEY(user_id, device_id));
                CREATE TABLE IF NOT EXISTS events(ts INTEGER, email TEXT, ip TEXT, event TEXT);""")
        if self.private is None:
            self.private = Ed25519PrivateKey.generate()
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(self.private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))

    def public_key_b64(self):
        raw = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return base64.b64encode(raw).decode()

    def log(self, email, ip, event):
        with self.conn() as c:
            c.execute("INSERT INTO events VALUES(?,?,?,?)", (int(time.time()), email, ip, event))

    # -- accounts ----------------------------------------------------------------------------
    def create_user(self, email, password=None):
        email = email.strip().lower()
        if not EMAIL_RE.match(email):
            raise ValueError("That does not look like an email address.")
        generated = password is None
        password = password or secrets.token_urlsafe(9)
        if len(password) < 8:
            raise ValueError("The password must have at least 8 characters.")
        with self.conn() as c:
            try:
                c.execute("INSERT INTO users(email,pw,created) VALUES(?,?,?)", (email, hash_password(password), int(time.time())))
            except Exception as exc:
                if self.is_pg and psycopg and isinstance(exc, psycopg.IntegrityError):
                    raise ValueError("An account with this email already exists.")
                if not self.is_pg and isinstance(exc, sqlite3.IntegrityError):
                    raise ValueError("An account with this email already exists.")
                raise
        return password if generated else None

    def set_password(self, email, password=None):
        password = password or secrets.token_urlsafe(9)
        with self.conn() as c:
            n = c.execute("UPDATE users SET pw=? WHERE email=?", (hash_password(password), email.strip().lower())).rowcount
        if not n:
            raise ValueError("No such account.")
        return password

    def delete_user(self, email):
        email = email.strip().lower()
        with self.conn() as c:
            row = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if not row:
                raise ValueError("No such account.")
            uid = row["id"] if self.is_pg else row["id"]
            c.execute("DELETE FROM devices WHERE user_id=?", (uid,))
            c.execute("DELETE FROM events WHERE email=?", (email,))
            c.execute("DELETE FROM users WHERE id=?", (uid,))

    def purge_events(self, days=365):
        with self.conn() as c:
            return c.execute("DELETE FROM events WHERE ts < ?", (int(time.time()) - int(days * 86400),)).rowcount

    # -- tokens ---------------------------------------------------------------------------------
    def issue(self, user_id, email, device):
        now = int(time.time())
        body = b64u(json.dumps({"v": 1, "jti": secrets.token_hex(6), "sub": email, "uid": user_id, "did": device, "iat": now,
                                "exp": now + int(self.token_days * 86400)}, separators=(",", ":")).encode())
        return {"token": body + "." + b64u(self.private.sign(body.encode())), "expires": now + int(self.token_days * 86400)}

    def read_token(self, token):
        try:
            body, sig = token.split(".")
            self.private.public_key().verify(b64d(sig), body.encode())
            payload = json.loads(b64d(body))
        except Exception:
            raise Err(401, "bad_token", "The sign-in is not valid. Please sign in again.")
        if payload["exp"] <= time.time():
            raise Err(401, "expired", "The sign-in has expired. Please sign in again.")
        return payload

    # -- API ------------------------------------------------------------------------------------------
    def login(self, d, ip):
        email, pw, dev = d.get("email"), d.get("password"), d.get("device_id")
        if not (isinstance(email, str) and isinstance(pw, str) and isinstance(dev, str)
                and len(email) <= 254 and 0 < len(pw) <= 256 and DEVICE_RE.match(dev)):
            raise Err(400, "bad_request", "Please enter your email and password.")
        email = email.strip().lower()
        wait = max(self.limiter.retry_after("e:" + email, 5), self.limiter.retry_after("i:" + ip, 30))
        if wait:
            raise Err(429, "rate_limited", f"Too many attempts. Please wait {max(1, wait // 60)} minute(s) and try again.", wait)
        with self.conn() as c:
            u = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            ok = verify_password(pw, u["pw"] if u else self._dummy) and u is not None
            if not ok:
                self.limiter.fail("e:" + email)
                self.limiter.fail("i:" + ip)
                self.log(email, ip, "login_failed")
                raise Err(401, "invalid_credentials", "Email or password is incorrect.")
            if not u["active"]:
                raise Err(403, "disabled", "This account is disabled. Please contact support.")
            known = c.execute("SELECT 1 FROM devices WHERE user_id=? AND device_id=?", (u["id"], dev)).fetchone()
            row_cnt = c.execute("SELECT COUNT(*) AS cnt FROM devices WHERE user_id=?", (u["id"],)).fetchone()
            count = row_cnt["cnt"] if self.is_pg else row_cnt[0]
            if not known and count >= self.max_devices:
                raise Err(403, "device_limit", f"This account is already used on {self.max_devices} computers. "
                          "Sign out on one of them, or contact support to free a spot.")
            now = int(time.time())
            dev_name = str(d.get("device_name", ""))[:60]
            c.execute("INSERT INTO devices VALUES(?,?,?,?,?) ON CONFLICT(user_id,device_id) DO UPDATE SET last_seen=?, name=?",
                      (u["id"], dev, dev_name, now, now, now, dev_name))
            c.execute("UPDATE users SET last_login=? WHERE id=?", (now, u["id"]))
        self.limiter.reset("e:" + email)
        self.log(email, ip, "login")
        return {**self.issue(u["id"], email, dev), "email": email}

    def _active(self, payload):
        with self.conn() as c:
            u = c.execute("SELECT active FROM users WHERE id=?", (payload["uid"],)).fetchone()
            dev = c.execute("SELECT 1 FROM devices WHERE user_id=? AND device_id=?", (payload["uid"], payload["did"])).fetchone()
        if not u or not u["active"]:
            raise Err(401, "disabled", "This account is disabled. Please contact support.")
        if not dev:
            raise Err(401, "revoked", "This computer was signed out. Please sign in again.")

    def refresh(self, d):
        payload = self.read_token(str(d.get("token", "")))
        if d.get("device_id") != payload["did"]:
            raise Err(401, "bad_token", "The sign-in belongs to another computer.")
        self._active(payload)
        with self.conn() as c:
            c.execute("UPDATE devices SET last_seen=? WHERE user_id=? AND device_id=?", (int(time.time()), payload["uid"], payload["did"]))
        return {**self.issue(payload["uid"], payload["sub"], payload["did"]), "email": payload["sub"]}

    def logout(self, d):
        payload = self.read_token(str(d.get("token", "")))
        with self.conn() as c:
            c.execute("DELETE FROM devices WHERE user_id=? AND device_id=?", (payload["uid"], payload["did"]))
        return {"ok": True}

    def admin_create(self, d, key):
        if not self.admin_key or not key or not hmac.compare_digest(key, self.admin_key):
            raise Err(401, "unauthorized", "Admin key required.")
        try:
            pw = self.create_user(str(d.get("email", "")), d.get("password"))
        except ValueError as e:
            raise Err(400, "bad_request", str(e))
        return {"ok": True, "temporary_password": pw}


class Err(Exception):
    def __init__(self, status, code, message, retry_after=None):
        super().__init__(message)
        self.status, self.code, self.message, self.retry_after = status, code, message, retry_after


# ======================= website accounts, Razorpay payments, downloads =======================
# Env: SITE_URL, API_BASE, RAZORPAY_WEBHOOK_SECRET, PRICE_PAISE (129900), BREVO_API_KEY, MAIL_FROM,
#      DOWNLOAD_URL  or  R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET, R2_OBJECT_KEY
def sigv4_presign(host, path, access_key, secret, region, service, expires=300, now=None):
    """AWS Signature V4 presigned GET URL (works for Cloudflare R2 with region 'auto', service 's3')."""
    t = now or time.gmtime()
    amz, day = time.strftime("%Y%m%dT%H%M%SZ", t), time.strftime("%Y%m%d", t)
    scope = f"{day}/{region}/{service}/aws4_request"
    params = {"X-Amz-Algorithm": "AWS4-HMAC-SHA256", "X-Amz-Credential": f"{access_key}/{scope}", "X-Amz-Date": amz,
              "X-Amz-Expires": str(expires), "X-Amz-SignedHeaders": "host"}
    qs = "&".join(f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}" for k, v in sorted(params.items()))
    canon = f"GET\n{urllib.parse.quote(path, safe='/')}\n{qs}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD"
    sts = f"AWS4-HMAC-SHA256\n{amz}\n{scope}\n{hashlib.sha256(canon.encode()).hexdigest()}"
    k = ("AWS4" + secret).encode()
    for part in (day, region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    return f"https://{host}{urllib.parse.quote(path, safe='/')}?{qs}&X-Amz-Signature={sig}"


class Billing:
    def __init__(self, svc):
        self.svc = svc
        e = os.environ.get
        self.site = e("SITE_URL", "https://kinetixis.com").rstrip("/")
        self.api_base = e("API_BASE", "https://auth.kinetixis.com").rstrip("/")
        self.wh = e("RAZORPAY_WEBHOOK_SECRET", "").encode()
        self.price = int(e("PRICE_PAISE", "129900"))
        self.mail_from = e("MAIL_FROM", "arjan@kinetixis.com")
        self._key = None

    def init(self):
        with self.svc.conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS web_acct(user_id INTEGER PRIMARY KEY, vtoken TEXT, "
                      "verified INTEGER NOT NULL DEFAULT 0, paid INTEGER NOT NULL DEFAULT 0)")
            c.execute("CREATE TABLE IF NOT EXISTS web_payments(payment_id TEXT PRIMARY KEY, email TEXT, amount BIGINT, ts BIGINT)")

    # -- signed web-session tokens (separate from the app's Ed25519 tokens) --
    def _k(self):
        if self._key is None:
            raw = self.svc.private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            self._key = hashlib.sha256(raw + b"|kmm-web-session").digest()
        return self._key

    def sign(self, payload, ttl):
        body = b64u(json.dumps({**payload, "exp": int(time.time()) + ttl}, separators=(",", ":")).encode())
        return body + "." + hmac.new(self._k(), body.encode(), hashlib.sha256).hexdigest()

    def unsign(self, tok):
        try:
            body, sig = tok.rsplit(".", 1)
            if not hmac.compare_digest(sig, hmac.new(self._k(), body.encode(), hashlib.sha256).hexdigest()):
                return None
            d = json.loads(b64d(body))
            return d if d["exp"] > time.time() else None
        except Exception:
            return None

    # -- email through Brevo's HTTPS API (Render's free plan blocks SMTP) --
    def mail(self, to, subject, text):
        key = os.environ.get("BREVO_API_KEY")
        if not key:
            print("BREVO_API_KEY missing; email not sent to", to, flush=True)
            return False
        body = json.dumps({"sender": {"name": "KinetixisMM", "email": self.mail_from}, "to": [{"email": to}],
                           "subject": subject, "textContent": text}).encode()
        req = urllib.request.Request("https://api.brevo.com/v3/smtp/email", data=body, headers={
            "api-key": key, "Content-Type": "application/json", "Accept": "application/json", "User-Agent": "KinetixisMM/1.0"})
        try:
            resp = urllib.request.urlopen(req, timeout=15).read()[:200]
            print("Brevo accepted email to", to, resp, flush=True)
            return True
        except Exception as ex:
            print("Brevo email failed:", ex, getattr(ex, "read", lambda: b"")()[:300], flush=True)
            return False

    def _send_verify(self, email, vtoken):
        self.mail(email, "Confirm your KinetixisMM email",
                  f"Welcome to KinetixisMM.\n\nConfirm your email to continue to payment:\n{self.api_base}/api/verify?token={vtoken}\n\n"
                  "If you did not create this account, you can ignore this email.\n\nKinetixis, arjan@kinetixis.com")

    # -- helpers --
    def _acct(self, c, u):
        a = c.execute("SELECT * FROM web_acct WHERE user_id=?", (u["id"],)).fetchone()
        if not a:  # account created by hand with add-user: treat as already confirmed
            c.execute("INSERT INTO web_acct(user_id,verified,paid) VALUES(?,1,?)", (u["id"], 1 if u["active"] else 0))
            a = c.execute("SELECT * FROM web_acct WHERE user_id=?", (u["id"],)).fetchone()
        return a

    def user_from(self, auth):
        d = self.unsign(auth[7:]) if auth.startswith("Bearer ") else None
        if not d:
            raise Err(401, "not_signed_in", "Please sign in.")
        with self.svc.conn() as c:
            u = c.execute("SELECT * FROM users WHERE id=?", (d["uid"],)).fetchone()
            if not u:
                raise Err(401, "not_signed_in", "Please sign in.")
            return u, self._acct(c, u)

    def _limit(self, key, limit):
        wait = self.svc.limiter.retry_after(key, limit)
        if wait:
            raise Err(429, "rate_limited", f"Too many attempts. Please wait {max(1, wait // 60)} minute(s).", wait)

    # -- API --
    def signup(self, d, ip):
        email, pw = d.get("email"), d.get("password")
        if not (isinstance(email, str) and isinstance(pw, str)) or not EMAIL_RE.match(email.strip().lower()) or not 8 <= len(pw) <= 256:
            raise Err(400, "bad_request", "Enter a valid email and a password of at least 8 characters.")
        email = email.strip().lower()
        self._limit("s:" + ip, 10)
        self.svc.limiter.fail("s:" + ip)
        vt = secrets.token_urlsafe(32)
        with self.svc.conn() as c:
            u = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if u:
                a = self._acct(c, u)
                if a["verified"]:
                    raise Err(409, "exists", "An account with this email already exists. Use Sign in instead.")
                # nobody has proven they own this email yet: let the real owner take it over
                c.execute("UPDATE users SET pw=? WHERE id=?", (hash_password(pw), u["id"]))
                c.execute("UPDATE web_acct SET vtoken=? WHERE user_id=?", (vt, u["id"]))
                uid = u["id"]
            else:
                c.execute("INSERT INTO users(email,pw,active,created) VALUES(?,?,0,?)", (email, hash_password(pw), int(time.time())))
                uid = c.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
                c.execute("INSERT INTO web_acct(user_id,vtoken,verified,paid) VALUES(?,?,0,0)", (uid, vt))
        print("signup received for", email, flush=True)
        self._send_verify(email, vt)
        self.svc.log(email, ip, "web_signup")
        return {"ok": True, "token": self.sign({"uid": uid}, 30 * 86400)}

    def login(self, d, ip):
        email, pw = d.get("email"), d.get("password")
        if not (isinstance(email, str) and isinstance(pw, str) and 0 < len(pw) <= 256):
            raise Err(400, "bad_request", "Enter your email and password.")
        email = email.strip().lower()
        self._limit("we:" + email, 8)
        self._limit("wi:" + ip, 40)
        with self.svc.conn() as c:
            u = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            ok = verify_password(pw, u["pw"] if u else self.svc._dummy) and u is not None
            if not ok:
                self.svc.limiter.fail("we:" + email)
                self.svc.limiter.fail("wi:" + ip)
                raise Err(401, "invalid_credentials", "Wrong email or password.")
            a = self._acct(c, u)
        self.svc.limiter.reset("we:" + email)
        return {"ok": True, "token": self.sign({"uid": u["id"]}, 30 * 86400), "unverified": not a["verified"]}

    def resend(self, d, ip):
        self._limit("r:" + ip, 10)
        self.svc.limiter.fail("r:" + ip)
        email = str(d.get("email", "")).strip().lower()
        with self.svc.conn() as c:
            u = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            a = self._acct(c, u) if u else None
        if a and not a["verified"] and a["vtoken"]:
            self._send_verify(email, a["vtoken"])
        return {"ok": True, "message": "If that account still needs confirming, we sent a new link."}

    def verify(self, token):
        with self.svc.conn() as c:
            a = c.execute("SELECT * FROM web_acct WHERE vtoken=?", (token,)).fetchone() if token else None
            if a:
                c.execute("UPDATE web_acct SET verified=1 WHERE user_id=?", (a["user_id"],))
                if a["paid"]:
                    c.execute("UPDATE users SET active=1 WHERE id=?", (a["user_id"],))
        return self.site + ("/#checkout" if a else "/#signin")

    def me(self, auth):
        u, a = self.user_from(auth)
        return {"ok": True, "email": u["email"], "verified": bool(a["verified"]), "paid": bool(a["paid"])}

    def mark_paid(self, email):
        email = email.strip().lower()
        with self.svc.conn() as c:
            u = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if not u:
                return False
            a = self._acct(c, u)
            c.execute("UPDATE web_acct SET paid=1 WHERE user_id=?", (u["id"],))
            if a["verified"]:
                c.execute("UPDATE users SET active=1 WHERE id=?", (u["id"],))
        return True

    def webhook(self, raw, sig):
        if not self.wh or not hmac.compare_digest(sig or "", hmac.new(self.wh, raw, hashlib.sha256).hexdigest()):
            raise Err(400, "bad_signature", "Bad signature.")
        ev = json.loads(raw.decode())
        if ev.get("event") not in ("payment.captured", "payment_link.paid", "order.paid"):
            return {"ok": True, "ignored": True}
        pay = (ev.get("payload", {}).get("payment") or {}).get("entity") or {}
        pid, email = pay.get("id"), str(pay.get("email") or "").strip().lower()
        if not pid or pay.get("status") != "captured" or pay.get("currency", "INR") != "INR" or int(pay.get("amount") or 0) < self.price:
            return {"ok": True, "ignored": True}
        with self.svc.conn() as c:
            if c.execute("SELECT 1 FROM web_payments WHERE payment_id=?", (pid,)).fetchone():
                return {"ok": True, "duplicate": True}
            c.execute("INSERT INTO web_payments VALUES(?,?,?,?)", (pid, email, int(pay.get("amount") or 0), int(time.time())))
        if self.mark_paid(email):
            self.mail(email, "Payment received: KinetixisMM",
                      f"Thank you! Your payment (ID {pid}) is confirmed.\n\nDownload KinetixisMM here:\n{self.site}/#download\n\n"
                      "Sign in on the website and inside the app with the email and password you created.\n\n"
                      "Questions? Reply to this email or write to arjan@kinetixis.com\n\nKinetixis")
        else:
            print(f"PAID but no account for {email} (payment {pid}). Fix: python auth_server.py mark-paid <account email>", flush=True)
        return {"ok": True}

    def download_link(self, auth):
        u, a = self.user_from(auth)
        if not a["paid"]:
            raise Err(402, "unpaid", "No payment found for this account yet.")
        if not a["verified"]:
            raise Err(403, "unverified", "Please confirm your email first.")
        return {"ok": True, "url": f"{self.api_base}/api/download?t={self.sign({'uid': u['id']}, 600)}"}

    def download_target(self, t):
        d = self.unsign(t or "")
        if not d:
            return self.site + "/#signin"
        with self.svc.conn() as c:
            u = c.execute("SELECT * FROM users WHERE id=?", (d["uid"],)).fetchone()
            a = self._acct(c, u) if u else None
        if not a or not a["paid"] or not a["verified"]:
            return self.site + "/#signin"
        e = os.environ.get
        if e("R2_ACCOUNT_ID") and e("R2_ACCESS_KEY_ID") and e("R2_SECRET_ACCESS_KEY") and e("R2_BUCKET") and e("R2_OBJECT_KEY"):
            return sigv4_presign(f"{e('R2_ACCOUNT_ID')}.r2.cloudflarestorage.com", f"/{e('R2_BUCKET')}/{e('R2_OBJECT_KEY')}",
                                 e("R2_ACCESS_KEY_ID"), e("R2_SECRET_ACCESS_KEY"), "auto", "s3", 300)
        return e("DOWNLOAD_URL") or self.site + "/#download"


def make_handler(svc, trust_proxy=False):
    bill = Billing(svc)

    class H(BaseHTTPRequestHandler):
        server_version = "kmm-auth"

        def log_message(self, *a):
            pass

        def _cors(self):
            if self.path.startswith("/api/"):
                self.send_header("Access-Control-Allow-Origin", bill.site)
                self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Vary", "Origin")

        def _send(self, status, obj):
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self._cors()
            self.end_headers()
            self.wfile.write(data)

        def _redirect(self, url):
            self.send_response(302)
            self.send_header("Location", url)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _ip(self):
            return (self.headers.get("X-Forwarded-For", "").split(",")[0].strip() if trust_proxy else "") or self.client_address[0]

        def _fail(self, e):
            if self.path.startswith("/api/"):
                self._send(e.status, {"ok": False, "error": e.message, "code": e.code, **({"retry_after": e.retry_after} if e.retry_after else {})})
            else:
                self._send(e.status, {"error": e.code, "message": e.message, **({"retry_after": e.retry_after} if e.retry_after else {})})

        def do_OPTIONS(self):
            self.send_response(204)
            self._cors()
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            try:
                u = urllib.parse.urlparse(self.path)
                qs = urllib.parse.parse_qs(u.query)
                auth = self.headers.get("Authorization", "")
                if u.path in ("/v1/health", "/api/health"):
                    self._send(200, {"ok": True})
                elif u.path == "/api/verify":
                    self._redirect(bill.verify(qs.get("token", [""])[0]))
                elif u.path == "/api/me":
                    self._send(200, bill.me(auth))
                elif u.path == "/api/download-link":
                    self._send(200, bill.download_link(auth))
                elif u.path == "/api/download":
                    self._redirect(bill.download_target(qs.get("t", [""])[0]))
                else:
                    self._send(404, {"error": "not_found", "message": "Not found."})
            except Err as e:
                self._fail(e)
            except Exception as ex:
                print("GET error:", repr(ex), flush=True)
                self._send(500, {"ok": False, "error": "Something went wrong on the server.", "message": "Something went wrong on the server."})

        def do_POST(self):
            try:
                path = urllib.parse.urlparse(self.path).path
                limit = 262144 if path == "/api/razorpay-webhook" else 8192
                n = int(self.headers.get("Content-Length", "0"))
                if not 0 < n <= limit:
                    raise Err(400, "bad_request", "Bad request.")
                raw = self.rfile.read(n)
                if path == "/api/razorpay-webhook":
                    self._send(200, bill.webhook(raw, self.headers.get("X-Razorpay-Signature")))
                    return
                d = json.loads(raw.decode())
                if not isinstance(d, dict):
                    raise Err(400, "bad_request", "Bad request.")
                ip = self._ip()
                routes = {"/v1/login": lambda: svc.login(d, ip), "/v1/refresh": lambda: svc.refresh(d),
                          "/v1/logout": lambda: svc.logout(d),
                          "/v1/admin/users": lambda: svc.admin_create(d, self.headers.get("X-Admin-Key")),
                          "/api/signup": lambda: bill.signup(d, ip), "/api/login": lambda: bill.login(d, ip),
                          "/api/resend": lambda: bill.resend(d, ip)}
                if path not in routes:
                    raise Err(404, "not_found", "Not found.")
                self._send(200, routes[path]())
            except Err as e:
                self._fail(e)
            except (ValueError, UnicodeDecodeError):
                self._send(400, {"ok": False, "error": "Bad request.", "message": "Bad request."})
            except Exception as ex:  # never leak details to the client
                print("POST error:", repr(ex), flush=True)
                self._send(500, {"ok": False, "error": "Something went wrong on the server.", "message": "Something went wrong on the server."})
    return H


def service_from_env():
    return Service(
        os.environ.get("KMM_DB", "kmm_auth.db"),
        os.environ.get("KMM_KEY", "kmm_private.pem"),
        os.environ.get("KMM_ADMIN_KEY"),
        float(os.environ.get("KMM_TOKEN_DAYS", "14")),
        int(os.environ.get("KMM_MAX_DEVICES", "3")),
        os.environ.get("DATABASE_URL"),
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["init", "serve", "add-user", "set-password", "disable", "enable", "list", "remove-device", "delete-user", "purge-logs", "mark-paid"])
    ap.add_argument("email", nargs="?")
    ap.add_argument("--password")
    ap.add_argument("--days", type=int, default=365, help="purge-logs: keep this many days of sign-in records")
    a = ap.parse_args()
    svc = service_from_env()
    svc.init()
    Billing(svc).init()
    if a.cmd == "init":
        print("Database and signing key are ready.\nPut this PUBLIC key into license_client.py (PUBLIC_KEY):\n\n" + svc.public_key_b64())
    elif a.cmd == "add-user":
        pw = svc.create_user(a.email, a.password)
        print(f"Created {a.email}" + (f"\nTemporary password: {pw}" if pw else ""))
    elif a.cmd == "set-password":
        print(f"New password for {a.email}: {svc.set_password(a.email, a.password)}")
    elif a.cmd in ("disable", "enable"):
        with svc.conn() as c:
            c.execute("UPDATE users SET active=? WHERE email=?", (1 if a.cmd == "enable" else 0, a.email.strip().lower()))
        print("Done.")
    elif a.cmd == "remove-device":
        with svc.conn() as c:
            c.execute("DELETE FROM devices WHERE user_id=(SELECT id FROM users WHERE email=?)", (a.email.strip().lower(),))
        print("All computers were signed out for this account.")
    elif a.cmd == "delete-user":
        svc.delete_user(a.email)
        print(f"Deleted the account and sign-in records of {a.email}.")
    elif a.cmd == "mark-paid":
        print("Marked as paid." if Billing(svc).mark_paid(a.email) else "No such account (they must sign up on the website first).")
    elif a.cmd == "purge-logs":
        print(f"Deleted {svc.purge_events(a.days)} sign-in records older than {a.days} days.")
    elif a.cmd == "list":
        with svc.conn() as c:
            for u in c.execute("SELECT * FROM users ORDER BY email"):
                devs = c.execute("SELECT name FROM devices WHERE user_id=?", (u["id"],)).fetchall()
                print(f"{u['email']:40s} {'active' if u['active'] else 'DISABLED':9s} computers: {', '.join(d['name'] or '?' for d in devs) or '-'}")
    else:
        host, port = os.environ.get("KMM_HOST", "127.0.0.1"), int(os.environ.get("KMM_PORT", "8080"))
        print(f"KinetixisMM sign-in server on http://{host}:{port}  (use HTTPS in front of it)")
        ThreadingHTTPServer((host, port), make_handler(svc, os.environ.get("KMM_TRUST_PROXY") == "1")).serve_forever()


if __name__ == "__main__":
    sys.exit(main())
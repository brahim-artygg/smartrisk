from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PBKDF2_ITERATIONS = 600_000
PASSWORD_MIN_LENGTH = 10
PASSWORD_MAX_LENGTH = 128
SESSION_TTL_DAYS = 30
VERIFY_TTL_HOURS = 24
RESET_TTL_HOURS = 1


class AuthError(ValueError):
    def __init__(self, message: str, code: str = "AUTH_ERROR", status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


class EmailDeliveryError(RuntimeError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256$%d$%s$%s" % (
        PBKDF2_ITERATIONS,
        base64.urlsafe_b64encode(salt).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations_text, salt_text, digest_text = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_text)
        salt = base64.urlsafe_b64decode(salt_text + "===")
        expected = base64.urlsafe_b64decode(digest_text + "===")
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except (TypeError, ValueError):
        return False


def validate_email(email: str) -> str:
    normalized = email.strip().lower()
    if len(normalized) > 320 or not EMAIL_RE.fullmatch(normalized):
        raise AuthError("Enter a valid email address.", "INVALID_EMAIL")
    return normalized


def validate_password(password: str) -> None:
    if not isinstance(password, str) or len(password) < PASSWORD_MIN_LENGTH:
        raise AuthError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters.", "WEAK_PASSWORD")
    if len(password) > PASSWORD_MAX_LENGTH:
        raise AuthError("Password is too long.", "WEAK_PASSWORD")


@dataclass(frozen=True)
class User:
    id: str
    email: str
    email_verified: bool
    status: str
    created_at: str
    last_login_at: str | None
    role: str = "user"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "email": self.email,
            "email_verified": self.email_verified,
            "status": self.status,
            "created_at": self.created_at,
            "last_login_at": self.last_login_at,
            "role": self.role,
        }


class AuthStore:
    def __init__(self, path: str | os.PathLike[str] = "artifacts/jobs.sqlite3"):
        self.path = str(path)
        from pathlib import Path
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    email_verified INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login_at TEXT,
                    role TEXT NOT NULL DEFAULT 'user'
                );
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

                CREATE TABLE IF NOT EXISTS email_verification_tokens (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    expires_at TEXT NOT NULL,
                    used_at TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_hash ON email_verification_tokens(token_hash);

                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    expires_at TEXT NOT NULL,
                    used_at TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_hash ON password_reset_tokens(token_hash);

                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    revoked_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
                """
            )

            columns = {row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()}
            if "role" not in columns:
                db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30)
        db.execute("PRAGMA busy_timeout = 30000")
        db.execute("PRAGMA foreign_keys = ON")
        return db

    def create_user(self, email: str, password_hash: str) -> User:
        user_id = secrets.token_hex(16)
        now = _iso(_now())
        with self._lock, self._connect() as db:
            try:
                db.execute(
                    "INSERT INTO users(id,email,password_hash,email_verified,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                    (user_id, email, password_hash, 0, "active", now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise AuthError("An account with this email already exists.", "EMAIL_EXISTS", 409) from exc
        return self.get_user(user_id)  # type: ignore[return-value]

    def get_user(self, user_id: str) -> User | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT id,email,email_verified,status,created_at,last_login_at,role FROM users WHERE id=?",
                (user_id,),
            ).fetchone()
        return self._user_from_row(row) if row else None

    def get_user_by_email(self, email: str) -> tuple[User, str] | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT id,email,password_hash,email_verified,status,created_at,last_login_at,role FROM users WHERE email=?",
                (email,),
            ).fetchone()
        if not row:
            return None
        user = User(row[0], row[1], bool(row[3]), row[4], row[5], row[6], row[7] or "user")
        return user, row[2]

    @staticmethod
    def _user_from_row(row: tuple[Any, ...]) -> User:
        return User(row[0], row[1], bool(row[2]), row[3], row[4], row[5], row[6] or "user")

    def mark_verified(self, user_id: str) -> None:
        with self._lock, self._connect() as db:
            db.execute("UPDATE users SET email_verified=1,updated_at=? WHERE id=?", (_iso(_now()), user_id))
            db.execute("UPDATE email_verification_tokens SET used_at=? WHERE user_id=? AND used_at IS NULL", (_iso(_now()), user_id))

    def touch_login(self, user_id: str) -> None:
        with self._lock, self._connect() as db:
            db.execute("UPDATE users SET last_login_at=?,updated_at=? WHERE id=?", (_iso(_now()), _iso(_now()), user_id))

    def set_user_role(self, user_id: str, role: str) -> User:
        if role not in {"user", "admin"}:
            raise AuthError("Invalid role.", "INVALID_ROLE", 422)
        with self._lock, self._connect() as db:
            cur = db.execute("UPDATE users SET role=?,updated_at=? WHERE id=?", (role, _iso(_now()), user_id))
            if cur.rowcount != 1:
                raise AuthError("User not found.", "USER_NOT_FOUND", 404)
        return self.get_user(user_id)  # type: ignore[return-value]

    def set_user_status(self, user_id: str, status: str) -> User:
        if status not in {"active", "suspended", "deleted"}:
            raise AuthError("Invalid account status.", "INVALID_USER_STATUS", 422)
        with self._lock, self._connect() as db:
            cur = db.execute("UPDATE users SET status=?,updated_at=? WHERE id=?", (status, _iso(_now()), user_id))
            if cur.rowcount != 1:
                raise AuthError("User not found.", "USER_NOT_FOUND", 404)
            if status != "active":
                db.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", (_iso(_now()), user_id))
        return self.get_user(user_id)  # type: ignore[return-value]

    def bootstrap_admin_from_env(self) -> User | None:
        email = os.getenv("SMARTRISK_ADMIN_EMAIL", "").strip().lower()
        password = os.getenv("SMARTRISK_ADMIN_PASSWORD", "")
        if not email or not password:
            return None
        if not EMAIL_RE.fullmatch(email):
            raise AuthError("SMARTRISK_ADMIN_EMAIL is invalid.", "INVALID_ADMIN_CONFIG", 500)
        validate_password(password)
        with self._lock, self._connect() as db:
            row = db.execute("SELECT id,password_hash FROM users WHERE email=?", (email,)).fetchone()
            if row:
                if not verify_password(password, row[1]):
                    raise AuthError("Existing admin email does not match the bootstrap password.", "ADMIN_BOOTSTRAP_MISMATCH", 500)
                db.execute("UPDATE users SET role='admin',email_verified=1,status='active',updated_at=? WHERE id=?", (_iso(_now()), row[0]))
                return self.get_user(row[0])
            user_id = secrets.token_hex(16)
            now = _iso(_now())
            db.execute(
                "INSERT INTO users(id,email,password_hash,email_verified,status,created_at,updated_at,role) VALUES(?,?,?,?,?,?,?,?)",
                (user_id, email, hash_password(password), 1, "active", now, now, "admin"),
            )
        return self.get_user(user_id)

    def create_one_time_token(self, table: str, user_id: str, ttl: timedelta) -> str:
        if table not in {"email_verification_tokens", "password_reset_tokens"}:
            raise ValueError("unsupported token table")
        raw = secrets.token_urlsafe(48)
        token_hash = _hash_token(raw)
        now = _now()
        expires = now + ttl
        token_id = secrets.token_hex(16)
        with self._lock, self._connect() as db:
            db.execute(
                f"UPDATE {table} SET used_at=? WHERE user_id=? AND used_at IS NULL",
                (_iso(now), user_id),
            )
            db.execute(
                f"INSERT INTO {table}(id,user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)",
                (token_id, user_id, token_hash, _iso(expires), _iso(now)),
            )
        return raw

    def consume_one_time_token(self, table: str, raw_token: str) -> tuple[str, str]:
        if table not in {"email_verification_tokens", "password_reset_tokens"}:
            raise ValueError("unsupported token table")
        token_hash = _hash_token(raw_token)
        now = _now()
        with self._lock, self._connect() as db:
            row = db.execute(
                f"SELECT id,user_id,expires_at,used_at FROM {table} WHERE token_hash=?",
                (token_hash,),
            ).fetchone()
            if not row:
                raise AuthError("This link is invalid or expired.", "INVALID_TOKEN", 400)
            if row[3] is not None:
                raise AuthError("This link is invalid or expired.", "INVALID_TOKEN", 400)
            try:
                expired = datetime.fromisoformat(row[2]) <= now
            except ValueError:
                expired = True
            if expired:
                db.execute(f"UPDATE {table} SET used_at=? WHERE id=?", (_iso(now), row[0]))
                raise AuthError("This link is invalid or expired.", "INVALID_TOKEN", 400)
            cur = db.execute(f"UPDATE {table} SET used_at=? WHERE id=? AND used_at IS NULL", (_iso(now), row[0]))
            if cur.rowcount != 1:
                raise AuthError("This link is invalid or expired.", "INVALID_TOKEN", 400)
            return row[1], row[0]

    def update_password(self, user_id: str, password_hash: str) -> None:
        with self._lock, self._connect() as db:
            db.execute("UPDATE users SET password_hash=?,updated_at=? WHERE id=?", (password_hash, _iso(_now()), user_id))

    def create_session(self, user_id: str, ttl: timedelta = timedelta(days=SESSION_TTL_DAYS)) -> tuple[str, str]:
        raw = secrets.token_urlsafe(48)
        now = _now()
        token_hash = _hash_token(raw)
        session_id = secrets.token_hex(16)
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT INTO sessions(id,user_id,token_hash,expires_at,created_at,last_seen_at) VALUES(?,?,?,?,?,?)",
                (session_id, user_id, token_hash, _iso(now + ttl), _iso(now), _iso(now)),
            )
        return raw, _iso(now + ttl)

    def get_user_by_session(self, raw_token: str) -> User | None:
        token_hash = _hash_token(raw_token)
        now = _now()
        with self._lock, self._connect() as db:
            row = db.execute(
                "SELECT s.id,s.user_id,s.expires_at,s.revoked_at,u.id,u.email,u.email_verified,u.status,u.created_at,u.last_login_at,u.role "
                "FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?",
                (token_hash,),
            ).fetchone()
            if not row:
                return None
            if row[3] is not None:
                return None
            try:
                expired = datetime.fromisoformat(row[2]) <= now
            except ValueError:
                expired = True
            if expired:
                db.execute("UPDATE sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (_iso(now), row[0]))
                return None
            db.execute("UPDATE sessions SET last_seen_at=? WHERE id=?", (_iso(now), row[0]))
            return User(row[4], row[5], bool(row[6]), row[7], row[8], row[9], row[10] or "user")

    def revoke_session(self, raw_token: str) -> None:
        with self._lock, self._connect() as db:
            db.execute("UPDATE sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL", (_iso(_now()), _hash_token(raw_token)))

    def revoke_all_sessions(self, user_id: str) -> None:
        with self._lock, self._connect() as db:
            db.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", (_iso(_now()), user_id))


class ResendMailer:
    def __init__(self, api_key: str | None = None, from_email: str | None = None, base_url: str | None = None, timeout: float = 10.0):
        self.api_key = api_key or os.getenv("RESEND_API_KEY", "")
        self.from_email = from_email or os.getenv("RESEND_FROM_EMAIL", "")
        self.base_url = (base_url or os.getenv("APP_BASE_URL", "http://localhost:8787")).rstrip("/")
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.api_key and self.from_email)

    def _send(self, *, to: str, subject: str, html: str) -> None:
        if not self.configured:
            raise EmailDeliveryError("Email delivery is not configured. Set RESEND_API_KEY and RESEND_FROM_EMAIL.")
        payload = json.dumps({"from": self.from_email, "to": [to], "subject": subject, "html": html}).encode("utf-8")
        request = urllib.request.Request(
            "https://api.resend.com/emails",
            data=payload,
            method="POST",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if response.status < 200 or response.status >= 300:
                    raise EmailDeliveryError(f"Resend returned HTTP {response.status}.")
        except urllib.error.HTTPError as exc:
            raise EmailDeliveryError(f"Resend returned HTTP {exc.code}.") from exc
        except urllib.error.URLError as exc:
            raise EmailDeliveryError("Could not reach Resend.") from exc

    def send_verification(self, email: str, token: str) -> None:
        url = f"{self.base_url}/v1/auth/verify?token={token}"
        self._send(
            to=email,
            subject="Verify your SmartRisk account",
            html=(
                "<div style='font-family:Arial,sans-serif;line-height:1.6'>"
                "<h2>Welcome to SmartRisk</h2>"
                "<p>Verify your email address to activate your account.</p>"
                f"<p><a href='{url}' style='display:inline-block;padding:12px 18px;background:#fff;color:#071526;text-decoration:none;border-radius:8px;font-weight:700'>Verify email</a></p>"
                "<p>This link expires in 24 hours.</p></div>"
            ),
        )

    def send_password_reset(self, email: str, token: str) -> None:
        url = f"{self.base_url}/auth?mode=reset&token={token}"
        self._send(
            to=email,
            subject="Reset your SmartRisk password",
            html=(
                "<div style='font-family:Arial,sans-serif;line-height:1.6'>"
                "<h2>Reset your SmartRisk password</h2>"
                "<p>Use the button below to set a new password.</p>"
                f"<p><a href='{url}' style='display:inline-block;padding:12px 18px;background:#fff;color:#071526;text-decoration:none;border-radius:8px;font-weight:700'>Reset password</a></p>"
                "<p>This link expires in 1 hour.</p></div>"
            ),
        )


class AuthService:
    def __init__(self, store: AuthStore | None = None, mailer: ResendMailer | None = None, clock: Callable[[], datetime] | None = None):
        self.store = store or AuthStore(os.getenv("SMARTRISK_AUTH_DB", "artifacts/jobs.sqlite3"))
        self.mailer = mailer or ResendMailer()
        self._clock = clock or _now

    def register(self, email: str, password: str) -> dict[str, Any]:
        normalized = validate_email(email)
        validate_password(password)
        user = self.store.create_user(normalized, hash_password(password))
        token = self.store.create_one_time_token("email_verification_tokens", user.id, timedelta(hours=VERIFY_TTL_HOURS))
        try:
            self.mailer.send_verification(user.email, token)
        except Exception:
            # Remove the just-created account so a failed delivery never leaves a user stranded.
            with self.store._lock, self.store._connect() as db:
                db.execute("DELETE FROM email_verification_tokens WHERE user_id=?", (user.id,))
                db.execute("DELETE FROM users WHERE id=?", (user.id,))
            raise
        return {"user": user.to_dict(), "verification_required": True}

    def login(self, email: str, password: str) -> tuple[User, str, str]:
        normalized = validate_email(email)
        record = self.store.get_user_by_email(normalized)
        if record is None:
            raise AuthError("Invalid email or password.", "INVALID_CREDENTIALS", 401)
        user, password_hash = record
        if not verify_password(password, password_hash):
            raise AuthError("Invalid email or password.", "INVALID_CREDENTIALS", 401)
        if user.status != "active":
            raise AuthError("This account is not active.", "ACCOUNT_INACTIVE", 403)
        if not user.email_verified:
            raise AuthError("Please verify your email before signing in.", "EMAIL_NOT_VERIFIED", 403)
        self.store.touch_login(user.id)
        user = self.store.get_user(user.id)  # type: ignore[assignment]
        token, expires_at = self.store.create_session(user.id)
        return user, token, expires_at  # type: ignore[return-value]

    def verify_email(self, raw_token: str) -> User:
        user_id, _ = self.store.consume_one_time_token("email_verification_tokens", raw_token)
        self.store.mark_verified(user_id)
        user = self.store.get_user(user_id)
        if user is None:
            raise AuthError("Account not found.", "ACCOUNT_NOT_FOUND", 404)
        return user

    def resend_verification(self, email: str) -> None:
        normalized = validate_email(email)
        record = self.store.get_user_by_email(normalized)
        if not record:
            return
        user, _ = record
        if user.email_verified or user.status != "active":
            return
        token = self.store.create_one_time_token("email_verification_tokens", user.id, timedelta(hours=VERIFY_TTL_HOURS))
        self.mailer.send_verification(user.email, token)

    def request_password_reset(self, email: str) -> None:
        normalized = validate_email(email)
        record = self.store.get_user_by_email(normalized)
        if not record:
            return
        user, _ = record
        if user.status != "active":
            return
        token = self.store.create_one_time_token("password_reset_tokens", user.id, timedelta(hours=RESET_TTL_HOURS))
        try:
            self.mailer.send_password_reset(user.email, token)
        except EmailDeliveryError:
            # Keep response semantics generic, but surface the delivery failure to the server caller.
            raise

    def reset_password(self, raw_token: str, new_password: str) -> None:
        validate_password(new_password)
        user_id, _ = self.store.consume_one_time_token("password_reset_tokens", raw_token)
        self.store.update_password(user_id, hash_password(new_password))
        self.store.revoke_all_sessions(user_id)

    def logout(self, raw_session: str | None) -> None:
        if raw_session:
            self.store.revoke_session(raw_session)

    def session_user(self, raw_session: str | None) -> User | None:
        if not raw_session:
            return None
        return self.store.get_user_by_session(raw_session)


def parse_cookie(header: str | None, name: str) -> str | None:
    if not header:
        return None
    for part in header.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep and key == name:
            return value
    return None


def session_cookie(token: str, expires_at: str, secure: bool = True) -> str:
    from email.utils import format_datetime
    expires = datetime.fromisoformat(expires_at).astimezone(timezone.utc)
    secure_flag = "; Secure" if secure else ""
    return f"smartrisk_session={token}; Path=/; HttpOnly{secure_flag}; SameSite=Lax; Expires={format_datetime(expires, usegmt=True)}"


def clear_session_cookie(secure: bool = True) -> str:
    secure_flag = "; Secure" if secure else ""
    return f"smartrisk_session=; Path=/; HttpOnly{secure_flag}; SameSite=Lax; Max-Age=0"

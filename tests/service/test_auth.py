from __future__ import annotations

import http.client
import json
import threading
from urllib.parse import urlsplit

import pytest

from smartrisk.service.auth import AuthError, AuthService, AuthStore, hash_password, verify_password
from smartrisk.service.http import serve
from smartrisk.service.service import ScanService
from smartrisk.service.store import JobStore


class FakeMailer:
    def __init__(self):
        self.verification_tokens = []
        self.reset_tokens = []

    def send_verification(self, email, token):
        self.verification_tokens.append((email, token))

    def send_password_reset(self, email, token):
        self.reset_tokens.append((email, token))


class FakeReport:
    status = "unknown"

    def to_dict(self):
        return {"status": self.status, "risk": {"band": "unknown"}}


class FakeEngine:
    def analyze(self, request, run_id=None):
        return FakeReport()


def test_password_hash_is_not_reversible_and_verifies():
    encoded = hash_password("correct horse battery staple")
    assert encoded != "correct horse battery staple"
    assert verify_password("correct horse battery staple", encoded)
    assert not verify_password("wrong password", encoded)


def test_register_verify_login_and_session(tmp_path):
    mailer = FakeMailer()
    auth = AuthService(AuthStore(tmp_path / "auth.sqlite3"), mailer)

    result = auth.register("User@example.com", "correct horse battery staple")
    assert result["verification_required"] is True
    assert result["user"]["email"] == "user@example.com"
    assert len(mailer.verification_tokens) == 1

    with pytest.raises(AuthError) as exc:
        auth.login("user@example.com", "correct horse battery staple")
    assert exc.value.code == "EMAIL_NOT_VERIFIED"

    user = auth.verify_email(mailer.verification_tokens[0][1])
    assert user.email_verified is True

    logged_in, session, _ = auth.login("user@example.com", "correct horse battery staple")
    assert logged_in.email == user.email
    assert auth.session_user(session).email == user.email


def test_password_reset_revokes_existing_sessions(tmp_path):
    mailer = FakeMailer()
    auth = AuthService(AuthStore(tmp_path / "auth.sqlite3"), mailer)
    auth.register("user@example.com", "old password 123")
    auth.verify_email(mailer.verification_tokens[-1][1])
    _, session, _ = auth.login("user@example.com", "old password 123")

    auth.request_password_reset("user@example.com")
    assert mailer.reset_tokens
    auth.reset_password(mailer.reset_tokens[-1][1], "new password 123")

    assert auth.session_user(session) is None
    _, _, _ = auth.login("user@example.com", "new password 123")


class RunningServer:
    def __init__(self, db_path):
        self.scan_service = ScanService(JobStore(db_path), FakeEngine(), max_workers=1)
        self.mailer = FakeMailer()
        self.auth = AuthService(AuthStore(db_path), self.mailer)
        self.server = serve("127.0.0.1", 0, service=self.scan_service, auth_service=self.auth)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def host(self):
        return self.server.server_address

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.server.shutdown()
        self.server.server_close()
        self.scan_service.executor.shutdown(wait=True)


def request(server, method, path, body=None, headers=None):
    host, port = server.host
    conn = http.client.HTTPConnection(host, port, timeout=5)
    payload = None
    actual_headers = dict(headers or {})
    if body is not None:
        payload = json.dumps(body)
        actual_headers["Content-Type"] = "application/json"
    conn.request(method, path, body=payload, headers=actual_headers)
    response = conn.getresponse()
    data = json.loads(response.read() or b"{}")
    return response, data


def test_http_auth_and_anonymous_scan_stay_independent(tmp_path):
    with RunningServer(tmp_path / "jobs.sqlite3") as server:
        response, data = request(server, "POST", "/v1/scans", {"chain_id": "1", "token_address": "0x" + "1" * 40})
        assert response.status == 202
        assert data["job_id"]

        response, data = request(server, "POST", "/v1/auth/register", {"email": "user@example.com", "password": "correct horse battery staple"})
        assert response.status == 201
        assert data["verification_required"] is True

        token = server.mailer.verification_tokens[-1][1]
        response = request(server, "GET", f"/v1/auth/verify?token={token}")[0]
        assert response.status == 302

        response, data = request(server, "POST", "/v1/auth/login", {"email": "user@example.com", "password": "correct horse battery staple"})
        assert response.status == 200
        cookie = response.getheader("Set-Cookie")
        assert cookie and "smartrisk_session=" in cookie

        response, data = request(server, "GET", "/v1/auth/me", headers={"Cookie": cookie.split(";", 1)[0]})
        assert response.status == 200
        assert data["authenticated"] is True

        # Authenticated users and anonymous visitors both use the exact same public scan endpoint.
        response, _ = request(server, "POST", "/v1/scans", {"chain_id": "1", "token_address": "0x" + "2" * 40})
        assert response.status == 202

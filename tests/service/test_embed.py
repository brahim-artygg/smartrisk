from __future__ import annotations

import http.client
import json
import threading
from pathlib import Path

from smartrisk.service.auth import AuthService, AuthStore
from smartrisk.service.http import serve
from smartrisk.service.service import ScanService
from smartrisk.service.store import JobStore


class FakeReport:
    status = "complete"

    def to_dict(self):
        return {
            "run_id": "run-embed",
            "status": "complete",
            "verdict": {
                "code": "HIGH_RISK",
                "label": "HIGH RISK",
                "primary_detection": {
                    "title": "Sell restriction",
                    "explanation": "A sellability signal was observed.",
                },
            },
            "risk": {"score": 87, "band": "high", "confidence": 0.94, "coverage": 0.92},
            "risk_dimensions": {
                "trading_security": {"signals": 2, "severity": "high"},
                "liquidity_market": {"signals": 0, "severity": "low"},
            },
            "findings": [
                {
                    "title": "Sellability restriction",
                    "severity": "high",
                    "status": "observed",
                    "description": "Sell behavior requires additional review.",
                },
                {
                    "title": "Owner permission",
                    "severity": "medium",
                    "status": "observed",
                    "description": "Administrative permissions are present.",
                },
            ],
            "unknowns": ["holder history"],
            "engines": [{"name": "heuristics", "status": "complete"}],
            "versions": {"release": "0.9.0"},
        }


class FakeEngine:
    def analyze(self, request, run_id=None):
        return FakeReport()


class FakeMailer:
    def send_verification(self, email, token):
        pass

    def send_password_reset(self, email, token):
        pass


def request(server, method, path, body=None, headers=None):
    host, port = server.server_address
    conn = http.client.HTTPConnection(host, port, timeout=5)
    headers = dict(headers or {})
    payload = None
    if body is not None:
        payload = json.dumps(body)
        headers["Content-Type"] = "application/json"
    conn.request(method, path, payload, headers)
    response = conn.getresponse()
    raw = response.read()
    parsed = json.loads(raw or b"{}") if response.getheader("Content-Type", "").startswith("application/json") else raw
    return response, parsed


def build_server(tmp_path):
    scan = ScanService(JobStore(tmp_path / "db.sqlite3"), FakeEngine(), max_workers=1)
    auth = AuthService(AuthStore(tmp_path / "db.sqlite3"), FakeMailer())
    server = serve("127.0.0.1", 0, service=scan, auth_service=auth)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, scan


def close_server(server, scan):
    server.shutdown()
    server.server_close()
    server.smartrisk_developer_api.shutdown()
    scan.executor.shutdown(wait=True)


def test_embed_assets_are_exposed_and_frameable(tmp_path):
    server, scan = build_server(tmp_path)
    try:
        response, body = request(server, "GET", "/embed/scanner")
        assert response.status == 200
        assert b"SmartRisk" in body
        assert response.getheader("Content-Security-Policy") == "frame-ancestors *"

        response, body = request(server, "GET", "/assets/embed.js")
        assert response.status == 200 and b"data-smartrisk-widget" in body
        response, body = request(server, "GET", "/assets/embed-frame.js")
        assert response.status == 200 and b"/v1/embed/scans" in body
    finally:
        close_server(server, scan)


def test_embed_scan_uses_same_engine_and_returns_safe_result(tmp_path):
    server, scan = build_server(tmp_path)
    try:
        response, created = request(
            server,
            "POST",
            "/v1/embed/scans",
            {"address": "0x" + "1" * 40, "chain_id": "1"},
        )
        assert response.status == 202
        assert created["job_id"].startswith("embed_")
        assert created["report_url"].startswith("/v1/embed/reports/embed_")

        response, result = request(server, "GET", f"/v1/embed/reports/{created['job_id']}")
        assert response.status == 200
        assert result["risk"]["score"] == 87
        assert result["network"] == "Ethereum"
        assert result["primary_detection"]["title"] == "Sell restriction"
        assert result["signals"][0]["title"] == "Sellability restriction"
        assert "findings" not in result
        assert "engines" not in result
        assert "evidence" not in result
        assert "request" not in result
    finally:
        close_server(server, scan)


def test_embed_rejects_invalid_address(tmp_path):
    server, scan = build_server(tmp_path)
    try:
        response, body = request(server, "POST", "/v1/embed/scans", {"address": "0x123"})
        assert response.status == 422
        assert body["code"] == "INVALID_ADDRESS"
    finally:
        close_server(server, scan)


def test_embed_result_endpoint_does_not_expose_non_embed_jobs(tmp_path):
    server, scan = build_server(tmp_path)
    try:
        response, body = request(server, "POST", "/v1/scans", {"address": "0x" + "2" * 40, "chain_id": "1", "token_address": "0x" + "2" * 40})
        assert response.status == 202
        response, body = request(server, "GET", "/v1/embed/reports/" + body["job_id"])
        assert response.status == 404
        assert body["code"] == "EMBED_SCAN_NOT_FOUND"
    finally:
        close_server(server, scan)


def test_embed_files_exist():
    root = Path(__file__).resolve().parents[2] / "smartrisk" / "web"
    for name in ("embed.html", "embed.css", "embed.js", "embed-frame.js"):
        assert (root / name).is_file()



def _admin_cookie(server):
    auth = server.smartrisk_admin_service.store.auth
    user = auth.create_user('admin@example.com', 'unused-hash')
    auth.mark_verified(user.id)
    auth.set_user_role(user.id, 'admin')
    response, _ = request(server, 'POST', '/v1/auth/login', {'email': 'admin@example.com', 'password': 'unused-hash'})
    # The normal login verifies a PBKDF2 password, so seed a real hash for test purposes.
    from smartrisk.service.auth import hash_password
    with auth._lock, auth._connect() as db:
        db.execute('UPDATE users SET password_hash=? WHERE id=?', (hash_password('test-password'), user.id))
    response, _ = request(server, 'POST', '/v1/auth/login', {'email': 'admin@example.com', 'password': 'test-password'})
    return response.getheader('Set-Cookie').split(';', 1)[0]


def test_embed_partner_app_enforces_origin_quota_and_token(tmp_path):
    server, scan = build_server(tmp_path)
    try:
        cookie = _admin_cookie(server)
        csrf = request(server, 'GET', '/v1/admin/csrf', headers={'Cookie': cookie})[1]['csrf_token']
        create_resp, created = request(server, 'POST', '/v1/admin/embed/apps', {'name': 'Partner', 'allowed_origins': ['https://partner.example'], 'monthly_quota': 1, 'rate_limit_per_minute': 10}, {'Cookie': cookie, 'X-CSRF-Token': csrf})
        assert create_resp.status == 201
        key = created['app']['public_key']

        bad, bad_body = request(server, 'GET', f'/embed/scanner?app={key}&origin=https://evil.example', headers={'Referer': 'https://evil.example/page'})
        assert bad.status == 403 and bad_body['code'] == 'EMBED_ORIGIN_NOT_ALLOWED'

        ok, html = request(server, 'GET', f'/embed/scanner?app={key}&origin=https://partner.example', headers={'Referer': 'https://partner.example/page'})
        assert ok.status == 200
        assert 'partner.example' in ok.getheader('Content-Security-Policy')
        import re as _re
        match = _re.search(rb'window\.SMART_RISK_EMBED=({.*?});', html)
        assert match
        cfg = json.loads(match.group(1))
        headers = {'X-SmartRisk-Embed-Key': key, 'X-SmartRisk-Embed-Token': cfg['token']}
        scan_resp, scan_body = request(server, 'POST', '/v1/embed/scans', {'address': '0x' + '3' * 40, 'chain_id': '1'}, headers=headers)
        assert scan_resp.status == 202
        quota_resp, quota_body = request(server, 'POST', '/v1/embed/scans', {'address': '0x' + '4' * 40, 'chain_id': '1'}, headers=headers)
        assert quota_resp.status == 429 and quota_body['code'] == 'EMBED_QUOTA_EXCEEDED'

        unauthorized, unauthorized_body = request(server, 'GET', f"/v1/embed/scans/{scan_body['job_id']}")
        assert unauthorized.status == 401 and unauthorized_body['code'] == 'EMBED_APP_REQUIRED'
    finally:
        close_server(server, scan)


def test_embed_partner_admin_analytics_and_rotation(tmp_path):
    server, scan = build_server(tmp_path)
    try:
        cookie = _admin_cookie(server)
        csrf = request(server, 'GET', '/v1/admin/csrf', headers={'Cookie': cookie})[1]['csrf_token']
        _, created = request(server, 'POST', '/v1/admin/embed/apps', {'name': 'Analytics', 'allowed_origins': ['https://analytics.example'], 'monthly_quota': 5, 'rate_limit_per_minute': 10}, {'Cookie': cookie, 'X-CSRF-Token': csrf})
        app_id = created['app']['id']; old_key = created['app']['public_key']
        list_resp, apps = request(server, 'GET', '/v1/admin/embed/apps', headers={'Cookie': cookie})
        assert list_resp.status == 200 and any(x['id'] == app_id for x in apps['apps'])
        analytics_resp, analytics = request(server, 'GET', f'/v1/admin/embed/apps/{app_id}/analytics?days=7', headers={'Cookie': cookie})
        assert analytics_resp.status == 200 and analytics['period_days'] == 7
        rotate_resp, rotated = request(server, 'POST', f'/v1/admin/embed/apps/{app_id}/rotate', {}, {'Cookie': cookie, 'X-CSRF-Token': csrf})
        assert rotate_resp.status == 200 and rotated['app']['public_key'] != old_key
        audit = request(server, 'GET', '/v1/admin/audit?limit=100', headers={'Cookie': cookie})[1]['data']
        assert any(x['target_type'] == 'embed_app' and x['action'] == 'embed_app.key_rotated' for x in audit)
    finally:
        close_server(server, scan)

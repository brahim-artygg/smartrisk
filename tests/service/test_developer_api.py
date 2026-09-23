from __future__ import annotations

import http.client
import json
import threading
import time

import pytest

from smartrisk.service.auth import AuthService, AuthStore
from smartrisk.service.developer_api import DeveloperAPIService, DeveloperStore
from smartrisk.service.http import serve
from smartrisk.service.service import ScanService
from smartrisk.service.store import JobStore


class FakeMailer:
    def __init__(self):
        self.tokens = []
    def send_verification(self, email, token): self.tokens.append(token)
    def send_password_reset(self, email, token): pass


class FakeReport:
    status = "complete"
    def to_dict(self):
        return {
            "run_id": "run",
            "status": "complete",
            "verdict": {"code": "LOW_RISK", "label": "LOW RISK", "primary_detection": {}},
            "risk": {"score": 12, "band": "low", "confidence": 0.9, "coverage": 1.0},
            "risk_dimensions": {"trading": {"score": 5}},
            "engines": [],
            "unknowns": [],
            "versions": {"release": "0.9.0"},
        }


class FakeEngine:
    def analyze(self, request, run_id=None): return FakeReport()


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
    data = response.read()
    parsed = json.loads(data or b"{}") if response.getheader("Content-Type", "").startswith("application/json") else data
    return response, parsed


def test_api_key_is_hashed_and_revoke_works(tmp_path):
    store = DeveloperStore(tmp_path / "db.sqlite3")
    store.ensure_development_subscription("user1")
    meta, raw = store.create_key("user1", "bot")
    assert raw.startswith("sr_live_")
    assert raw not in store._connect().execute("SELECT key_hash FROM api_keys").fetchone()[0]
    key_meta, plan = store.authenticate_key(raw)
    assert key_meta["id"] == meta["id"]
    assert plan["id"] == "developer"
    store.revoke_key("user1", meta["id"])
    with pytest.raises(Exception): store.authenticate_key(raw)


def test_batch_deduplicates_and_is_idempotent(tmp_path):
    scan = ScanService(JobStore(tmp_path / "db.sqlite3"), FakeEngine(), max_workers=2)
    api = DeveloperAPIService(scan, DeveloperStore(tmp_path / "db.sqlite3"))
    api.store.ensure_development_subscription("user1")
    _, raw = api.store.create_key("user1", "test")
    key_meta, plan = api.authenticate(raw)
    batch = api.create_batch("user1", key_meta["id"], plan, [
        {"address": "0x" + "1" * 40, "chain_id": "1"},
        {"address": "0x" + "1" * 40, "chain_id": "1"},
        {"address": "0x" + "2" * 40, "chain_id": "8453"},
    ], "idem-1")
    assert batch["accepted"] == 2
    with pytest.raises(Exception) as exc:
        api.create_batch("user1", key_meta["id"], plan, [{"address": "0x" + "9" * 40}], "idem-1")
    assert getattr(exc.value, "code", None) == "IDEMPOTENCY_CONFLICT"
    same = api.create_batch("user1", key_meta["id"], plan, [
        {"address": "0x" + "1" * 40, "chain_id": "1"},
        {"address": "0x" + "1" * 40, "chain_id": "1"},
        {"address": "0x" + "2" * 40, "chain_id": "8453"},
    ], "idem-1")
    assert same["batch_id"] == batch["batch_id"]
    api.shutdown(); scan.executor.shutdown(wait=True)


def test_http_developer_api_requires_key_but_public_scan_stays_public(tmp_path):
    scan = ScanService(JobStore(tmp_path / "db.sqlite3"), FakeEngine(), max_workers=2)
    auth = AuthService(AuthStore(tmp_path / "db.sqlite3"), FakeMailer())
    server = serve("127.0.0.1", 0, service=scan, auth_service=auth)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        response, data = request(server, "POST", "/v1/api/batches", {"items": [{"address": "0x" + "1" * 40, "chain_id": "1"}]})
        assert response.status == 401 and data["code"] == "INVALID_API_KEY"
        response, data = request(server, "POST", "/v1/scans", {"chain_id": "1", "token_address": "0x" + "2" * 40})
        assert response.status == 202 and data["job_id"]

        auth.register("user@example.com", "correct horse battery staple")
        token = auth.mailer.tokens[-1]
        request(server, "GET", f"/v1/auth/verify?token={token}")
        response, _ = request(server, "POST", "/v1/auth/login", {"email": "user@example.com", "password": "correct horse battery staple"})
        cookie = response.getheader("Set-Cookie").split(";", 1)[0]
        response, data = request(server, "POST", "/v1/developer/api-keys", {"name": "integration-test"}, {"Cookie": cookie})
        assert response.status == 201 and data["key"].startswith("sr_live_")
        api_key = data["key"]
        response, batch = request(server, "POST", "/v1/api/batches", {"items": [{"address": "0x" + "3" * 40, "chain_id": "1"}]}, {"X-API-Key": api_key, "Idempotency-Key": "http-1"})
        assert response.status == 202 and batch["accepted"] == 1
    finally:
        server.shutdown(); server.server_close(); server.smartrisk_developer_api.shutdown(); scan.executor.shutdown(wait=True)


def test_developer_batch_accepts_500_contracts(tmp_path):
    scan = ScanService(JobStore(tmp_path / "db.sqlite3"), FakeEngine(), max_workers=8)
    api = DeveloperAPIService(scan, DeveloperStore(tmp_path / "db.sqlite3"))
    api.store.ensure_development_subscription("user500")
    _, raw = api.store.create_key("user500", "bulk")
    key_meta, plan = api.authenticate(raw)
    items = [{"address": "0x" + f"{index:040x}", "chain_id": "1"} for index in range(1, 501)]
    batch = api.create_batch("user500", key_meta["id"], plan, items, "bulk-500")
    assert batch["accepted"] == 500
    assert batch["total"] == 500
    api.shutdown(); scan.executor.shutdown(wait=False, cancel_futures=True)


def test_quota_is_atomic_across_concurrent_batch_creates(tmp_path):
    store = DeveloperStore(tmp_path / "db.sqlite3")
    plan = {"id": "test", "name": "Test", "monthly_scan_limit": 3, "batch_limit": 3, "requests_per_second": 5, "concurrency": 2, "max_active_batches": 10}
    results, errors = [], []
    barrier = threading.Barrier(2)

    def create():
        try:
            barrier.wait(timeout=2)
            results.append(store.create_batch("u", "k", plan, [{"address": "0x" + "1" * 40}, {"address": "0x" + "2" * 40}, {"address": "0x" + "3" * 40}], None))
        except Exception as exc:
            errors.append(getattr(exc, "code", type(exc).__name__))

    a = threading.Thread(target=create); b = threading.Thread(target=create)
    a.start(); b.start(); a.join(); b.join()
    assert len(results) == 1
    assert errors == ["INSUFFICIENT_QUOTA"] or errors == ["INSUFFICIENT_QUOTA"]
    usage = store.usage("u", plan)
    assert usage["scans_reserved"] == 3


def test_expired_subscription_rejects_api_key(tmp_path):
    store = DeveloperStore(tmp_path / "db.sqlite3")
    store.ensure_development_subscription("u")
    _, raw = store.create_key("u", "expired")
    with store._lock, store._connect() as db:
        db.execute("UPDATE subscriptions SET ends_at=?, status='active' WHERE user_id=?", ("2000-01-01T00:00:00+00:00", "u"))
    with pytest.raises(Exception) as exc:
        store.authenticate_key(raw)
    assert getattr(exc.value, "code", None) == "SUBSCRIPTION_EXPIRED"


def test_api_summary_is_engine_derived_and_programmatic(tmp_path):
    scan = ScanService(JobStore(tmp_path / "db.sqlite3"), FakeEngine(), max_workers=2)
    api = DeveloperAPIService(scan, DeveloperStore(tmp_path / "db.sqlite3"))
    api.store.ensure_development_subscription("u")
    meta, raw = api.store.create_key("u", "summary")
    key_meta, plan = api.authenticate(raw)
    batch = api.create_batch("u", key_meta["id"], plan, [{"address": "0x" + "1" * 40, "chain_id": "1"}], "summary-1")
    deadline = time.time() + 5
    while time.time() < deadline:
        state = api.batch("u", batch["batch_id"])
        if state["status"] in {"complete", "partial", "failed"}:
            break
        time.sleep(0.05)
    rows, total, _ = api.result_rows("u", batch["batch_id"], 0, 1, include_full=False)
    result = rows[0]["result"]
    assert total == 1
    assert result["address"] == "0x" + "1" * 40
    assert result["chain_id"] == "1"
    assert result["risk"]["score_direction"] == "higher_is_more_risky"
    assert "verdict" in result and "risk" in result and "engines" in result
    api.shutdown(); scan.executor.shutdown(wait=True)


def test_500_batch_completes_end_to_end(tmp_path):
    scan = ScanService(JobStore(tmp_path / "db.sqlite3"), FakeEngine(), max_workers=16)
    api = DeveloperAPIService(scan, DeveloperStore(tmp_path / "db.sqlite3"))
    api.store.ensure_development_subscription("u500")
    key_meta, raw = api.store.create_key("u500", "bulk")
    _, plan = api.authenticate(raw)
    items = [{"address": "0x" + f"{index:040x}", "chain_id": "1"} for index in range(1, 501)]
    batch = api.create_batch("u500", key_meta["id"], plan, items, "bulk-e2e")
    deadline = time.time() + 10
    while time.time() < deadline:
        state = api.batch("u500", batch["batch_id"])
        if state["status"] in {"complete", "partial", "failed"}:
            break
        time.sleep(0.05)
    state = api.batch("u500", batch["batch_id"])
    assert state["status"] == "complete"
    assert state["completed"] == 500 and state["failed"] == 0
    usage = api.store.usage("u500", plan)
    assert usage["scans_reserved"] == 500 and usage["scans_completed"] == 500
    api.shutdown(); scan.executor.shutdown(wait=True)


def test_full_report_entitlement_is_explicit(tmp_path):
    store = DeveloperStore(tmp_path / "db.sqlite3")
    store.ensure_development_subscription("u")
    _, raw = store.create_key("u", "paid")
    _, plan = store.authenticate_key(raw)
    assert plan["full_results"] is True
    plan["full_results"] = False
    api = DeveloperAPIService(ScanService(JobStore(tmp_path / "jobs.sqlite3"), FakeEngine(), max_workers=1), store)
    with pytest.raises(Exception) as exc:
        api.result_rows("u", "missing", 0, 1, include_full=True, full_allowed=False)
    assert getattr(exc.value, "code", None) == "FULL_RESULTS_NOT_INCLUDED"
    api.shutdown()

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..core.networks import get_network
from ..state_fork.cli import _load_honeypot, _load_scenarios
from ..unified.models import UnifiedRequest
from .auth import AuthError, User
from .network_resolver import NetworkResolutionError, resolve_network
from .service import ScanService

ADDRESS_RE = __import__("re").compile(r"^0x[a-fA-F0-9]{40}$")
API_KEY_PREFIX = "sr_live_"
API_KEY_BYTES = 32
DEFAULT_PLANS = (
    {
        "id": "developer",
        "name": "Developer",
        "monthly_scan_limit": 10_000,
        "batch_limit": 500,
        "requests_per_second": 5,
        "concurrency": 5,
        "max_active_batches": 2,
        "price_usdt": 29.0,
        "active": 1,
        "full_results": 1,
    },
    {
        "id": "pro",
        "name": "Pro",
        "monthly_scan_limit": 50_000,
        "batch_limit": 2_000,
        "requests_per_second": 25,
        "concurrency": 20,
        "max_active_batches": 4,
        "price_usdt": 99.0,
        "active": 1,
        "full_results": 1,
    },
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _month_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _validate_address(address: str) -> str:
    if not isinstance(address, str) or not ADDRESS_RE.fullmatch(address.strip()):
        raise AuthError("Enter a valid EVM contract address.", "INVALID_ADDRESS", 422)
    return address.strip().lower()


def _plan_dict(row: tuple[Any, ...]) -> dict[str, Any]:
    return {
        "id": row[0],
        "name": row[1],
        "monthly_scan_limit": int(row[2]),
        "batch_limit": int(row[3]),
        "requests_per_second": int(row[4]),
        "concurrency": int(row[5]),
        "max_active_batches": int(row[6]),
        "price_usdt": float(row[7] or 0),
        "active": bool(row[8]),
        "full_results": bool(row[9]) if len(row) > 9 else True,
    }


class DeveloperStore:
    """Persistent developer API state in the same SQLite database as auth/jobs."""

    def __init__(self, path: str | os.PathLike[str] = "artifacts/jobs.sqlite3"):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS api_plans (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    monthly_scan_limit INTEGER NOT NULL,
                    batch_limit INTEGER NOT NULL,
                    requests_per_second INTEGER NOT NULL,
                    concurrency INTEGER NOT NULL,
                    max_active_batches INTEGER NOT NULL,
                    price_usdt REAL NOT NULL DEFAULT 0,
                    active INTEGER NOT NULL DEFAULT 1,
                    full_results INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS subscriptions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL UNIQUE,
                    plan_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    starts_at TEXT NOT NULL,
                    ends_at TEXT,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    prefix TEXT NOT NULL,
                    last4 TEXT NOT NULL,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT,
                    revoked_at TEXT,
                    disabled_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
                CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);

                CREATE TABLE IF NOT EXISTS api_usage_monthly (
                    user_id TEXT NOT NULL,
                    month_key TEXT NOT NULL,
                    scans_reserved INTEGER NOT NULL DEFAULT 0,
                    scans_completed INTEGER NOT NULL DEFAULT 0,
                    scans_failed INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (user_id, month_key)
                );

                CREATE TABLE IF NOT EXISTS api_rate_windows (
                    api_key_id TEXT NOT NULL,
                    second_bucket INTEGER NOT NULL,
                    request_count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (api_key_id, second_bucket)
                );
                CREATE INDEX IF NOT EXISTS idx_api_rate_windows_bucket ON api_rate_windows(second_bucket);

                CREATE TABLE IF NOT EXISTS api_batches (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    api_key_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    total INTEGER NOT NULL,
                    queued INTEGER NOT NULL,
                    running INTEGER NOT NULL DEFAULT 0,
                    completed INTEGER NOT NULL DEFAULT 0,
                    failed INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    idempotency_key TEXT,
                    request_fingerprint TEXT,
                    UNIQUE(user_id, idempotency_key)
                );
                CREATE INDEX IF NOT EXISTS idx_api_batches_user ON api_batches(user_id, created_at);

                CREATE TABLE IF NOT EXISTS api_batch_items (
                    id TEXT PRIMARY KEY,
                    batch_id TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    client_ref TEXT,
                    address TEXT NOT NULL,
                    chain_id TEXT,
                    status TEXT NOT NULL,
                    scan_job_id TEXT,
                    error_code TEXT,
                    error_message TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(batch_id, position)
                );
                CREATE INDEX IF NOT EXISTS idx_api_batch_items_batch ON api_batch_items(batch_id, position);
                CREATE INDEX IF NOT EXISTS idx_api_batch_items_scan ON api_batch_items(scan_job_id);
                """
            )
            key_columns = {row[1] for row in db.execute("PRAGMA table_info(api_keys)").fetchall()}
            if "disabled_at" not in key_columns:
                db.execute("ALTER TABLE api_keys ADD COLUMN disabled_at TEXT")
            plan_columns = {row[1] for row in db.execute("PRAGMA table_info(api_plans)").fetchall()}
            if "price_usdt" not in plan_columns:
                db.execute("ALTER TABLE api_plans ADD COLUMN price_usdt REAL NOT NULL DEFAULT 0")
            if "active" not in plan_columns:
                db.execute("ALTER TABLE api_plans ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
            if "full_results" not in plan_columns:
                db.execute("ALTER TABLE api_plans ADD COLUMN full_results INTEGER NOT NULL DEFAULT 1")
            columns = {row[1] for row in db.execute("PRAGMA table_info(api_batches)").fetchall()}
            if "request_fingerprint" not in columns:
                db.execute("ALTER TABLE api_batches ADD COLUMN request_fingerprint TEXT")
            for plan in DEFAULT_PLANS:
                db.execute(
                    """INSERT OR IGNORE INTO api_plans(id,name,monthly_scan_limit,batch_limit,requests_per_second,concurrency,max_active_batches,price_usdt,active,full_results,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        plan["id"], plan["name"], plan["monthly_scan_limit"], plan["batch_limit"],
                        plan["requests_per_second"], plan["concurrency"], plan["max_active_batches"],
                        plan["price_usdt"], plan["active"], plan.get("full_results", 1), _now(),
                    ),
                )

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30)
        db.execute("PRAGMA busy_timeout = 30000")
        return db

    def plans(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT id,name,monthly_scan_limit,batch_limit,requests_per_second,concurrency,max_active_batches,price_usdt,active,full_results FROM api_plans ORDER BY CASE id WHEN 'developer' THEN 1 WHEN 'pro' THEN 2 ELSE 3 END, id"
            ).fetchall()
        return [_plan_dict(row) for row in rows]

    def plan(self, plan_id: str) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute(
                "SELECT id,name,monthly_scan_limit,batch_limit,requests_per_second,concurrency,max_active_batches,price_usdt,active,full_results FROM api_plans WHERE id=?",
                (plan_id,),
            ).fetchone()
        if not row:
            raise AuthError("Plan not found.", "PLAN_NOT_FOUND", 404)
        return _plan_dict(row)

    def ensure_development_subscription(self, user_id: str) -> dict[str, Any]:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT id,plan_id,status,starts_at,ends_at FROM subscriptions WHERE user_id=?", (user_id,)).fetchone()
            if row:
                return {"id": row[0], "plan_id": row[1], "status": row[2], "starts_at": row[3], "ends_at": row[4]}
            sid = _new_id("sub")
            now = _now()
            db.execute(
                "INSERT INTO subscriptions(id,user_id,plan_id,status,starts_at,updated_at) VALUES(?,?,?,?,?,?)",
                (sid, user_id, "developer", "active", now, now),
            )
            return {"id": sid, "plan_id": "developer", "status": "active", "starts_at": now, "ends_at": None}

    def subscription(self, user_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT id,plan_id,status,starts_at,ends_at,updated_at FROM subscriptions WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            return None
        return {"id": row[0], "plan_id": row[1], "status": row[2], "starts_at": row[3], "ends_at": row[4], "updated_at": row[5]}

    def list_keys(self, user_id: str) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT id,prefix,last4,name,created_at,last_used_at,revoked_at,disabled_at FROM api_keys WHERE user_id=? ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
        return [
            {
                "id": row[0], "prefix": row[1], "last4": row[2], "name": row[3],
                "created_at": row[4], "last_used_at": row[5], "revoked_at": row[6], "disabled_at": row[7],
                "status": "revoked" if row[6] else ("disabled" if row[7] else "active"),
            }
            for row in rows
        ]

    def create_key(self, user_id: str, name: str) -> tuple[dict[str, Any], str]:
        clean_name = " ".join(str(name or "").strip().split())[:80] or "Default key"
        raw = API_KEY_PREFIX + secrets.token_urlsafe(API_KEY_BYTES)
        key_id = _new_id("key")
        now = _now()
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT INTO api_keys(id,user_id,key_hash,prefix,last4,name,created_at) VALUES(?,?,?,?,?,?,?)",
                (key_id, user_id, _hash_secret(raw), API_KEY_PREFIX, raw[-4:], clean_name, now),
            )
        return (
            {"id": key_id, "prefix": API_KEY_PREFIX, "last4": raw[-4:], "name": clean_name, "created_at": now, "status": "active"},
            raw,
        )

    def revoke_key(self, user_id: str, key_id: str) -> None:
        with self._lock, self._connect() as db:
            cur = db.execute(
                "UPDATE api_keys SET revoked_at=COALESCE(revoked_at,?) WHERE id=? AND user_id=?",
                (_now(), key_id, user_id),
            )
            if cur.rowcount != 1:
                raise AuthError("API key not found.", "API_KEY_NOT_FOUND", 404)

    def authenticate_key(self, raw_key: str) -> tuple[dict[str, Any], dict[str, Any]]:
        if not isinstance(raw_key, str) or not raw_key.startswith(API_KEY_PREFIX):
            raise AuthError("Invalid API key.", "INVALID_API_KEY", 401)
        with self._connect() as db:
            row = db.execute(
                """SELECT k.id,k.user_id,k.revoked_at,k.disabled_at,s.plan_id,s.status,p.id,p.name,p.monthly_scan_limit,p.batch_limit,p.requests_per_second,p.concurrency,p.max_active_batches,p.active,p.price_usdt,p.full_results
                   FROM api_keys k
                   LEFT JOIN subscriptions s ON s.user_id=k.user_id
                   LEFT JOIN api_plans p ON p.id=s.plan_id
                   WHERE k.key_hash=?""",
                (_hash_secret(raw_key),),
            ).fetchone()
            if not row or row[2]:
                raise AuthError("Invalid API key.", "INVALID_API_KEY", 401)
            if row[3]:
                raise AuthError("This API key is disabled.", "API_KEY_DISABLED", 403)
            if row[5] not in {"active", "trialing"}:
                raise AuthError("The API subscription is not active.", "SUBSCRIPTION_INACTIVE", 403)
            sub_row = db.execute("SELECT ends_at FROM subscriptions WHERE user_id=?", (row[1],)).fetchone()
            if sub_row and sub_row[0]:
                try:
                    if datetime.fromisoformat(sub_row[0]) <= datetime.now(timezone.utc):
                        raise AuthError("The API subscription has expired.", "SUBSCRIPTION_EXPIRED", 403)
                except ValueError:
                    raise AuthError("The API subscription has expired.", "SUBSCRIPTION_EXPIRED", 403)
            if row[6] is None:
                raise AuthError("The API subscription plan is invalid.", "PLAN_NOT_FOUND", 403)
            if not bool(row[13]):
                raise AuthError("The API subscription plan is inactive.", "PLAN_INACTIVE", 403)
            db.execute("UPDATE api_keys SET last_used_at=? WHERE id=?", (_now(), row[0]))
        key_meta = {"id": row[0], "user_id": row[1]}
        plan = {
            "id": row[6] or "developer",
            "name": row[7] or "Developer",
            "monthly_scan_limit": int(row[8] or 10_000),
            "batch_limit": int(row[9] or 500),
            "requests_per_second": int(row[10] or 5),
            "concurrency": int(row[11] or 5),
            "max_active_batches": int(row[12] or 2),
            "price_usdt": float(row[14] or 0),
            "active": bool(row[13]),
            "full_results": bool(row[15]) if len(row) > 15 else True,
        }
        return key_meta, plan

    def consume_rate_limit(self, api_key_id: str, limit: int) -> bool:
        """Atomically consume one request from a one-second plan window.

        This is stored in SQLite so multiple HTTP handler threads/processes sharing
        the same database cannot each independently grant the full per-key limit.
        """
        limit = max(1, int(limit))
        bucket = int(time.time())
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM api_rate_windows WHERE second_bucket < ?", (bucket - 2,))
            row = db.execute(
                "SELECT request_count FROM api_rate_windows WHERE api_key_id=? AND second_bucket=?",
                (api_key_id, bucket),
            ).fetchone()
            current = int(row[0]) if row else 0
            if current >= limit:
                return False
            if row:
                db.execute(
                    "UPDATE api_rate_windows SET request_count=request_count+1 WHERE api_key_id=? AND second_bucket=?",
                    (api_key_id, bucket),
                )
            else:
                db.execute(
                    "INSERT INTO api_rate_windows(api_key_id,second_bucket,request_count) VALUES(?,?,1)",
                    (api_key_id, bucket),
                )
            return True

    def usage(self, user_id: str, plan: dict[str, Any]) -> dict[str, Any]:
        month = _month_key()
        with self._connect() as db:
            row = db.execute(
                "SELECT scans_reserved,scans_completed,scans_failed FROM api_usage_monthly WHERE user_id=? AND month_key=?",
                (user_id, month),
            ).fetchone()
        reserved, completed, failed = (int(x) for x in row) if row else (0, 0, 0)
        return {
            "month": month,
            "plan": plan,
            "scans_reserved": reserved,
            "scans_completed": completed,
            "scans_failed": failed,
            "scans_remaining": max(0, int(plan["monthly_scan_limit"]) - reserved),
        }

    def reserve_usage(self, user_id: str, count: int, plan: dict[str, Any]) -> None:
        month = _month_key()
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT scans_reserved FROM api_usage_monthly WHERE user_id=? AND month_key=?", (user_id, month)).fetchone()
            reserved = int(row[0]) if row else 0
            if reserved + count > int(plan["monthly_scan_limit"]):
                raise AuthError("Monthly API scan limit reached.", "INSUFFICIENT_QUOTA", 402)
            if row:
                db.execute("UPDATE api_usage_monthly SET scans_reserved=scans_reserved+? WHERE user_id=? AND month_key=?", (count, user_id, month))
            else:
                db.execute("INSERT INTO api_usage_monthly(user_id,month_key,scans_reserved) VALUES(?,?,?)", (user_id, month, count))

    def mark_usage_result(self, user_id: str, completed: int = 0, failed: int = 0) -> None:
        month = _month_key()
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT INTO api_usage_monthly(user_id,month_key,scans_completed,scans_failed) VALUES(?,?,?,?) ON CONFLICT(user_id,month_key) DO UPDATE SET scans_completed=scans_completed+excluded.scans_completed, scans_failed=scans_failed+excluded.scans_failed",
                (user_id, month, completed, failed),
            )

    def create_batch(self, user_id: str, api_key_id: str, plan: dict[str, Any], items: list[dict[str, Any]], idempotency_key: str | None, request_fingerprint: str | None = None) -> dict[str, Any]:
        batch_id = _new_id("bat")
        now = _now()
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if idempotency_key:
                existing = db.execute("SELECT id,request_fingerprint FROM api_batches WHERE user_id=? AND idempotency_key=?", (user_id, idempotency_key)).fetchone()
                if existing:
                    if existing[1] != request_fingerprint:
                        raise AuthError("Idempotency key was already used with a different request.", "IDEMPOTENCY_CONFLICT", 409)
                    existing_id = existing[0]
                else:
                    existing_id = None
            else:
                existing_id = None
            if existing_id:
                return self.get_batch(existing_id, user_id)

            active = db.execute("SELECT COUNT(*) FROM api_batches WHERE user_id=? AND status IN ('queued','running')", (user_id,)).fetchone()[0]
            if int(active) >= int(plan["max_active_batches"]):
                raise AuthError("Too many active batches for this plan.", "ACTIVE_BATCH_LIMIT", 429)

            month = _month_key()
            usage = db.execute("SELECT scans_reserved FROM api_usage_monthly WHERE user_id=? AND month_key=?", (user_id, month)).fetchone()
            reserved = int(usage[0]) if usage else 0
            if reserved + len(items) > int(plan["monthly_scan_limit"]):
                raise AuthError("Monthly API scan limit reached.", "INSUFFICIENT_QUOTA", 402)
            if usage:
                db.execute("UPDATE api_usage_monthly SET scans_reserved=scans_reserved+? WHERE user_id=? AND month_key=?", (len(items), user_id, month))
            else:
                db.execute("INSERT INTO api_usage_monthly(user_id,month_key,scans_reserved) VALUES(?,?,?)", (user_id, month, len(items)))

            db.execute(
                "INSERT INTO api_batches(id,user_id,api_key_id,status,total,queued,running,completed,failed,created_at,updated_at,idempotency_key,request_fingerprint) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (batch_id, user_id, api_key_id, "queued", len(items), len(items), 0, 0, 0, now, now, idempotency_key, request_fingerprint),
            )
            for pos, item in enumerate(items):
                db.execute(
                    "INSERT INTO api_batch_items(id,batch_id,position,client_ref,address,chain_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (_new_id("item"), batch_id, pos, item.get("client_ref"), item["address"], item.get("chain_id"), "queued", now, now),
                )
        return self.get_batch(batch_id, user_id)

    def get_batch(self, batch_id: str, user_id: str | None = None) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute(
                "SELECT id,user_id,api_key_id,status,total,queued,running,completed,failed,created_at,updated_at,idempotency_key,request_fingerprint FROM api_batches WHERE id=?" + (" AND user_id=?" if user_id else ""),
                (batch_id, user_id) if user_id else (batch_id,),
            ).fetchone()
            if not row:
                raise KeyError(batch_id)
            items = db.execute(
                "SELECT id,position,client_ref,address,chain_id,status,scan_job_id,error_code,error_message,created_at,updated_at FROM api_batch_items WHERE batch_id=? ORDER BY position",
                (batch_id,),
            ).fetchall()
        return {
            "batch_id": row[0], "status": row[3], "total": int(row[4]), "queued": int(row[5]),
            "running": int(row[6]), "completed": int(row[7]), "failed": int(row[8]),
            "created_at": row[9], "updated_at": row[10], "idempotency_key": row[11],
            "items": [
                {
                    "id": x[0], "position": int(x[1]), "client_ref": x[2], "address": x[3], "chain_id": x[4],
                    "status": x[5], "scan_job_id": x[6], "error_code": x[7], "error": x[8],
                    "created_at": x[9], "updated_at": x[10],
                }
                for x in items
            ],
        }

    def get_batch_items(self, batch_id: str, statuses: tuple[str, ...] | None = None) -> list[dict[str, Any]]:
        sql = "SELECT id,position,client_ref,address,chain_id,status,scan_job_id,error_code,error_message FROM api_batch_items WHERE batch_id=?"
        params: list[Any] = [batch_id]
        if statuses:
            sql += " AND status IN (" + ",".join("?" for _ in statuses) + ")"
            params.extend(statuses)
        sql += " ORDER BY position"
        with self._connect() as db:
            rows = db.execute(sql, tuple(params)).fetchall()
        return [
            {"id": r[0], "position": int(r[1]), "client_ref": r[2], "address": r[3], "chain_id": r[4], "status": r[5], "scan_job_id": r[6], "error_code": r[7], "error": r[8]}
            for r in rows
        ]

    def update_item(self, item_id: str, **fields: Any) -> None:
        allowed = {"status", "chain_id", "scan_job_id", "error_code", "error_message"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return
        updates["updated_at"] = _now()
        clauses = ",".join(f"{key}=?" for key in updates)
        params = list(updates.values()) + [item_id]
        with self._lock, self._connect() as db:
            db.execute(f"UPDATE api_batch_items SET {clauses} WHERE id=?", params)

    def update_batch(self, batch_id: str, **fields: Any) -> None:
        allowed = {"status", "queued", "running", "completed", "failed"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return
        updates["updated_at"] = _now()
        clauses = ",".join(f"{key}=?" for key in updates)
        params = list(updates.values()) + [batch_id]
        with self._lock, self._connect() as db:
            db.execute(f"UPDATE api_batches SET {clauses} WHERE id=?", params)

    def active_batches(self, user_id: str) -> int:
        with self._connect() as db:
            row = db.execute("SELECT COUNT(*) FROM api_batches WHERE user_id=? AND status IN ('queued','running')", (user_id,)).fetchone()
        return int(row[0])

    def active_batch_records(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT id,user_id,status FROM api_batches WHERE status IN ('queued','running') ORDER BY created_at"
            ).fetchall()
        return [{"batch_id": row[0], "user_id": row[1], "status": row[2]} for row in rows]

    def recover_batch_items(self, batch_id: str) -> None:
        """Reset coordinator-owned item states that never received a child scan job."""
        now = _now()
        with self._lock, self._connect() as db:
            db.execute(
                "UPDATE api_batch_items SET status='queued', updated_at=? WHERE batch_id=? AND status='running' AND (scan_job_id IS NULL OR scan_job_id='')",
                (now, batch_id),
            )

    def batch_for_scan(self, user_id: str, scan_job_id: str) -> tuple[str, dict[str, Any]] | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT i.batch_id,i.position,i.client_ref,i.address,i.chain_id,i.status,i.error_code,i.error_message FROM api_batch_items i JOIN api_batches b ON b.id=i.batch_id WHERE b.user_id=? AND i.scan_job_id=?",
                (user_id, scan_job_id),
            ).fetchone()
        if not row:
            return None
        return row[0], {
            "position": int(row[1]), "client_ref": row[2], "address": row[3], "chain_id": row[4],
            "status": row[5], "error_code": row[6], "error": row[7],
        }


class DeveloperAPIService:
    def __init__(self, scan_service: ScanService, store: DeveloperStore | None = None):
        self.scan_service = scan_service
        self.store = store or DeveloperStore(scan_service.store.path)
        self._executor = ThreadPoolExecutor(max_workers=int(os.getenv("SMARTRISK_BATCH_COORDINATORS", "4")), thread_name_prefix="smartrisk-batch")
        self._running: set[str] = set()
        self._lock = threading.Lock()
        # Resume coordinator work after process restarts. Child scan jobs are
        # independently recovered by ScanService, so this only re-attaches
        # batch orchestration to their durable records.
        self._recover_active_batches()

    def _recover_active_batches(self) -> None:
        for record in self.store.active_batch_records():
            try:
                self.store.recover_batch_items(record["batch_id"])
                sub = self.store.subscription(record["user_id"])
                plan_id = sub["plan_id"] if sub and sub.get("plan_id") else "developer"
                plan = self.store.plan(plan_id)
                with self._lock:
                    if record["batch_id"] in self._running:
                        continue
                    self._running.add(record["batch_id"])
                self._executor.submit(self._process_batch, record["batch_id"], record["user_id"], plan, [])
            except Exception:
                with self._lock:
                    self._running.discard(record["batch_id"])

    @property
    def billing_required(self) -> bool:
        return os.getenv("SMARTRISK_BILLING_REQUIRED", "false").lower() in {"1", "true", "yes", "on"}

    def ensure_subscription(self, user_id: str) -> dict[str, Any] | None:
        sub = self.store.subscription(user_id)
        if sub is None and not self.billing_required:
            sub = self.store.ensure_development_subscription(user_id)
        return sub

    def subscription_for_user(self, user_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        sub = self.ensure_subscription(user_id)
        if not sub or sub["status"] not in {"active", "trialing"}:
            raise AuthError("An active developer subscription is required.", "SUBSCRIPTION_INACTIVE", 403)
        if sub.get("ends_at"):
            try:
                if datetime.fromisoformat(sub["ends_at"]) <= datetime.now(timezone.utc):
                    raise AuthError("The developer subscription has expired.", "SUBSCRIPTION_EXPIRED", 403)
            except ValueError:
                raise AuthError("The developer subscription has expired.", "SUBSCRIPTION_EXPIRED", 403)
        return sub, self.store.plan(sub["plan_id"])

    def dashboard(self, user: User) -> dict[str, Any]:
        sub = self.store.subscription(user.id)
        plan = self.store.plan(sub["plan_id"]) if sub and sub.get("plan_id") else None
        usage = self.store.usage(user.id, plan) if plan else {"scans_reserved": 0, "scans_completed": 0, "scans_failed": 0, "scans_remaining": 0}
        return {
            "user": user.to_dict(),
            "subscription": sub,
            "plan": plan,
            "api_keys": self.store.list_keys(user.id),
            "usage": usage,
            "billing_required": self.billing_required,
            "billing_status": "active" if sub and sub.get("status") in {"active", "trialing"} else ("required" if self.billing_required else "not_connected"),
        }

    def create_api_key(self, user: User, name: str) -> dict[str, Any]:
        self.subscription_for_user(user.id)
        keys = [item for item in self.store.list_keys(user.id) if item["status"] == "active"]
        if len(keys) >= 5:
            raise AuthError("You can have up to 5 active API keys.", "API_KEY_LIMIT", 409)
        meta, raw = self.store.create_key(user.id, name)
        return {"key": raw, "key_id": meta["id"], "key_details": meta, "warning": "Store this key now. It will not be shown again."}

    def list_api_keys(self, user: User) -> list[dict[str, Any]]:
        return self.store.list_keys(user.id)

    def revoke_api_key(self, user: User, key_id: str) -> None:
        self.store.revoke_key(user.id, key_id)

    def rotate_api_key(self, user: User, key_id: str) -> dict[str, Any]:
        keys = self.store.list_keys(user.id)
        current = next((item for item in keys if item["id"] == key_id and item["status"] == "active"), None)
        if current is None:
            raise AuthError("API key not found.", "API_KEY_NOT_FOUND", 404)
        self.store.revoke_key(user.id, key_id)
        meta, raw = self.store.create_key(user.id, current["name"])
        return {"key": raw, "key_id": meta["id"], "key_details": meta, "replaced_key_id": key_id, "warning": "Store this key now. It will not be shown again."}

    def rate_allowed(self, key_id: str, limit: int) -> bool:
        return self.store.consume_rate_limit(key_id, limit)

    def authenticate(self, raw_key: str) -> tuple[dict[str, Any], dict[str, Any]]:
        return self.store.authenticate_key(raw_key)

    def existing_idempotent_batch(self, user_id: str, idempotency_key: str | None) -> dict[str, Any] | None:
        if not idempotency_key:
            return None
        with self.store._connect() as db:
            row = db.execute("SELECT id FROM api_batches WHERE user_id=? AND idempotency_key=?", (user_id, idempotency_key)).fetchone()
        return self.store.get_batch(row[0], user_id) if row else None

    def create_batch(self, user_id: str, api_key_id: str, plan: dict[str, Any], items: list[dict[str, Any]], idempotency_key: str | None) -> dict[str, Any]:
        if not isinstance(items, list):
            raise AuthError("items must be an array.", "INVALID_BATCH_ITEMS", 422)
        if len(items) < 1:
            raise AuthError("Batch must contain at least one contract.", "EMPTY_BATCH", 422)
        if len(items) > int(plan["batch_limit"]):
            raise AuthError(f"Your plan supports up to {plan['batch_limit']} contracts per batch.", "BATCH_TOO_LARGE", 413)

        normalized: list[dict[str, Any]] = []
        seen: set[tuple[str, str | None]] = set()
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise AuthError(f"Batch item {index + 1} must be an object.", "INVALID_BATCH_ITEM", 422)
            address = _validate_address(item.get("address") or item.get("token_address") or "")
            raw_chain = item.get("chain_id") or item.get("chain")
            chain_id = None
            if raw_chain is not None and str(raw_chain).strip() != "":
                try:
                    chain_id = get_network(raw_chain).chain_id
                except KeyError as exc:
                    raise AuthError(f"Unsupported SmartRisk network: {raw_chain}", "UNSUPPORTED_NETWORK", 422) from exc
            key = (address, chain_id)
            if key in seen:
                continue
            seen.add(key)
            normalized.append({
                "address": address,
                "chain_id": chain_id,
                "client_ref": str(item.get("id") or item.get("client_ref") or f"item_{index + 1}"),
                "project": item.get("project"),
                "block_tag": item.get("block_tag", "safe"),
                "block_number": item.get("block_number"),
                "window_blocks": item.get("window_blocks", 10_000),
            })

        if not normalized:
            raise AuthError("Batch contains no unique contracts.", "EMPTY_BATCH", 422)
        if len(normalized) > int(plan["batch_limit"]):
            raise AuthError(f"Your plan supports up to {plan['batch_limit']} unique contracts per batch.", "BATCH_TOO_LARGE", 413)

        request_fingerprint = _hash_secret(json.dumps({"items": normalized}, sort_keys=True, separators=(",", ":"), default=str))
        batch = self.store.create_batch(user_id, api_key_id, plan, normalized, idempotency_key, request_fingerprint=request_fingerprint)
        with self._lock:
            if batch["batch_id"] not in self._running:
                self._running.add(batch["batch_id"])
                self._executor.submit(self._process_batch, batch["batch_id"], user_id, plan, normalized)
        batch.pop("items", None)
        batch["accepted"] = len(normalized)
        batch["deduplicated"] = len(items) - len(normalized)
        return batch

    def _build_request(self, item: dict[str, Any]) -> UnifiedRequest:
        chain_id = item.get("chain_id")
        if not chain_id:
            chain_id = resolve_network(item["address"]).chain_id
        return UnifiedRequest(
            project=item.get("project"),
            chain_id=chain_id,
            token_address=item["address"],
            scenarios=_load_scenarios(item["scenarios"]) if item.get("scenarios") else [],
            honeypot=_load_honeypot(item["honeypot"]) if item.get("honeypot") else None,
            block_tag=item.get("block_tag", "safe"),
            block_number=item.get("block_number"),
            compiler_version=item.get("compiler_version"),
            window_blocks=item.get("window_blocks", 10_000),
            deployer_address=item.get("deployer_address"),
            scan_profile="paid",
        )

    def _process_batch(self, batch_id: str, user_id: str, plan: dict[str, Any], normalized: list[dict[str, Any]]) -> None:
        try:
            self.store.update_batch(batch_id, status="running")
            items = self.store.get_batch_items(batch_id)
            # Bounded submission concurrency keeps network discovery from creating a 5000-RPC burst.
            limit = max(1, int(plan["concurrency"]))
            with ThreadPoolExecutor(max_workers=limit, thread_name_prefix=f"smartrisk-batch-submit-{batch_id[:8]}") as executor:
                future_map = {
                    executor.submit(self._submit_one, batch_id, item): item
                    for item in items
                    if item["status"] == "queued"
                }
                for future in as_completed(future_map):
                    item = future_map[future]
                    try:
                        future.result()
                    except Exception as exc:
                        code = exc.code if isinstance(exc, AuthError) else "SCAN_SUBMISSION_FAILED"
                        self.store.update_item(item["id"], status="failed", error_code=code, error_message=str(exc))
                        self.store.update_batch(batch_id, failed=self._count_batch(batch_id, "failed"))
            self._monitor_batch(batch_id, user_id)
        finally:
            with self._lock:
                self._running.discard(batch_id)

    def _submit_one(self, batch_id: str, item: dict[str, Any]) -> None:
        self.store.update_item(item["id"], status="running")
        try:
            payload = {
                "address": item["address"],
                "chain_id": item["chain_id"],
                "project": item.get("project"),
                "block_tag": item.get("block_tag", "safe"),
                "block_number": item.get("block_number"),
                "window_blocks": item.get("window_blocks", 10_000),
            }
            request = self._build_request(payload)
            self.store.update_item(item["id"], chain_id=request.chain_id)
            job = self.scan_service.submit(request)
            self.store.update_item(item["id"], scan_job_id=job["job_id"], status="running")
        except NetworkResolutionError as exc:
            self.store.update_item(item["id"], status="failed", error_code="NETWORK_RESOLUTION_FAILED", error_message=str(exc))
        except Exception as exc:
            self.store.update_item(item["id"], status="failed", error_code="SCAN_SUBMISSION_FAILED", error_message=str(exc))

    def _monitor_batch(self, batch_id: str, user_id: str) -> None:
        while True:
            items = self.store.get_batch_items(batch_id)
            remaining = False
            for item in items:
                if item["status"] not in {"running"} or not item.get("scan_job_id"):
                    continue
                remaining = True
                try:
                    job = self.scan_service.get(item["scan_job_id"])
                except KeyError:
                    self.store.update_item(item["id"], status="failed", error_code="SCAN_NOT_FOUND", error_message="Child scan job not found.")
                    continue
                if job["status"] in {"complete", "partial", "unknown"}:
                    self.store.update_item(item["id"], status="completed")
                elif job["status"] == "failed":
                    self.store.update_item(item["id"], status="failed", error_code="SCAN_FAILED", error_message=job.get("error") or "Scan failed.")
                else:
                    remaining = True
            counts = {status: self._count_batch(batch_id, status) for status in ("queued", "running", "completed", "failed")}
            total = sum(counts.values())
            if remaining and total < self.store.get_batch(batch_id, user_id)["total"]:
                self.store.update_batch(batch_id, queued=counts["queued"], running=counts["running"], completed=counts["completed"], failed=counts["failed"], status="running")
                time.sleep(0.8)
                continue
            status = "complete" if counts["failed"] == 0 and counts["completed"] == total else "partial" if counts["completed"] > 0 else "failed"
            self.store.update_batch(batch_id, queued=counts["queued"], running=counts["running"], completed=counts["completed"], failed=counts["failed"], status=status)
            self.store.mark_usage_result(user_id, completed=counts["completed"], failed=counts["failed"])
            return

    def _count_batch(self, batch_id: str, status: str) -> int:
        with self.store._connect() as db:
            row = db.execute("SELECT COUNT(*) FROM api_batch_items WHERE batch_id=? AND status=?", (batch_id, status)).fetchone()
        return int(row[0])

    def batch(self, user_id: str, batch_id: str) -> dict[str, Any]:
        return self.store.get_batch(batch_id, user_id)

    def result_rows(self, user_id: str, batch_id: str, offset: int, limit: int, include_full: bool = False, full_allowed: bool = True) -> tuple[list[dict[str, Any]], int, dict[str, Any]]:
        if include_full and not full_allowed:
            raise AuthError("Your plan does not include full scan reports.", "FULL_RESULTS_NOT_INCLUDED", 403)
        if include_full and limit > 100:
            limit = 100
        batch = self.store.get_batch(batch_id, user_id)
        items = batch["items"][offset:offset + limit]
        rows = []
        for item in items:
            row = {
                "position": item["position"],
                "id": item["id"],
                "client_ref": item["client_ref"],
                "address": item["address"],
                "chain_id": item["chain_id"],
                "status": item["status"],
                "scan_job_id": item["scan_job_id"],
                "error": item["error"],
            }
            if item["scan_job_id"]:
                try:
                    job = self.scan_service.get(item["scan_job_id"])
                    if job.get("result"):
                        row["result"] = summarize_result(job["result"], address=item["address"], chain_id=item["chain_id"]) if not include_full else job["result"]
                except KeyError:
                    pass
            rows.append(row)
        return rows, len(batch["items"]), batch

    def single_scan(self, user_id: str, scan_job_id: str, include_full: bool = False, full_allowed: bool = True) -> dict[str, Any]:
        if include_full and not full_allowed:
            raise AuthError("Your plan does not include full scan reports.", "FULL_RESULTS_NOT_INCLUDED", 403)
        belongs = self.store.batch_for_scan(user_id, scan_job_id)
        if not belongs:
            raise AuthError("Scan not found.", "SCAN_NOT_FOUND", 404)
        job = self.scan_service.get(scan_job_id)
        payload: dict[str, Any] = {"scan_job_id": scan_job_id, "status": job["status"]}
        if job.get("result"):
            payload["result"] = job["result"] if include_full else summarize_result(job["result"], address=belongs[1]["address"], chain_id=belongs[1]["chain_id"])
        if job.get("error"):
            payload["error"] = job["error"]
        return payload

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    def export(self, user_id: str, batch_id: str, fmt: str, include_full: bool = False, full_allowed: bool = True) -> tuple[str, str]:
        rows, _, _ = self.result_rows(user_id, batch_id, 0, 10000, include_full=include_full, full_allowed=full_allowed)
        if fmt == "json":
            return "application/json", json.dumps(rows, indent=2, sort_keys=True, default=str)
        if fmt == "jsonl":
            return "application/x-ndjson", "\n".join(json.dumps(row, sort_keys=True, default=str) for row in rows) + ("\n" if rows else "")
        if fmt == "csv":
            fields = ["position", "client_ref", "address", "chain_id", "status", "scan_job_id", "error", "risk_score", "risk_band", "verdict", "confidence", "coverage"]
            buffer = io.StringIO()
            writer = csv.DictWriter(buffer, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                result = row.get("result") or {}
                risk = result.get("risk") or {}
                verdict = result.get("verdict") or {}
                writer.writerow({
                    **{key: row.get(key) for key in fields if key in row},
                    "risk_score": risk.get("score"), "risk_band": risk.get("band"),
                    "verdict": verdict.get("code"), "confidence": risk.get("confidence"), "coverage": risk.get("coverage"),
                })
            return "text/csv; charset=utf-8", buffer.getvalue()
        raise AuthError("Unsupported export format.", "INVALID_EXPORT_FORMAT", 422)


def summarize_result(report: dict[str, Any], *, address: str | None = None, chain_id: str | None = None) -> dict[str, Any]:
    risk = dict(report.get("risk") or {})
    verdict = dict(report.get("verdict") or {})
    # SmartRisk scores are risk-oriented: higher numbers mean more risk.
    risk["score_direction"] = "higher_is_more_risky"
    findings = report.get("findings") or []
    detections = [
        {
            "id": item.get("finding_id"),
            "rule_id": item.get("rule_id"),
            "title": item.get("title"),
            "severity": item.get("severity"),
            "status": item.get("status"),
            "confidence": item.get("confidence"),
            "evidence_refs": item.get("evidence_refs") or [],
        }
        for item in findings if isinstance(item, dict)
    ]
    return {
        "schema_version": "1.0",
        "status": report.get("status"),
        "address": address,
        "chain_id": chain_id,
        "run_id": report.get("run_id"),
        "verdict": verdict,
        "risk": risk,
        "primary_detection": verdict.get("primary_detection") or {},
        "detections": detections,
        "risk_dimensions": report.get("risk_dimensions") or {},
        "engines": [
            {
                "name": item.get("name"),
                "status": item.get("status"),
                "score": item.get("score"),
                "confidence": item.get("confidence"),
                "coverage": item.get("coverage"),
                "unknowns": item.get("unknowns") or [],
            }
            for item in report.get("engines") or []
        ],
        "unknowns": report.get("unknowns") or [],
        "versions": report.get("versions") or {},
    }

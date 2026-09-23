from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .embed_partner import validate_origins

from .auth import AuthError, AuthStore, User
from .billing import ADDRESS_RE, BillingStore, ETHEREUM_CHAIN_ID, USDT_ETHEREUM_CONTRACT, USDT_DECIMALS


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


class AdminStore:
    """Back-office data store. All destructive changes are audited and most account data uses soft states."""

    def __init__(self, path: str | Path = "artifacts/jobs.sqlite3"):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.auth = AuthStore(self.path)
        self.billing = BillingStore(self.path)
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS site_ads (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    body TEXT NOT NULL,
                    cta_label TEXT,
                    cta_url TEXT,
                    placement TEXT NOT NULL DEFAULT 'banner',
                    audience TEXT NOT NULL DEFAULT 'all',
                    priority INTEGER NOT NULL DEFAULT 0,
                    starts_at TEXT,
                    ends_at TEXT,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_site_ads_active ON site_ads(active, placement, priority);

                CREATE TABLE IF NOT EXISTS coupon_codes (
                    id TEXT PRIMARY KEY,
                    code TEXT NOT NULL UNIQUE,
                    discount_type TEXT NOT NULL,
                    discount_value REAL NOT NULL,
                    max_redemptions INTEGER,
                    used_count INTEGER NOT NULL DEFAULT 0,
                    plan_id TEXT,
                    starts_at TEXT,
                    ends_at TEXT,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_coupon_codes_active ON coupon_codes(active, code);

                CREATE TABLE IF NOT EXISTS plan_grants (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    plan_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    starts_at TEXT NOT NULL,
                    ends_at TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    granted_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    previous_plan_id TEXT,
                    previous_status TEXT,
                    previous_ends_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_plan_grants_user ON plan_grants(user_id, status);

                CREATE TABLE IF NOT EXISTS payment_transactions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    subscription_id TEXT,
                    plan_id TEXT,
                    amount_usdt REAL NOT NULL,
                    currency TEXT NOT NULL DEFAULT 'USDT',
                    network TEXT,
                    tx_hash TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    invoice_ref TEXT,
                    metadata_json TEXT,
                    paid_at TEXT,
                    verified_by TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_payments_user ON payment_transactions(user_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_payments_status ON payment_transactions(status, created_at);

                CREATE TABLE IF NOT EXISTS platform_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    value_type TEXT NOT NULL DEFAULT 'string',
                    description TEXT,
                    updated_at TEXT NOT NULL,
                    updated_by TEXT
                );

                CREATE TABLE IF NOT EXISTS embed_apps (
                    id TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    allowed_origins_json TEXT NOT NULL,
                    monthly_quota INTEGER NOT NULL DEFAULT 1000,
                    rate_limit_per_minute INTEGER NOT NULL DEFAULT 30,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_embed_apps_active ON embed_apps(active);

                CREATE TABLE IF NOT EXISTS embed_scan_map (
                    job_id TEXT PRIMARY KEY,
                    app_id TEXT,
                    origin TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_embed_scan_map_app ON embed_scan_map(app_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS embed_usage_monthly (
                    app_id TEXT NOT NULL,
                    month_key TEXT NOT NULL,
                    scans_submitted INTEGER NOT NULL DEFAULT 0,
                    scans_completed INTEGER NOT NULL DEFAULT 0,
                    scans_failed INTEGER NOT NULL DEFAULT 0,
                    last_scan_at TEXT,
                    PRIMARY KEY(app_id, month_key)
                );

                CREATE TABLE IF NOT EXISTS embed_events (
                    id TEXT PRIMARY KEY,
                    app_id TEXT,
                    job_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    origin TEXT,
                    client_ip TEXT,
                    user_agent TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(job_id, event_type)
                );
                CREATE INDEX IF NOT EXISTS idx_embed_events_app ON embed_events(app_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_embed_events_origin ON embed_events(origin, created_at DESC);

                CREATE TABLE IF NOT EXISTS admin_audit_log (
                    id TEXT PRIMARY KEY,
                    admin_user_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_type TEXT,
                    target_id TEXT,
                    details_json TEXT,
                    ip_address TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit_log(created_at DESC);
                """
            )
            defaults = {
                "maintenance_mode": ("false", "bool", "Put the platform into read-only maintenance mode."),
                "public_scans_enabled": ("true", "bool", "Allow anonymous contract scans."),
                "embed_enabled": ("true", "bool", "Allow SmartRisk Embed/Widget scans."),
                "registration_enabled": ("true", "bool", "Allow new user registrations."),
                "developer_api_enabled": ("true", "bool", "Allow developer API traffic."),
                "ads_enabled": ("true", "bool", "Render active site promotions."),
            }
            now = _now()
            grant_columns = {row[1] for row in db.execute("PRAGMA table_info(plan_grants)").fetchall()}
            for col in ("previous_plan_id", "previous_status", "previous_ends_at"):
                if col not in grant_columns:
                    db.execute(f"ALTER TABLE plan_grants ADD COLUMN {col} TEXT")
            for key, (value, typ, desc) in defaults.items():
                db.execute(
                    "INSERT OR IGNORE INTO platform_settings(key,value,value_type,description,updated_at) VALUES(?,?,?,?,?)",
                    (key, value, typ, desc, now),
                )

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.execute("PRAGMA busy_timeout=30000")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    # ---------- dashboard ----------
    def overview(self) -> dict[str, Any]:
        with self._connect() as db:
            users = db.execute("SELECT COUNT(*) FROM users WHERE status!='deleted'").fetchone()[0]
            verified = db.execute("SELECT COUNT(*) FROM users WHERE status!='deleted' AND email_verified=1").fetchone()[0]
            active_keys = db.execute("SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NULL AND disabled_at IS NULL").fetchone()[0]
            active_subs = db.execute("SELECT COUNT(*) FROM subscriptions WHERE status IN ('active','trialing')").fetchone()[0]
            pending_payments = db.execute("SELECT COUNT(*) FROM payment_transactions WHERE status='pending'").fetchone()[0]
            confirmed_revenue = db.execute("SELECT COALESCE(SUM(amount_usdt),0) FROM payment_transactions WHERE status='confirmed'").fetchone()[0]
            active_batches = db.execute("SELECT COUNT(*) FROM api_batches WHERE status IN ('queued','running')").fetchone()[0]
            scans_month = db.execute("SELECT COALESCE(SUM(scans_reserved),0) FROM api_usage_monthly WHERE month_key=strftime('%Y-%m','now')").fetchone()[0]
            failed_jobs = db.execute("SELECT COUNT(*) FROM jobs WHERE status='failed'").fetchone()[0]
        return {
            "users": int(users), "verified_users": int(verified), "active_api_keys": int(active_keys),
            "active_subscriptions": int(active_subs), "pending_payments": int(pending_payments),
            "confirmed_revenue_usdt": float(confirmed_revenue or 0), "active_batches": int(active_batches),
            "api_scans_reserved_this_month": int(scans_month or 0), "failed_jobs": int(failed_jobs or 0),
            "settings": self.settings(),
            "billing": self.billing_overview(),
        }

    # ---------- users ----------
    def list_users(self, search: str = "", status: str | None = None, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        where, params = ["1=1"], []
        if search:
            where.append("(u.email LIKE ? OR u.id LIKE ?)")
            params += [f"%{search.lower()}%", f"%{search}%"]
        if status:
            where.append("u.status=?"); params.append(status)
        where_sql = " AND ".join(where)
        with self._connect() as db:
            total = db.execute(f"SELECT COUNT(*) FROM users u WHERE {where_sql}", tuple(params)).fetchone()[0]
            rows = db.execute(
                f"""SELECT u.id,u.email,u.email_verified,u.status,u.role,u.created_at,u.last_login_at,
                    s.plan_id,s.status,s.ends_at,
                    (SELECT COUNT(*) FROM api_keys k WHERE k.user_id=u.id AND k.revoked_at IS NULL AND k.disabled_at IS NULL) active_keys
                    FROM users u LEFT JOIN subscriptions s ON s.user_id=u.id
                    WHERE {where_sql} ORDER BY u.created_at DESC LIMIT ? OFFSET ?""",
                tuple(params + [max(1, min(limit, 200)), max(0, offset)]),
            ).fetchall()
        data = []
        for r in rows:
            data.append({
                "id": r[0], "email": r[1], "email_verified": bool(r[2]), "status": r[3], "role": r[4],
                "created_at": r[5], "last_login_at": r[6],
                "subscription": {"plan_id": r[7], "status": r[8], "ends_at": r[9]} if r[7] else None,
                "active_api_keys": int(r[10]),
            })
        return {"data": data, "pagination": {"total": int(total), "offset": offset, "limit": limit}}

    def user_detail(self, user_id: str) -> dict[str, Any]:
        user = self.auth.get_user(user_id)
        if not user:
            raise AuthError("User not found.", "USER_NOT_FOUND", 404)
        with self._connect() as db:
            sub = db.execute("SELECT id,plan_id,status,starts_at,ends_at,updated_at FROM subscriptions WHERE user_id=?", (user_id,)).fetchone()
            keys = db.execute("SELECT id,prefix,last4,name,created_at,last_used_at,revoked_at,disabled_at FROM api_keys WHERE user_id=? ORDER BY created_at DESC", (user_id,)).fetchall()
            usage = db.execute("SELECT month_key,scans_reserved,scans_completed,scans_failed FROM api_usage_monthly WHERE user_id=? ORDER BY month_key DESC LIMIT 12", (user_id,)).fetchall()
            payments = db.execute("SELECT id,amount_usdt,network,tx_hash,status,invoice_ref,paid_at,created_at,plan_id FROM payment_transactions WHERE user_id=? ORDER BY created_at DESC LIMIT 20", (user_id,)).fetchall()
        return {
            "user": user.to_dict(),
            "subscription": ({"id": sub[0], "plan_id": sub[1], "status": sub[2], "starts_at": sub[3], "ends_at": sub[4], "updated_at": sub[5]} if sub else None),
            "api_keys": [{"id": r[0], "prefix": r[1], "last4": r[2], "name": r[3], "created_at": r[4], "last_used_at": r[5], "revoked_at": r[6], "disabled_at": r[7], "status": "revoked" if r[6] else ("disabled" if r[7] else "active")} for r in keys],
            "usage": [{"month": r[0], "scans_reserved": int(r[1]), "scans_completed": int(r[2]), "scans_failed": int(r[3])} for r in usage],
            "payments": [{"id": r[0], "amount_usdt": float(r[1]), "network": r[2], "tx_hash": r[3], "status": r[4], "invoice_ref": r[5], "paid_at": r[6], "created_at": r[7], "plan_id": r[8]} for r in payments],
        }

    def set_user_status(self, user_id: str, status: str, admin_id: str, ip: str | None = None) -> dict[str, Any]:
        if user_id == admin_id and status != "active":
            raise AuthError("You cannot disable your own administrator account.", "SELF_LOCKOUT_PREVENTED", 409)
        if status != "active":
            with self._connect() as db:
                target_role = db.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
                if target_role and target_role[0] == "admin":
                    admin_count = db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND status='active' AND id!=?", (user_id,)).fetchone()[0]
                    if admin_count < 1:
                        raise AuthError("At least one active administrator must remain.", "LAST_ADMIN_PROTECTED", 409)
        user = self.auth.set_user_status(user_id, status)
        self.audit(admin_id, "user.status_changed", "user", user_id, {"status": status}, ip)
        return user.to_dict()

    def set_user_role(self, user_id: str, role: str, admin_id: str, ip: str | None = None) -> dict[str, Any]:
        if user_id == admin_id and role != "admin":
            raise AuthError("You cannot remove your own administrator role.", "SELF_LOCKOUT_PREVENTED", 409)
        if role != "admin":
            with self._connect() as db:
                target_role = db.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
                if target_role and target_role[0] == "admin":
                    admin_count = db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND status='active' AND id!=?", (user_id,)).fetchone()[0]
                    if admin_count < 1:
                        raise AuthError("At least one active administrator must remain.", "LAST_ADMIN_PROTECTED", 409)
        user = self.auth.set_user_role(user_id, role)
        self.audit(admin_id, "user.role_changed", "user", user_id, {"role": role}, ip)
        return user.to_dict()

    def upsert_subscription(self, user_id: str, plan_id: str, status: str, ends_at: str | None, admin_id: str, ip: str | None = None) -> dict[str, Any]:
        with self._connect() as db:
            if not db.execute("SELECT 1 FROM api_plans WHERE id=?", (plan_id,)).fetchone():
                raise AuthError("Plan not found.", "PLAN_NOT_FOUND", 404)
        if status not in {"active", "trialing", "canceled", "past_due", "expired"}:
            raise AuthError("Invalid subscription status.", "INVALID_SUBSCRIPTION_STATUS", 422)
        with self._lock, self._connect() as db:
            now = _now()
            row = db.execute("SELECT id FROM subscriptions WHERE user_id=?", (user_id,)).fetchone()
            if row:
                db.execute("UPDATE subscriptions SET plan_id=?,status=?,ends_at=?,updated_at=? WHERE user_id=?", (plan_id,status,ends_at,now,user_id))
                sid = row[0]
            else:
                sid = _id("sub")
                db.execute("INSERT INTO subscriptions(id,user_id,plan_id,status,starts_at,ends_at,updated_at) VALUES(?,?,?,?,?,?,?)", (sid,user_id,plan_id,status,now,ends_at,now))
        self.audit(admin_id, "subscription.updated", "subscription", sid, {"user_id": user_id, "plan_id": plan_id, "status": status, "ends_at": ends_at}, ip)
        return {"id": sid, "user_id": user_id, "plan_id": plan_id, "status": status, "ends_at": ends_at}

    # ---------- API keys ----------
    def list_api_keys(self, search: str = "", status: str | None = None, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        where, params = ["1=1"], []
        if search:
            where.append("(u.email LIKE ? OR k.id LIKE ? OR k.name LIKE ?)"); params += [f"%{search.lower()}%", f"%{search}%", f"%{search}%"]
        if status == "active": where.append("k.revoked_at IS NULL AND k.disabled_at IS NULL")
        elif status == "disabled": where.append("k.revoked_at IS NULL AND k.disabled_at IS NOT NULL")
        elif status == "revoked": where.append("k.revoked_at IS NOT NULL")
        with self._connect() as db:
            total = db.execute(f"SELECT COUNT(*) FROM api_keys k JOIN users u ON u.id=k.user_id WHERE {' AND '.join(where)}", tuple(params)).fetchone()[0]
            rows = db.execute(f"""SELECT k.id,k.name,k.prefix,k.last4,k.created_at,k.last_used_at,k.revoked_at,k.disabled_at,u.id,u.email,s.plan_id
                FROM api_keys k JOIN users u ON u.id=k.user_id LEFT JOIN subscriptions s ON s.user_id=u.id
                WHERE {' AND '.join(where)} ORDER BY k.created_at DESC LIMIT ? OFFSET ?""", tuple(params+[max(1,min(limit,200)),max(0,offset)])).fetchall()
        return {"data":[{"id":r[0],"name":r[1],"prefix":r[2],"last4":r[3],"created_at":r[4],"last_used_at":r[5],"revoked_at":r[6],"disabled_at":r[7],"status":"revoked" if r[6] else ("disabled" if r[7] else "active"),"user":{"id":r[8],"email":r[9],"plan_id":r[10]}} for r in rows],"pagination":{"total":int(total),"offset":offset,"limit":limit}}

    def key_state(self, key_id: str, state: str, admin_id: str, ip: str | None = None) -> None:
        if state not in {"active","disabled","revoked"}:
            raise AuthError("Invalid key state.", "INVALID_KEY_STATE", 422)
        with self._lock, self._connect() as db:
            row = db.execute("SELECT user_id,revoked_at FROM api_keys WHERE id=?", (key_id,)).fetchone()
            if not row: raise AuthError("API key not found.", "API_KEY_NOT_FOUND", 404)
            if row[1] and state != "revoked":
                raise AuthError("A revoked API key cannot be reactivated; create a new key.", "API_KEY_REVOKED", 409)
            now = _now()
            if state == "revoked":
                db.execute("UPDATE api_keys SET revoked_at=COALESCE(revoked_at,?),disabled_at=NULL WHERE id=?", (now,key_id))
            elif state == "disabled":
                db.execute("UPDATE api_keys SET disabled_at=?,revoked_at=NULL WHERE id=?", (now,key_id))
            else:
                db.execute("UPDATE api_keys SET disabled_at=NULL,revoked_at=NULL WHERE id=?", (key_id,))
        self.audit(admin_id, f"api_key.{state}", "api_key", key_id, {"user_id": row[0]}, ip)

    # ---------- plans ----------
    def plans(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows=db.execute("SELECT id,name,monthly_scan_limit,batch_limit,requests_per_second,concurrency,max_active_batches,price_usdt,active,full_results FROM api_plans ORDER BY CASE id WHEN 'developer' THEN 1 WHEN 'pro' THEN 2 ELSE 3 END,id").fetchall()
        return [{"id":r[0],"name":r[1],"monthly_scan_limit":int(r[2]),"batch_limit":int(r[3]),"requests_per_second":int(r[4]),"concurrency":int(r[5]),"max_active_batches":int(r[6]),"price_usdt":float(r[7]),"active":bool(r[8]),"full_results":bool(r[9]) if len(r)>9 else True} for r in rows]

    def update_plan(self, plan_id: str, patch: dict[str, Any], admin_id: str, ip: str | None = None) -> dict[str, Any]:
        allowed={"name","monthly_scan_limit","batch_limit","requests_per_second","concurrency","max_active_batches","price_usdt","active","full_results"}
        patch={k:v for k,v in patch.items() if k in allowed}
        if not patch: raise AuthError("No valid plan fields provided.","NO_FIELDS",422)
        for k in ("monthly_scan_limit","batch_limit","requests_per_second","concurrency","max_active_batches"):
            if k in patch and int(patch[k])<1: raise AuthError(f"{k} must be positive.","INVALID_PLAN_LIMIT",422)
        if "price_usdt" in patch and float(patch["price_usdt"])<0: raise AuthError("Price cannot be negative.","INVALID_PLAN_PRICE",422)
        updates=", ".join(f"{k}=?" for k in patch)+", created_at=created_at"
        params=[patch[k] for k in patch]+[plan_id]
        with self._lock,self._connect() as db:
            cur=db.execute(f"UPDATE api_plans SET {', '.join(f'{k}=?' for k in patch)} WHERE id=?", params)
            if cur.rowcount!=1: raise AuthError("Plan not found.","PLAN_NOT_FOUND",404)
        self.audit(admin_id,"plan.updated","plan",plan_id,patch,ip)
        return next(p for p in self.plans() if p["id"]==plan_id)

    # ---------- coupons ----------
    def list_coupons(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows=db.execute("SELECT id,code,discount_type,discount_value,max_redemptions,used_count,plan_id,starts_at,ends_at,active,created_at,updated_at FROM coupon_codes ORDER BY created_at DESC").fetchall()
        return [{"id":r[0],"code":r[1],"discount_type":r[2],"discount_value":float(r[3]),"max_redemptions":r[4],"used_count":int(r[5]),"plan_id":r[6],"starts_at":r[7],"ends_at":r[8],"active":bool(r[9]),"created_at":r[10],"updated_at":r[11]} for r in rows]

    def create_coupon(self, data: dict[str, Any], admin_id: str, ip: str | None = None) -> dict[str, Any]:
        code="-".join(str(data.get("code","")).strip().upper().split()).replace(" ","")
        typ=str(data.get("discount_type","percent"))
        value=float(data.get("discount_value",0))
        if not code or typ not in {"percent","fixed_usdt"} or value<=0 or (typ=="percent" and value>100): raise AuthError("Invalid coupon.","INVALID_COUPON",422)
        cid=_id("cup"); now=_now()
        try:
            with self._lock,self._connect() as db:
                db.execute("INSERT INTO coupon_codes(id,code,discount_type,discount_value,max_redemptions,plan_id,starts_at,ends_at,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(cid,code,typ,value,data.get("max_redemptions"),data.get("plan_id"),data.get("starts_at"),data.get("ends_at"),1,now,now))
        except sqlite3.IntegrityError as exc: raise AuthError("Coupon code already exists.","COUPON_EXISTS",409) from exc
        self.audit(admin_id,"coupon.created","coupon",cid,{"code":code},ip)
        return next(c for c in self.list_coupons() if c["id"]==cid)

    def toggle_coupon(self,coupon_id:str,active:bool,admin_id:str,ip:str|None=None)->None:
        with self._lock,self._connect() as db:
            if db.execute("UPDATE coupon_codes SET active=?,updated_at=? WHERE id=?",(1 if active else 0,_now(),coupon_id)).rowcount!=1: raise AuthError("Coupon not found.","COUPON_NOT_FOUND",404)
        self.audit(admin_id,"coupon.toggled","coupon",coupon_id,{"active":bool(active)},ip)

    # ---------- grants ----------
    def list_grants(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows=db.execute("SELECT g.id,g.user_id,u.email,g.plan_id,g.reason,g.starts_at,g.ends_at,g.status,g.granted_by,g.created_at,g.updated_at FROM plan_grants g JOIN users u ON u.id=g.user_id ORDER BY g.created_at DESC").fetchall()
        return [{"id":r[0],"user_id":r[1],"email":r[2],"plan_id":r[3],"reason":r[4],"starts_at":r[5],"ends_at":r[6],"status":r[7],"granted_by":r[8],"created_at":r[9],"updated_at":r[10]} for r in rows]

    def create_grant(self,data:dict[str,Any],admin_id:str,ip:str|None=None)->dict[str,Any]:
        user_id=str(data.get("user_id","")).strip(); plan_id=str(data.get("plan_id","")).strip(); reason=str(data.get("reason","")).strip()[:500]
        if not user_id or not plan_id or not reason: raise AuthError("user_id, plan_id and reason are required.","INVALID_GRANT",422)
        if not self.auth.get_user(user_id): raise AuthError("User not found.","USER_NOT_FOUND",404)
        now=_now(); starts=data.get("starts_at") or now
        with self._lock,self._connect() as db:
            if not db.execute("SELECT 1 FROM api_plans WHERE id=?",(plan_id,)).fetchone(): raise AuthError("Plan not found.","PLAN_NOT_FOUND",404)
            prev=db.execute("SELECT id,plan_id,status,ends_at FROM subscriptions WHERE user_id=?",(user_id,)).fetchone()
            gid=_id("grant")
            db.execute("INSERT INTO plan_grants(id,user_id,plan_id,reason,starts_at,ends_at,status,granted_by,created_at,updated_at,previous_plan_id,previous_status,previous_ends_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(gid,user_id,plan_id,reason,starts,data.get("ends_at"),"active",admin_id,now,now,prev[1] if prev else None,prev[2] if prev else None,prev[3] if prev else None))
            if prev:
                db.execute("UPDATE subscriptions SET plan_id=?,status='active',ends_at=?,updated_at=? WHERE user_id=?",(plan_id,data.get("ends_at"),now,user_id))
            else:
                sid=_id("sub"); db.execute("INSERT INTO subscriptions(id,user_id,plan_id,status,starts_at,ends_at,updated_at) VALUES(?,?,?,?,?,?,?)",(sid,user_id,plan_id,"active",starts,data.get("ends_at"),now))
        self.audit(admin_id,"grant.created","grant",gid,{"user_id":user_id,"plan_id":plan_id},ip)
        return next(g for g in self.list_grants() if g["id"]==gid)

    def revoke_grant(self,grant_id:str,admin_id:str,ip:str|None=None)->None:
        with self._lock,self._connect() as db:
            row=db.execute("SELECT user_id,previous_plan_id,previous_status,previous_ends_at,status FROM plan_grants WHERE id=?",(grant_id,)).fetchone()
            if not row: raise AuthError("Grant not found.","GRANT_NOT_FOUND",404)
            if row[4] == "revoked": return
            db.execute("UPDATE plan_grants SET status='revoked',updated_at=? WHERE id=?",(_now(),grant_id))
            if row[1] is not None:
                db.execute("UPDATE subscriptions SET plan_id=?,status=?,ends_at=?,updated_at=? WHERE user_id=?",(row[1],row[2] or "active",row[3],_now(),row[0]))
            else:
                db.execute("DELETE FROM subscriptions WHERE user_id=?",(row[0],))
        self.audit(admin_id,"grant.revoked","grant",grant_id,{},ip)

    # ---------- crypto billing administration ----------
    @staticmethod
    def _billing_amount(units: int) -> str:
        scale = 10 ** USDT_DECIMALS
        return f"{int(units) / scale:.{USDT_DECIMALS}f}"

    def _billing_env(self) -> dict[str, Any]:
        enabled = os.getenv("SMARTRISK_BILLING_ENABLED", "false").lower() in {"1", "true", "yes", "on"}
        receiver = (os.getenv("SMARTRISK_PAYMENT_RECEIVER") or "").strip().lower()
        token = (os.getenv("SMARTRISK_PAYMENT_USDT_CONTRACT") or USDT_ETHEREUM_CONTRACT).strip().lower()
        rpc_names = (
            "SMARTRISK_PAYMENT_RPC_URL", "ALCHEMY_API_KEY", "ALCHEMY_RPC_URL",
            "SMARTRISK_ETHEREUM_RPC_URL", "QUICKNODE_RPC_URL", "CHAINSTACK_RPC_URL",
            "SMARTRISK_ETHEREUM_QUICKNODE_RPC_URL", "SMARTRISK_ETHEREUM_CHAINSTACK_RPC_URL",
        )
        rpc_configured = any(os.getenv(name) for name in rpc_names)
        address_valid = bool(ADDRESS_RE.fullmatch(receiver))
        configured = enabled and address_valid and token == USDT_ETHEREUM_CONTRACT and rpc_configured
        return {
            "enabled": enabled, "configured": configured, "rpc_configured": rpc_configured,
            "chain_id": ETHEREUM_CHAIN_ID, "network": "Ethereum Mainnet", "token": "USDT",
            "token_contract": token, "receiver_address": receiver, "receiver_valid": address_valid,
            "invoice_ttl_minutes": int(os.getenv("SMARTRISK_PAYMENT_INVOICE_TTL_MINUTES", "30")),
            "poll_seconds": int(os.getenv("SMARTRISK_PAYMENT_POLL_SECONDS", "15")),
            "scan_lookback_blocks": int(os.getenv("SMARTRISK_PAYMENT_SCAN_LOOKBACK_BLOCKS", "50")),
        }

    def billing_overview(self) -> dict[str, Any]:
        env = self._billing_env()
        with self._connect() as db:
            invoice_counts = {r[0]: int(r[1]) for r in db.execute("SELECT status,COUNT(*) FROM payment_invoices GROUP BY status").fetchall()}
            event_counts = {r[0]: int(r[1]) for r in db.execute("SELECT status,COUNT(*) FROM payment_events GROUP BY status").fetchall()}
            unmatched = int(db.execute("SELECT COUNT(*) FROM payment_events WHERE invoice_id IS NULL").fetchone()[0])
            rejected = int(db.execute("SELECT COUNT(*) FROM payment_events WHERE status='rejected'").fetchone()[0])
            settled_amount_units = int(db.execute("SELECT COALESCE(SUM(pe.amount_units),0) FROM payment_events pe JOIN payment_settlements ps ON ps.payment_event_id=pe.id").fetchone()[0] or 0)
            invoices_total = int(db.execute("SELECT COUNT(*) FROM payment_invoices").fetchone()[0])
            latest_invoice_at = db.execute("SELECT created_at FROM payment_invoices ORDER BY created_at DESC LIMIT 1").fetchone()
            scanner = db.execute("SELECT next_block,updated_at FROM payment_scanner_state WHERE id='ethereum-usdt'").fetchone()
        return {
            **env, "invoice_counts": invoice_counts, "event_counts": event_counts,
            "invoices_total": invoices_total, "awaiting_payment": invoice_counts.get("awaiting_payment", 0),
            "payment_detected": invoice_counts.get("payment_detected", 0), "confirming": invoice_counts.get("confirming", 0),
            "paid": invoice_counts.get("paid", 0), "expired": invoice_counts.get("expired", 0),
            "unmatched_events": unmatched, "rejected_events": rejected,
            "settled_revenue_usdt": self._billing_amount(settled_amount_units),
            "scanner_next_block": int(scanner[0]) if scanner else None,
            "scanner_updated_at": scanner[1] if scanner else None,
            "latest_invoice_at": latest_invoice_at[0] if latest_invoice_at else None,
        }

    def list_billing_invoices(self, status: str | None = None, search: str = "", limit: int = 100, offset: int = 0) -> dict[str, Any]:
        allowed = {"awaiting_payment","payment_detected","confirming","paid","expired","underpaid","overpaid","rejected","canceled"}
        status = status if status in allowed else None
        limit=max(1,min(int(limit),200)); offset=max(0,int(offset)); search=(search or "").strip().lower()
        where=["1=1"]; params:list[Any]=[]
        if status: where.append("i.status=?"); params.append(status)
        if search:
            where.append("(LOWER(i.id) LIKE ? OR LOWER(u.email) LIKE ? OR LOWER(i.receiver_address) LIKE ? OR LOWER(COALESCE(pe.tx_hash,'')) LIKE ? OR LOWER(i.plan_id) LIKE ?)")
            like=f"%{search}%"; params += [like,like,like,like,like]
        cond=" AND ".join(where)
        with self._connect() as db:
            total=db.execute(f"""SELECT COUNT(*) FROM payment_invoices i JOIN users u ON u.id=i.user_id
                                     LEFT JOIN payment_events pe ON pe.id=(SELECT id FROM payment_events WHERE invoice_id=i.id ORDER BY created_at DESC LIMIT 1)
                                     WHERE {cond}""",tuple(params)).fetchone()[0]
            rows=db.execute(f"""SELECT i.id,i.user_id,u.email,i.plan_id,COALESCE(ap.name,i.plan_id),i.base_price_units,i.payment_amount_units,
                                      i.currency,i.chain_id,i.token_contract,i.receiver_address,i.expected_payer_address,i.status,i.expires_at,i.paid_at,
                                      i.settlement_id,i.created_at,i.updated_at,pe.id,pe.tx_hash,pe.block_number,pe.confirmations,pe.status,pe.from_address,
                                      ps.subscription_id,ps.settled_at
                               FROM payment_invoices i JOIN users u ON u.id=i.user_id LEFT JOIN api_plans ap ON ap.id=i.plan_id
                               LEFT JOIN payment_events pe ON pe.id=(SELECT id FROM payment_events WHERE invoice_id=i.id ORDER BY created_at DESC LIMIT 1)
                               LEFT JOIN payment_settlements ps ON ps.invoice_id=i.id WHERE {cond}
                               ORDER BY i.created_at DESC LIMIT ? OFFSET ?""",tuple(params+[limit,offset])).fetchall()
        data=[]
        for r in rows:
            data.append({"id":r[0],"user_id":r[1],"email":r[2],"plan_id":r[3],"plan_name":r[4],
                         "base_price_usdt":self._billing_amount(r[5]),"payment_amount_usdt":self._billing_amount(r[6]),"currency":r[7],
                         "chain_id":r[8],"token_contract":r[9],"receiver_address":r[10],"expected_payer_address":r[11],"status":r[12],
                         "expires_at":r[13],"paid_at":r[14],"settlement_id":r[15],"created_at":r[16],"updated_at":r[17],
                         "payment_event":({"id":r[18],"tx_hash":r[19],"block_number":r[20],"confirmations":r[21],"status":r[22],"from_address":r[23]} if r[18] else None),
                         "subscription_id":r[24],"settled_at":r[25]})
        return {"data":data,"pagination":{"total":int(total),"offset":offset,"limit":limit}}

    def billing_invoice_detail(self, invoice_id: str) -> dict[str, Any]:
        with self._connect() as db:
            row=db.execute("""SELECT i.id,i.user_id,u.email,i.plan_id,COALESCE(ap.name,i.plan_id),i.base_price_units,i.payment_amount_units,
                                      i.currency,i.chain_id,i.token_contract,i.receiver_address,i.expected_payer_address,i.status,i.expires_at,i.paid_at,i.settlement_id,i.created_at,i.updated_at
                               FROM payment_invoices i JOIN users u ON u.id=i.user_id LEFT JOIN api_plans ap ON ap.id=i.plan_id WHERE i.id=?""",(invoice_id,)).fetchone()
            if not row: raise AuthError("Payment invoice not found.","INVOICE_NOT_FOUND",404)
            events=db.execute("""SELECT id,invoice_id,chain_id,tx_hash,log_index,block_number,block_hash,token_contract,from_address,to_address,amount_units,receipt_status,confirmations,status,rejection_code,first_seen_at,confirmed_at,reorged_at,created_at,updated_at
                                FROM payment_events WHERE invoice_id=? ORDER BY created_at DESC""",(invoice_id,)).fetchall()
            settlement=db.execute("""SELECT ps.id,ps.payment_event_id,ps.subscription_id,ps.settled_at,s.plan_id,s.status,s.ends_at
                                    FROM payment_settlements ps LEFT JOIN subscriptions s ON s.id=ps.subscription_id WHERE ps.invoice_id=?""",(invoice_id,)).fetchone()
        invoice={"id":row[0],"user_id":row[1],"email":row[2],"plan_id":row[3],"plan_name":row[4],"base_price_usdt":self._billing_amount(row[5]),"payment_amount_usdt":self._billing_amount(row[6]),
                 "currency":row[7],"chain_id":row[8],"token_contract":row[9],"receiver_address":row[10],"expected_payer_address":row[11],"status":row[12],"expires_at":row[13],"paid_at":row[14],"settlement_id":row[15],"created_at":row[16],"updated_at":row[17]}
        return {"invoice":invoice,"events":[{"id":e[0],"invoice_id":e[1],"chain_id":e[2],"tx_hash":e[3],"log_index":e[4],"block_number":e[5],"block_hash":e[6],"token_contract":e[7],"from_address":e[8],"to_address":e[9],"amount_usdt":self._billing_amount(e[10]),"receipt_status":e[11],"confirmations":e[12],"status":e[13],"rejection_code":e[14],"first_seen_at":e[15],"confirmed_at":e[16],"reorged_at":e[17],"created_at":e[18],"updated_at":e[19]} for e in events],"settlement":({"id":settlement[0],"payment_event_id":settlement[1],"subscription_id":settlement[2],"settled_at":settlement[3],"plan_id":settlement[4],"status":settlement[5],"ends_at":settlement[6]} if settlement else None)}

    def list_billing_events(self, status: str | None = None, search: str = "", limit: int = 100, offset: int = 0, unmatched_only: bool = False) -> dict[str, Any]:
        limit=max(1,min(int(limit),200)); offset=max(0,int(offset)); search=(search or "").strip().lower()
        where=["1=1"]; params:list[Any]=[]
        if status: where.append("pe.status=?"); params.append(status)
        if unmatched_only: where.append("pe.invoice_id IS NULL")
        if search:
            where.append("(LOWER(pe.tx_hash) LIKE ? OR LOWER(pe.from_address) LIKE ? OR LOWER(pe.to_address) LIKE ? OR LOWER(COALESCE(pe.invoice_id,'')) LIKE ? OR LOWER(COALESCE(u.email,'')) LIKE ?)")
            like=f"%{search}%"; params += [like,like,like,like,like]
        cond=" AND ".join(where)
        with self._connect() as db:
            total=db.execute(f"SELECT COUNT(*) FROM payment_events pe LEFT JOIN payment_invoices i ON i.id=pe.invoice_id LEFT JOIN users u ON u.id=i.user_id WHERE {cond}",tuple(params)).fetchone()[0]
            rows=db.execute(f"""SELECT pe.id,pe.invoice_id,u.email,pe.chain_id,pe.tx_hash,pe.log_index,pe.block_number,pe.block_hash,pe.token_contract,pe.from_address,pe.to_address,pe.amount_units,pe.receipt_status,pe.confirmations,pe.status,pe.rejection_code,pe.first_seen_at,pe.confirmed_at,pe.reorged_at,pe.created_at,pe.updated_at,i.plan_id
                               FROM payment_events pe LEFT JOIN payment_invoices i ON i.id=pe.invoice_id LEFT JOIN users u ON u.id=i.user_id
                               WHERE {cond} ORDER BY pe.created_at DESC LIMIT ? OFFSET ?""",tuple(params+[limit,offset])).fetchall()
        return {"data":[{"id":r[0],"invoice_id":r[1],"email":r[2],"chain_id":r[3],"tx_hash":r[4],"log_index":r[5],"block_number":r[6],"block_hash":r[7],"token_contract":r[8],"from_address":r[9],"to_address":r[10],"amount_usdt":self._billing_amount(r[11]),"receipt_status":r[12],"confirmations":r[13],"status":r[14],"rejection_code":r[15],"first_seen_at":r[16],"confirmed_at":r[17],"reorged_at":r[18],"created_at":r[19],"updated_at":r[20],"plan_id":r[21]} for r in rows],"pagination":{"total":int(total),"offset":offset,"limit":limit}}

    def reconcile_billing(self, admin_id: str, ip: str | None = None) -> dict[str, Any]:
        expired=self.billing.mark_expired()
        result=self.billing_overview()
        self.audit(admin_id,"billing.reconciled","billing",None,{"expired_invoices":expired,"confirming":result["confirming"],"unmatched_events":result["unmatched_events"]},ip)
        result["expired_invoices"]=expired
        return result

    # ---------- payments / subscriptions ----------
    def list_payments(self,status:str|None=None,limit:int=100,offset:int=0)->dict[str,Any]:
        where=["1=1"];params=[]
        if status: where.append("p.status=?");params.append(status)
        with self._connect() as db:
            total=db.execute(f"SELECT COUNT(*) FROM payment_transactions p WHERE {' AND '.join(where)}",tuple(params)).fetchone()[0]
            rows=db.execute(f"SELECT p.id,p.user_id,u.email,p.subscription_id,p.plan_id,p.amount_usdt,p.network,p.tx_hash,p.status,p.invoice_ref,p.paid_at,p.created_at,p.updated_at FROM payment_transactions p JOIN users u ON u.id=p.user_id WHERE {' AND '.join(where)} ORDER BY p.created_at DESC LIMIT ? OFFSET ?",tuple(params+[max(1,min(limit,200)),max(0,offset)])).fetchall()
        return {"data":[{"id":r[0],"user_id":r[1],"email":r[2],"subscription_id":r[3],"plan_id":r[4],"amount_usdt":float(r[5]),"network":r[6],"tx_hash":r[7],"status":r[8],"invoice_ref":r[9],"paid_at":r[10],"created_at":r[11],"updated_at":r[12]} for r in rows],"pagination":{"total":int(total),"offset":offset,"limit":limit}}

    def create_payment(self,data:dict[str,Any],admin_id:str,ip:str|None=None)->dict[str,Any]:
        user_id=str(data.get("user_id","")).strip(); amount=float(data.get("amount_usdt",0));
        if not user_id or amount<=0 or not self.auth.get_user(user_id): raise AuthError("Invalid payment.","INVALID_PAYMENT",422)
        pid=_id("pay");now=_now()
        with self._lock,self._connect() as db:
            db.execute("INSERT INTO payment_transactions(id,user_id,subscription_id,plan_id,amount_usdt,currency,network,tx_hash,status,invoice_ref,metadata_json,paid_at,verified_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(pid,user_id,data.get("subscription_id"),data.get("plan_id"),amount,"USDT",data.get("network"),data.get("tx_hash"),data.get("status","pending"),data.get("invoice_ref"),json.dumps(data.get("metadata") or {}),data.get("paid_at"),admin_id if data.get("status")=="confirmed" else None,now,now))
        self.audit(admin_id,"payment.created","payment",pid,{"user_id":user_id,"amount_usdt":amount},ip)
        return next(x for x in self.list_payments()["data"] if x["id"]==pid)

    def set_payment_status(self,payment_id:str,status:str,admin_id:str,ip:str|None=None)->dict[str,Any]:
        if status not in {"pending","confirmed","failed","refunded"}: raise AuthError("Invalid payment status.","INVALID_PAYMENT_STATUS",422)
        now=_now()
        with self._lock,self._connect() as db:
            row=db.execute("SELECT id,user_id,status FROM payment_transactions WHERE id=?",(payment_id,)).fetchone()
            if not row: raise AuthError("Payment not found.","PAYMENT_NOT_FOUND",404)
            if row[2] == "confirmed" and status == "confirmed":
                return next(x for x in self.list_payments()["data"] if x["id"]==payment_id)
            payment_row = db.execute("SELECT user_id,plan_id,subscription_id FROM payment_transactions WHERE id=?", (payment_id,)).fetchone()
            db.execute("UPDATE payment_transactions SET status=?,paid_at=?,verified_by=?,updated_at=? WHERE id=?",(status,now if status=="confirmed" else None,admin_id if status=="confirmed" else None,now,payment_id))
            if status == "confirmed" and payment_row and payment_row[1]:
                plan_id = payment_row[1]
                if not db.execute("SELECT 1 FROM api_plans WHERE id=? AND active=1", (plan_id,)).fetchone():
                    raise AuthError("The payment plan is not active.", "PLAN_INACTIVE", 409)
                existing = db.execute("SELECT id,ends_at FROM subscriptions WHERE user_id=?", (payment_row[0],)).fetchone()
                from datetime import timedelta
                try:
                    existing_end = datetime.fromisoformat(existing[1]) if existing and existing[1] else None
                except ValueError:
                    existing_end = None
                base = existing_end if existing_end and existing_end > datetime.now(timezone.utc) else datetime.now(timezone.utc)
                new_end = (base + timedelta(days=30)).isoformat()
                if existing:
                    db.execute("UPDATE subscriptions SET plan_id=?,status='active',ends_at=?,updated_at=? WHERE user_id=?", (plan_id,new_end,now,payment_row[0]))
                else:
                    db.execute("INSERT INTO subscriptions(id,user_id,plan_id,status,starts_at,ends_at,updated_at) VALUES(?,?,?,?,?,?,?)", (_id('sub'),payment_row[0],plan_id,'active',now,new_end,now))
        self.audit(admin_id,"payment.status_changed","payment",payment_id,{"status":status},ip)
        return next(x for x in self.list_payments()["data"] if x["id"]==payment_id)

    # ---------- embed partner applications ----------
    @staticmethod
    def _embed_month_key() -> str:
        return datetime.now(timezone.utc).strftime('%Y-%m')

    @staticmethod
    def _embed_public_key() -> str:
        import secrets
        return 'srw_pub_' + secrets.token_urlsafe(18)

    def list_embed_apps(self) -> list[dict[str, Any]]:
        month = self._embed_month_key()
        with self._connect() as db:
            rows = db.execute(
                """SELECT a.id,a.public_key,a.name,a.allowed_origins_json,a.monthly_quota,a.rate_limit_per_minute,
                          a.active,a.created_at,a.updated_at,
                          COALESCE(u.scans_submitted,0),COALESCE(u.scans_completed,0),COALESCE(u.scans_failed,0)
                   FROM embed_apps a LEFT JOIN embed_usage_monthly u ON u.app_id=a.id AND u.month_key=?
                   ORDER BY a.created_at DESC""", (month,)
            ).fetchall()
        return [
            {
                'id': r[0], 'public_key': r[1], 'name': r[2],
                'allowed_origins': json.loads(r[3] or '[]'),
                'monthly_quota': int(r[4]), 'rate_limit_per_minute': int(r[5]),
                'active': bool(r[6]), 'created_at': r[7], 'updated_at': r[8],
                'usage': {'submitted': int(r[9]), 'completed': int(r[10]), 'failed': int(r[11]),
                          'remaining': max(0, int(r[4]) - int(r[9])) if int(r[4]) >= 0 else None}
            }
            for r in rows
        ]

    def get_embed_app(self, app_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT id,public_key,name,allowed_origins_json,monthly_quota,rate_limit_per_minute,active,created_by,created_at,updated_at FROM embed_apps WHERE id=?",
                (app_id,),
            ).fetchone()
        if not row:
            return None
        return {
            'id': row[0], 'public_key': row[1], 'name': row[2], 'allowed_origins': json.loads(row[3] or '[]'),
            'monthly_quota': int(row[4]), 'rate_limit_per_minute': int(row[5]), 'active': bool(row[6]),
            'created_by': row[7], 'created_at': row[8], 'updated_at': row[9],
        }

    def get_embed_app_by_public_key(self, public_key: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT id,public_key,name,allowed_origins_json,monthly_quota,rate_limit_per_minute,active,created_by,created_at,updated_at FROM embed_apps WHERE public_key=?",
                (str(public_key).strip(),),
            ).fetchone()
        if not row:
            return None
        return {
            'id': row[0], 'public_key': row[1], 'name': row[2], 'allowed_origins': json.loads(row[3] or '[]'),
            'monthly_quota': int(row[4]), 'rate_limit_per_minute': int(row[5]), 'active': bool(row[6]),
            'created_by': row[7], 'created_at': row[8], 'updated_at': row[9],
        }

    def create_embed_app(self, data: dict[str, Any], admin_id: str, ip: str | None = None) -> dict[str, Any]:
        name = str(data.get('name', '')).strip()[:120]
        if not name:
            raise AuthError('Embed application name is required.', 'INVALID_EMBED_APP', 422)
        origins = validate_origins(data.get('allowed_origins'))
        quota = int(data.get('monthly_quota', 1000))
        rate = int(data.get('rate_limit_per_minute', 30))
        if quota < -1 or quota > 10_000_000:
            raise AuthError('Monthly quota must be -1 (unlimited) or between 0 and 10,000,000.', 'INVALID_EMBED_QUOTA', 422)
        if rate < 1 or rate > 10_000:
            raise AuthError('Rate limit must be between 1 and 10,000 requests per minute.', 'INVALID_EMBED_RATE_LIMIT', 422)
        now = _now(); aid = _id('embed_app'); public_key = self._embed_public_key()
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT INTO embed_apps(id,public_key,name,allowed_origins_json,monthly_quota,rate_limit_per_minute,active,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (aid, public_key, name, json.dumps(origins), quota, rate, 1 if data.get('active', True) else 0, admin_id, now, now),
            )
        self.audit(admin_id, 'embed_app.created', 'embed_app', aid, {'name': name, 'allowed_origins': origins, 'monthly_quota': quota, 'rate_limit_per_minute': rate}, ip)
        return self.get_embed_app(aid) or {}

    def update_embed_app(self, app_id: str, data: dict[str, Any], admin_id: str, ip: str | None = None) -> dict[str, Any]:
        current = self.get_embed_app(app_id)
        if not current:
            raise AuthError('Embed application not found.', 'EMBED_APP_NOT_FOUND', 404)
        name = str(data.get('name', current['name'])).strip()[:120]
        if not name:
            raise AuthError('Embed application name is required.', 'INVALID_EMBED_APP', 422)
        origins = validate_origins(data.get('allowed_origins', current['allowed_origins']))
        quota = int(data.get('monthly_quota', current['monthly_quota']))
        rate = int(data.get('rate_limit_per_minute', current['rate_limit_per_minute']))
        if quota < -1 or quota > 10_000_000:
            raise AuthError('Monthly quota must be -1 (unlimited) or between 0 and 10,000,000.', 'INVALID_EMBED_QUOTA', 422)
        if rate < 1 or rate > 10_000:
            raise AuthError('Rate limit must be between 1 and 10,000 requests per minute.', 'INVALID_EMBED_RATE_LIMIT', 422)
        now = _now()
        with self._lock, self._connect() as db:
            db.execute(
                "UPDATE embed_apps SET name=?,allowed_origins_json=?,monthly_quota=?,rate_limit_per_minute=?,active=?,updated_at=? WHERE id=?",
                (name, json.dumps(origins), quota, rate, 1 if data.get('active', current['active']) else 0, now, app_id),
            )
        self.audit(admin_id, 'embed_app.updated', 'embed_app', app_id, {'name': name, 'allowed_origins': origins, 'monthly_quota': quota, 'rate_limit_per_minute': rate, 'active': bool(data.get('active', current['active']))}, ip)
        return self.get_embed_app(app_id) or {}

    def toggle_embed_app(self, app_id: str, active: bool, admin_id: str, ip: str | None = None) -> None:
        with self._lock, self._connect() as db:
            if db.execute("UPDATE embed_apps SET active=?,updated_at=? WHERE id=?", (1 if active else 0, _now(), app_id)).rowcount != 1:
                raise AuthError('Embed application not found.', 'EMBED_APP_NOT_FOUND', 404)
        self.audit(admin_id, 'embed_app.toggled', 'embed_app', app_id, {'active': bool(active)}, ip)

    def rotate_embed_app_key(self, app_id: str, admin_id: str, ip: str | None = None) -> dict[str, Any]:
        current = self.get_embed_app(app_id)
        if not current:
            raise AuthError('Embed application not found.', 'EMBED_APP_NOT_FOUND', 404)
        new_key = self._embed_public_key(); now = _now()
        with self._lock, self._connect() as db:
            db.execute('UPDATE embed_apps SET public_key=?,updated_at=? WHERE id=?', (new_key, now, app_id))
        self.audit(admin_id, 'embed_app.key_rotated', 'embed_app', app_id, {'previous_prefix': current['public_key'][:12], 'new_prefix': new_key[:12]}, ip)
        return self.get_embed_app(app_id) or {}

    def reserve_embed_scan(self, app_id: str) -> None:
        month = self._embed_month_key(); now = _now()
        with self._lock, self._connect() as db:
            row = db.execute('SELECT monthly_quota,active FROM embed_apps WHERE id=?', (app_id,)).fetchone()
            if not row or not row[1]:
                raise AuthError('Embed application is unavailable.', 'EMBED_APP_DISABLED', 403)
            quota = int(row[0]); used = db.execute('SELECT scans_submitted FROM embed_usage_monthly WHERE app_id=? AND month_key=?', (app_id, month)).fetchone()
            used_count = int(used[0]) if used else 0
            if quota >= 0 and used_count >= quota:
                raise AuthError('Embed monthly quota reached.', 'EMBED_QUOTA_EXCEEDED', 429)
            db.execute(
                "INSERT INTO embed_usage_monthly(app_id,month_key,scans_submitted,scans_completed,scans_failed,last_scan_at) VALUES(?,?,?,?,?,?) ON CONFLICT(app_id,month_key) DO UPDATE SET scans_submitted=scans_submitted+1,last_scan_at=excluded.last_scan_at",
                (app_id, month, 1, 0, 0, now),
            )

    def release_reserved_embed_scan(self, app_id: str) -> None:
        month = self._embed_month_key()
        with self._lock, self._connect() as db:
            db.execute('UPDATE embed_usage_monthly SET scans_submitted=MAX(0,scans_submitted-1),last_scan_at=NULL WHERE app_id=? AND month_key=?', (app_id, month))

    def bind_embed_job(self, job_id: str, app_id: str | None, origin: str | None) -> None:
        with self._lock, self._connect() as db:
            db.execute('INSERT INTO embed_scan_map(job_id,app_id,origin,created_at) VALUES(?,?,?,?)', (job_id, app_id, origin, _now()))

    def embed_job_context(self, job_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute('SELECT job_id,app_id,origin,created_at FROM embed_scan_map WHERE job_id=?', (job_id,)).fetchone()
        if not row:
            return None
        return {'job_id': row[0], 'app_id': row[1], 'origin': row[2], 'created_at': row[3]}

    def record_embed_event(self, job_id: str, event_type: str, app_id: str | None, origin: str | None, client_ip: str | None, user_agent: str | None) -> None:
        now = _now(); month = self._embed_month_key()
        with self._lock, self._connect() as db:
            cur = db.execute(
                'INSERT OR IGNORE INTO embed_events(id,app_id,job_id,event_type,origin,client_ip,user_agent,created_at) VALUES(?,?,?,?,?,?,?,?)',
                (_id('embed_evt'), app_id, job_id, event_type, origin, client_ip, user_agent, now),
            )
            if cur.rowcount != 1 or not app_id:
                return
            if event_type == 'scan_completed':
                db.execute('INSERT INTO embed_usage_monthly(app_id,month_key,scans_submitted,scans_completed,scans_failed,last_scan_at) VALUES(?,?,?,?,?,?) ON CONFLICT(app_id,month_key) DO UPDATE SET scans_completed=scans_completed+1,last_scan_at=excluded.last_scan_at', (app_id, month, 0, 1, 0, now))
            elif event_type == 'scan_failed':
                db.execute('INSERT INTO embed_usage_monthly(app_id,month_key,scans_submitted,scans_completed,scans_failed,last_scan_at) VALUES(?,?,?,?,?,?) ON CONFLICT(app_id,month_key) DO UPDATE SET scans_failed=scans_failed+1,last_scan_at=excluded.last_scan_at', (app_id, month, 0, 0, 1, now))

    def embed_analytics(self, app_id: str | None = None, days: int = 30) -> dict[str, Any]:
        days = max(1, min(int(days), 90)); params: list[Any] = []
        where = ['event_type IN (\'scan_submitted\',\'scan_completed\',\'scan_failed\')', "created_at >= datetime('now',?)"]
        params.append(f'-{days-1} days')
        if app_id:
            where.append('app_id=?'); params.append(app_id)
        where_sql = ' AND '.join(where)
        with self._connect() as db:
            daily = db.execute(
                f"SELECT substr(created_at,1,10) day, SUM(CASE WHEN event_type='scan_submitted' THEN 1 ELSE 0 END), SUM(CASE WHEN event_type='scan_completed' THEN 1 ELSE 0 END), SUM(CASE WHEN event_type='scan_failed' THEN 1 ELSE 0 END) FROM embed_events WHERE {where_sql} GROUP BY day ORDER BY day",
                tuple(params),
            ).fetchall()
            origins = db.execute(
                f"SELECT COALESCE(origin,'public') origin, COUNT(*) total FROM embed_events WHERE {where_sql} AND event_type='scan_submitted' GROUP BY origin ORDER BY total DESC LIMIT 20",
                tuple(params),
            ).fetchall()
        return {
            'period_days': days,
            'daily': [{'date': r[0], 'submitted': int(r[1]), 'completed': int(r[2]), 'failed': int(r[3])} for r in daily],
            'origins': [{'origin': r[0], 'submitted': int(r[1])} for r in origins],
        }

    # ---------- ads / settings ----------
    def list_ads(self)->list[dict[str,Any]]:
        with self._connect() as db:
            rows=db.execute("SELECT id,title,body,cta_label,cta_url,placement,audience,priority,starts_at,ends_at,active,created_at,updated_at FROM site_ads ORDER BY priority DESC,created_at DESC").fetchall()
        return [{"id":r[0],"title":r[1],"body":r[2],"cta_label":r[3],"cta_url":r[4],"placement":r[5],"audience":r[6],"priority":int(r[7]),"starts_at":r[8],"ends_at":r[9],"active":bool(r[10]),"created_at":r[11],"updated_at":r[12]} for r in rows]

    def create_ad(self,data:dict[str,Any],admin_id:str,ip:str|None=None)->dict[str,Any]:
        title=str(data.get("title","")).strip()[:120]; body=str(data.get("body","")).strip()[:1000]
        if not title or not body: raise AuthError("Title and body are required.","INVALID_AD",422)
        aid=_id("ad");now=_now()
        with self._lock,self._connect() as db:
            db.execute("INSERT INTO site_ads(id,title,body,cta_label,cta_url,placement,audience,priority,starts_at,ends_at,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(aid,title,body,data.get("cta_label"),data.get("cta_url"),data.get("placement","banner"),data.get("audience","all"),int(data.get("priority",0)),data.get("starts_at"),data.get("ends_at"),1,now,now))
        self.audit(admin_id,"ad.created","ad",aid,{"title":title},ip)
        return next(x for x in self.list_ads() if x["id"]==aid)

    def toggle_ad(self,ad_id:str,active:bool,admin_id:str,ip:str|None=None)->None:
        with self._lock,self._connect() as db:
            if db.execute("UPDATE site_ads SET active=?,updated_at=? WHERE id=?",(1 if active else 0,_now(),ad_id)).rowcount!=1: raise AuthError("Ad not found.","AD_NOT_FOUND",404)
        self.audit(admin_id,"ad.toggled","ad",ad_id,{"active":bool(active)},ip)

    def setting_value(self, key: str, default: Any = None) -> Any:
        with self._connect() as db:
            row = db.execute("SELECT value,value_type FROM platform_settings WHERE key=?", (key,)).fetchone()
        if not row:
            return default
        value, typ = row
        if typ == "bool":
            return str(value).lower() == "true"
        if typ == "int":
            try:
                return int(value)
            except (TypeError, ValueError):
                return default
        return value

    def settings(self)->list[dict[str,Any]]:
        with self._connect() as db:
            rows=db.execute("SELECT key,value,value_type,description,updated_at,updated_by FROM platform_settings ORDER BY key").fetchall()
        return [{"key":r[0],"value":r[1],"value_type":r[2],"description":r[3],"updated_at":r[4],"updated_by":r[5]} for r in rows]

    def update_setting(self,key:str,value:Any,admin_id:str,ip:str|None=None)->dict[str,Any]:
        with self._lock,self._connect() as db:
            row=db.execute("SELECT value_type FROM platform_settings WHERE key=?",(key,)).fetchone()
            if not row: raise AuthError("Setting not found.","SETTING_NOT_FOUND",404)
            typ=row[0]
            if typ=="bool": normalized="true" if bool(value) else "false"
            elif typ=="int": normalized=str(int(value))
            else: normalized=str(value)
            db.execute("UPDATE platform_settings SET value=?,updated_at=?,updated_by=? WHERE key=?",(normalized,_now(),admin_id,key))
        self.audit(admin_id,"setting.updated","setting",key,{"value":normalized},ip)
        return next(x for x in self.settings() if x["key"]==key)

    # ---------- audit ----------
    def audit(self,admin_user_id:str,action:str,target_type:str|None,target_id:str|None,details:dict[str,Any],ip:str|None=None)->None:
        with self._lock,self._connect() as db:
            db.execute("INSERT INTO admin_audit_log(id,admin_user_id,action,target_type,target_id,details_json,ip_address,created_at) VALUES(?,?,?,?,?,?,?,?)",(_id("audit"),admin_user_id,action,target_type,target_id,json.dumps(details,sort_keys=True,default=str),ip,_now()))

    def audit_log(self,limit:int=100,offset:int=0)->dict[str,Any]:
        with self._connect() as db:
            total=db.execute("SELECT COUNT(*) FROM admin_audit_log").fetchone()[0]
            rows=db.execute("SELECT a.id,a.action,a.target_type,a.target_id,a.details_json,a.ip_address,a.created_at,u.email FROM admin_audit_log a LEFT JOIN users u ON u.id=a.admin_user_id ORDER BY a.created_at DESC LIMIT ? OFFSET ?",(max(1,min(limit,200)),max(0,offset))).fetchall()
        return {"data":[{"id":r[0],"action":r[1],"target_type":r[2],"target_id":r[3],"details":json.loads(r[4] or "{}"),"ip_address":r[5],"created_at":r[6],"admin_email":r[7]} for r in rows],"pagination":{"total":int(total),"offset":offset,"limit":limit}}


class AdminService:
    def __init__(self, path: str | Path = "artifacts/jobs.sqlite3"):
        self.store = AdminStore(path)

    def require_admin(self, user: User) -> User:
        if user.role != "admin" or user.status != "active" or not user.email_verified:
            raise AuthError("Administrator access required.", "ADMIN_REQUIRED", 403)
        return user

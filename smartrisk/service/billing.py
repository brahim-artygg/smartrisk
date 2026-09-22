from __future__ import annotations

import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_DOWN
from pathlib import Path
from typing import Any, Callable

from ..state_fork.alchemy_rpc import AlchemyRpcClient
from .auth import AuthError

ETHEREUM_CHAIN_ID = "1"
USDT_ETHEREUM_CONTRACT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
USDT_DECIMALS = 6
TX_HASH_RE = re.compile(r"^0x[a-fA-F0-9]{64}$")
ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

OPEN_INVOICE_STATUSES = ("awaiting_payment", "payment_detected", "confirming")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _lower_address(value: str | None) -> str | None:
    if value is None:
        return None
    value = str(value).strip().lower()
    if not ADDRESS_RE.fullmatch(value):
        raise AuthError("Enter a valid Ethereum address.", "INVALID_PAYMENT_ADDRESS", 422)
    return value


def _validate_tx_hash(value: str) -> str:
    value = str(value or "").strip()
    if not TX_HASH_RE.fullmatch(value):
        raise AuthError("Enter a valid Ethereum transaction hash.", "INVALID_TX_HASH", 422)
    return value.lower()


def _money_to_units(value: Any) -> int:
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise AuthError("Invalid USDT price.", "INVALID_PAYMENT_PRICE", 500) from exc
    units = (amount * Decimal(10**USDT_DECIMALS)).quantize(Decimal("1"), rounding=ROUND_DOWN)
    if amount <= 0 or units != amount * Decimal(10**USDT_DECIMALS):
        raise AuthError("USDT price must be positive and fit 6 decimals.", "INVALID_PAYMENT_PRICE", 500)
    return int(units)


def _units_to_decimal(units: int) -> str:
    return f"{Decimal(int(units)) / Decimal(10**USDT_DECIMALS):.{USDT_DECIMALS}f}"


def _hex_int(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    text = str(value)
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def _topic_address(address: str) -> str:
    return "0x" + (address.lower()[2:]).rjust(64, "0")


def _bool_env(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default).lower()).lower() in {"1", "true", "yes", "on"}


class BillingError(AuthError):
    pass


class BillingStore:
    """Durable crypto-billing state in the same SQLite database as the platform."""

    def __init__(self, path: str | os.PathLike[str] = "artifacts/jobs.sqlite3"):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS payment_invoices (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    plan_id TEXT NOT NULL,
                    base_price_units INTEGER NOT NULL,
                    payment_amount_units INTEGER NOT NULL UNIQUE,
                    currency TEXT NOT NULL DEFAULT 'USDT',
                    chain_id TEXT NOT NULL DEFAULT '1',
                    token_contract TEXT NOT NULL,
                    receiver_address TEXT NOT NULL,
                    expected_payer_address TEXT,
                    status TEXT NOT NULL DEFAULT 'awaiting_payment',
                    expires_at TEXT NOT NULL,
                    paid_at TEXT,
                    settlement_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_payment_invoices_user ON payment_invoices(user_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_payment_invoices_status ON payment_invoices(status, expires_at);
                CREATE INDEX IF NOT EXISTS idx_payment_invoices_payer ON payment_invoices(expected_payer_address, status);

                CREATE TABLE IF NOT EXISTS payment_events (
                    id TEXT PRIMARY KEY,
                    invoice_id TEXT,
                    chain_id TEXT NOT NULL,
                    tx_hash TEXT NOT NULL,
                    log_index INTEGER NOT NULL,
                    block_number INTEGER NOT NULL,
                    block_hash TEXT NOT NULL,
                    token_contract TEXT NOT NULL,
                    from_address TEXT NOT NULL,
                    to_address TEXT NOT NULL,
                    amount_units INTEGER NOT NULL,
                    receipt_status INTEGER NOT NULL DEFAULT 1,
                    confirmations INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'detected',
                    rejection_code TEXT,
                    first_seen_at TEXT NOT NULL,
                    confirmed_at TEXT,
                    reorged_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(chain_id, tx_hash, log_index)
                );
                CREATE INDEX IF NOT EXISTS idx_payment_events_invoice ON payment_events(invoice_id, status);
                CREATE INDEX IF NOT EXISTS idx_payment_events_tx ON payment_events(chain_id, tx_hash);
                CREATE INDEX IF NOT EXISTS idx_payment_events_status ON payment_events(status, block_number);

                CREATE TABLE IF NOT EXISTS payment_settlements (
                    id TEXT PRIMARY KEY,
                    invoice_id TEXT NOT NULL UNIQUE,
                    payment_event_id TEXT NOT NULL UNIQUE,
                    subscription_id TEXT NOT NULL,
                    settled_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS payment_scanner_state (
                    id TEXT PRIMARY KEY,
                    next_block INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_payment_amount ON payment_invoices(payment_amount_units);

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
                """
            )
            # Protect the legacy/manual payment table from reusing a blockchain tx.
            try:
                db.execute(
                    """CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_transactions_tx_unique
                       ON payment_transactions(tx_hash)
                       WHERE tx_hash IS NOT NULL AND tx_hash != ''"""
                )
            except sqlite3.IntegrityError:
                # Legacy/manual data may contain duplicate hashes; the new payment_events
                # uniqueness remains authoritative for automated blockchain settlement.
                pass

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30)
        db.execute("PRAGMA busy_timeout=30000")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def create_invoice(
        self,
        user_id: str,
        plan: dict[str, Any],
        receiver_address: str,
        expected_payer_address: str | None,
        ttl_minutes: int,
        amount_suffix_factory: Callable[[], int],
        chain_id: str = ETHEREUM_CHAIN_ID,
        token_contract: str = USDT_ETHEREUM_CONTRACT,
    ) -> dict[str, Any]:
        base_units = _money_to_units(plan["price_usdt"])
        now_dt = datetime.now(timezone.utc)
        expires = now_dt + timedelta(minutes=max(5, min(ttl_minutes, 180)))
        receiver = _lower_address(receiver_address)
        payer = _lower_address(expected_payer_address)
        if chain_id != ETHEREUM_CHAIN_ID:
            raise BillingError("Only Ethereum Mainnet is supported for USDT billing.", "PAYMENT_CHAIN_UNSUPPORTED", 422)
        token_contract = str(token_contract).strip().lower()
        if token_contract != USDT_ETHEREUM_CONTRACT:
            raise BillingError("Only the configured Ethereum USDT contract is accepted.", "PAYMENT_TOKEN_UNSUPPORTED", 500)

        with self._lock, self._connect() as db:
            now = _now()
            db.execute("UPDATE payment_invoices SET status='expired',updated_at=? WHERE status='awaiting_payment' AND expires_at<=?", (now, now))
            row = db.execute(
                "SELECT id,expected_payer_address FROM payment_invoices WHERE user_id=? AND plan_id=? AND status IN (?,?,?) ORDER BY created_at DESC LIMIT 1",
                (user_id, plan["id"], *OPEN_INVOICE_STATUSES),
            ).fetchone()
            if row:
                existing_payer = row[1]
                if existing_payer and payer and existing_payer != payer:
                    raise BillingError("An active invoice is tied to another wallet address.", "INVOICE_PAYER_LOCKED", 409)
                if not existing_payer and payer:
                    db.execute("UPDATE payment_invoices SET expected_payer_address=?,updated_at=? WHERE id=?", (payer, _now(), row[0]))
                    db.commit()
                return self.get_invoice(row[0], user_id)

            for _ in range(50):
                suffix = int(amount_suffix_factory())
                amount_units = base_units + suffix
                try:
                    invoice_id = _new_id("inv")
                    created = _now()
                    db.execute(
                        """INSERT INTO payment_invoices(
                           id,user_id,plan_id,base_price_units,payment_amount_units,currency,chain_id,token_contract,
                           receiver_address,expected_payer_address,status,expires_at,created_at,updated_at
                        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            invoice_id,
                            user_id,
                            plan["id"],
                            base_units,
                            amount_units,
                            "USDT",
                            chain_id,
                            token_contract,
                            receiver,
                            payer,
                            "awaiting_payment",
                            expires.isoformat(),
                            created,
                            created,
                        ),
                    )
                    db.commit()
                    return self.get_invoice(invoice_id, user_id)
                except sqlite3.IntegrityError as exc:
                    if "payment_invoices.payment_amount_units" not in str(exc) and "UNIQUE constraint failed: payment_invoices.payment_amount_units" not in str(exc):
                        raise
            raise BillingError("Could not allocate a unique payment amount.", "PAYMENT_AMOUNT_UNAVAILABLE", 503)

    def get_invoice(self, invoice_id: str, user_id: str | None = None) -> dict[str, Any]:
        where = "id=?"
        params: list[Any] = [invoice_id]
        if user_id is not None:
            where += " AND user_id=?"
            params.append(user_id)
        with self._connect() as db:
            row = db.execute(
                f"""SELECT id,user_id,plan_id,base_price_units,payment_amount_units,currency,chain_id,token_contract,
                           receiver_address,expected_payer_address,status,expires_at,paid_at,settlement_id,created_at,updated_at
                    FROM payment_invoices WHERE {where}""",
                tuple(params),
            ).fetchone()
        if not row:
            raise AuthError("Payment invoice not found.", "INVOICE_NOT_FOUND", 404)
        return self._invoice_row(row)

    def latest_invoice(self, user_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute(
                """SELECT id,user_id,plan_id,base_price_units,payment_amount_units,currency,chain_id,token_contract,
                          receiver_address,expected_payer_address,status,expires_at,paid_at,settlement_id,created_at,updated_at
                   FROM payment_invoices WHERE user_id=? ORDER BY created_at DESC LIMIT 1""",
                (user_id,),
            ).fetchone()
        return self._invoice_row(row) if row else None

    def active_invoices(self) -> list[dict[str, Any]]:
        placeholders = ",".join("?" for _ in OPEN_INVOICE_STATUSES)
        with self._connect() as db:
            rows = db.execute(
                f"""SELECT id,user_id,plan_id,base_price_units,payment_amount_units,currency,chain_id,token_contract,
                           receiver_address,expected_payer_address,status,expires_at,paid_at,settlement_id,created_at,updated_at
                    FROM payment_invoices WHERE status IN ({placeholders}) ORDER BY created_at""",
                OPEN_INVOICE_STATUSES,
            ).fetchall()
        return [self._invoice_row(row) for row in rows]

    def mark_expired(self) -> int:
        now = _now()
        with self._lock, self._connect() as db:
            cur = db.execute(
                "UPDATE payment_invoices SET status='expired',updated_at=? WHERE status='awaiting_payment' AND expires_at<=?",
                (now, now),
            )
            return int(cur.rowcount)

    def insert_payment_event(self, event: dict[str, Any]) -> dict[str, Any]:
        now = _now()
        with self._lock, self._connect() as db:
            existing = db.execute(
                "SELECT id FROM payment_events WHERE chain_id=? AND tx_hash=? AND log_index=?",
                (event["chain_id"], event["tx_hash"], event["log_index"]),
            ).fetchone()
            if existing:
                row = db.execute(
                    """SELECT id,invoice_id,chain_id,tx_hash,log_index,block_number,block_hash,token_contract,from_address,
                              to_address,amount_units,receipt_status,confirmations,status,rejection_code,first_seen_at,confirmed_at,reorged_at,created_at,updated_at
                       FROM payment_events WHERE id=?""",
                    (existing[0],),
                ).fetchone()
                return self._event_row(row)
            event_id = _new_id("pev")
            db.execute(
                """INSERT INTO payment_events(
                   id,invoice_id,chain_id,tx_hash,log_index,block_number,block_hash,token_contract,from_address,to_address,
                   amount_units,receipt_status,confirmations,status,first_seen_at,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event_id, event.get("invoice_id"), event["chain_id"], event["tx_hash"], event["log_index"], event["block_number"],
                    event["block_hash"], event["token_contract"], event["from_address"], event["to_address"], event["amount_units"],
                    int(event.get("receipt_status", 1)), int(event.get("confirmations", 0)), event.get("status", "detected"), now, now, now,
                ),
            )
            db.commit()
            return self.get_payment_event(event_id)

    def get_payment_event(self, event_id: str) -> dict[str, Any]:
        with self._connect() as db:
            row = db.execute(
                """SELECT id,invoice_id,chain_id,tx_hash,log_index,block_number,block_hash,token_contract,from_address,
                          to_address,amount_units,receipt_status,confirmations,status,rejection_code,first_seen_at,confirmed_at,reorged_at,created_at,updated_at
                   FROM payment_events WHERE id=?""",
                (event_id,),
            ).fetchone()
        if not row:
            raise AuthError("Payment event not found.", "PAYMENT_EVENT_NOT_FOUND", 404)
        return self._event_row(row)

    def find_matching_invoice(self, amount_units: int, receiver: str, payer: str | None, now: str | None = None) -> dict[str, Any] | None:
        now = now or _now()
        placeholders = ",".join("?" for _ in OPEN_INVOICE_STATUSES)
        with self._connect() as db:
            params: list[Any] = [int(amount_units), receiver.lower(), *OPEN_INVOICE_STATUSES]
            where = f"payment_amount_units=? AND receiver_address=? AND status IN ({placeholders})"
            if payer:
                where += " AND (expected_payer_address IS NULL OR expected_payer_address=?)"
                params.append(payer.lower())
            row = db.execute(
                f"""SELECT id,user_id,plan_id,base_price_units,payment_amount_units,currency,chain_id,token_contract,
                           receiver_address,expected_payer_address,status,expires_at,paid_at,settlement_id,created_at,updated_at
                    FROM payment_invoices WHERE {where} ORDER BY created_at DESC LIMIT 1""",
                tuple(params),
            ).fetchone()
        if not row:
            return None
        invoice = self._invoice_row(row)
        if invoice["expires_at"] <= now:
            return None
        return invoice

    def attach_invoice(self, event_id: str, invoice: dict[str, Any], payer_matches: bool) -> None:
        now = _now()
        with self._lock, self._connect() as db:
            status = "payment_detected"
            rejection = None
            if not payer_matches:
                status = "rejected"
                rejection = "PAYER_MISMATCH"
            elif invoice["expires_at"] <= now:
                status = "rejected"
                rejection = "INVOICE_EXPIRED"
            db.execute(
                "UPDATE payment_events SET invoice_id=?,status=?,rejection_code=?,updated_at=? WHERE id=?",
                (invoice["id"], status, rejection, now, event_id),
            )
            if status == "payment_detected":
                db.execute("UPDATE payment_invoices SET status='confirming',updated_at=? WHERE id=? AND status IN (?,?,?)", (now, invoice["id"], *OPEN_INVOICE_STATUSES))

    def update_event_confirmation(self, event_id: str, confirmations: int, status: str, block_hash: str | None = None) -> None:
        now = _now()
        fields = ["confirmations=?", "status=?", "updated_at=?"]
        params: list[Any] = [max(0, int(confirmations)), status, now]
        if status == "confirmed":
            fields.append("confirmed_at=?")
            params.append(now)
        if status == "reorged":
            fields.append("reorged_at=?")
            params.append(now)
        if block_hash:
            fields.append("block_hash=?")
            params.append(block_hash)
        params.append(event_id)
        with self._lock, self._connect() as db:
            db.execute(f"UPDATE payment_events SET {', '.join(fields)} WHERE id=?", tuple(params))

    def settle(self, invoice_id: str, event_id: str, duration_days: int = 30) -> dict[str, Any]:
        now_dt = datetime.now(timezone.utc)
        now = now_dt.isoformat()
        with self._lock, self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            invoice_row = db.execute(
                "SELECT id,user_id,plan_id,status,payment_amount_units,expires_at,settlement_id FROM payment_invoices WHERE id=?",
                (invoice_id,),
            ).fetchone()
            if not invoice_row:
                raise AuthError("Payment invoice not found.", "INVOICE_NOT_FOUND", 404)
            if invoice_row[2] is None:
                raise BillingError("Invoice has no plan.", "INVOICE_PLAN_MISSING", 409)
            existing_settlement = db.execute(
                "SELECT id,subscription_id,settled_at FROM payment_settlements WHERE invoice_id=?",
                (invoice_id,),
            ).fetchone()
            if existing_settlement:
                return {
                    "settlement_id": existing_settlement[0],
                    "invoice_id": invoice_id,
                    "subscription_id": existing_settlement[1],
                    "status": "settled",
                    "settled_at": existing_settlement[2],
                    "idempotent": True,
                }
            event_row = db.execute(
                "SELECT id,invoice_id,status FROM payment_events WHERE id=?",
                (event_id,),
            ).fetchone()
            if not event_row:
                raise AuthError("Payment event not found.", "PAYMENT_EVENT_NOT_FOUND", 404)
            if event_row[1] != invoice_id:
                raise BillingError("Payment event is not linked to this invoice.", "PAYMENT_EVENT_MISMATCH", 409)
            if event_row[2] not in {"confirmed", "settled"}:
                raise BillingError("Payment is not final yet.", "PAYMENT_NOT_FINAL", 409)
            if invoice_row[3] == "settled":
                return {"invoice_id": invoice_id, "status": "settled", "settlement_id": invoice_row[6], "idempotent": True}
            try:
                expires_at = datetime.fromisoformat(invoice_row[5])
            except ValueError as exc:
                raise BillingError("Invoice expiration is invalid.", "INVOICE_EXPIRY_INVALID", 409) from exc
            event_seen = db.execute("SELECT first_seen_at FROM payment_events WHERE id=?", (event_id,)).fetchone()
            if expires_at <= now_dt and (not event_seen or not event_seen[0] or event_seen[0] > invoice_row[5]):
                raise BillingError("This payment invoice has expired.", "INVOICE_EXPIRED", 409)
            plan_row = db.execute(
                "SELECT id,price_usdt,active FROM api_plans WHERE id=?",
                (invoice_row[2],),
            ).fetchone()
            if not plan_row or not bool(plan_row[2]):
                raise BillingError("The payment plan is not active.", "PLAN_INACTIVE", 409)
            sub = db.execute("SELECT id,plan_id,status,starts_at,ends_at FROM subscriptions WHERE user_id=?", (invoice_row[1],)).fetchone()
            try:
                existing_end = datetime.fromisoformat(sub[4]) if sub and sub[4] else None
            except ValueError:
                existing_end = None
            base = existing_end if existing_end and existing_end > now_dt else now_dt
            new_end = (base + timedelta(days=max(1, duration_days))).isoformat()
            subscription_id = sub[0] if sub else _new_id("sub")
            if sub:
                db.execute(
                    "UPDATE subscriptions SET plan_id=?,status='active',ends_at=?,updated_at=? WHERE user_id=?",
                    (invoice_row[2], new_end, now, invoice_row[1]),
                )
            else:
                db.execute(
                    "INSERT INTO subscriptions(id,user_id,plan_id,status,starts_at,ends_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                    (subscription_id, invoice_row[1], invoice_row[2], "active", now, new_end, now),
                )
            settlement_id = _new_id("set")
            db.execute(
                "INSERT INTO payment_settlements(id,invoice_id,payment_event_id,subscription_id,settled_at,created_at) VALUES(?,?,?,?,?,?)",
                (settlement_id, invoice_id, event_id, subscription_id, now, now),
            )
            db.execute(
                "UPDATE payment_invoices SET status='paid',paid_at=?,settlement_id=?,updated_at=? WHERE id=?",
                (now, settlement_id, now, invoice_id),
            )
            db.execute("UPDATE payment_events SET status='settled',updated_at=? WHERE id=?", (now, event_id))
            # Keep the existing admin payment ledger populated for compatibility.
            tx = db.execute(
                "SELECT tx_hash FROM payment_events WHERE id=?", (event_id,)
            ).fetchone()[0]
            event_amount = db.execute("SELECT amount_units,tx_hash,chain_id FROM payment_events WHERE id=?", (event_id,)).fetchone()
            amount_usdt = float(Decimal(event_amount[0]) / Decimal(10**USDT_DECIMALS))
            legacy_id = _new_id("pay")
            try:
                db.execute(
                    """INSERT INTO payment_transactions(
                       id,user_id,subscription_id,plan_id,amount_usdt,currency,network,tx_hash,status,invoice_ref,metadata_json,paid_at,verified_by,created_at,updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        legacy_id, invoice_row[1], subscription_id, invoice_row[2], amount_usdt, "USDT", "Ethereum", tx, "confirmed",
                        invoice_id, '{"source":"blockchain","payment_event_id":"' + event_id + '"}', now, "blockchain", now, now,
                    ),
                )
            except sqlite3.IntegrityError:
                pass
            return {
                "settlement_id": settlement_id,
                "invoice_id": invoice_id,
                "subscription_id": subscription_id,
                "status": "settled",
                "settled_at": now,
                "idempotent": False,
            }

    @staticmethod
    def _invoice_row(row: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "id": row[0], "user_id": row[1], "plan_id": row[2], "base_price_units": int(row[3]),
            "base_price_usdt": _units_to_decimal(int(row[3])), "payment_amount_units": int(row[4]),
            "payment_amount_usdt": _units_to_decimal(int(row[4])), "currency": row[5], "chain_id": row[6],
            "token_contract": row[7], "receiver_address": row[8], "expected_payer_address": row[9],
            "status": row[10], "expires_at": row[11], "paid_at": row[12], "settlement_id": row[13],
            "created_at": row[14], "updated_at": row[15],
        }

    @staticmethod
    def _event_row(row: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "id": row[0], "invoice_id": row[1], "chain_id": row[2], "tx_hash": row[3], "log_index": int(row[4]),
            "block_number": int(row[5]), "block_hash": row[6], "token_contract": row[7], "from_address": row[8],
            "to_address": row[9], "amount_units": int(row[10]), "amount_usdt": _units_to_decimal(int(row[10])),
            "receipt_status": int(row[11]), "confirmations": int(row[12]), "status": row[13], "rejection_code": row[14],
            "first_seen_at": row[15], "confirmed_at": row[16], "reorged_at": row[17], "created_at": row[18], "updated_at": row[19],
        }


class BillingService:
    def __init__(self, db_path: str = "artifacts/jobs.sqlite3"):
        self.store = BillingStore(db_path)
        self.enabled = _bool_env("SMARTRISK_BILLING_ENABLED", False)
        self.chain_id = ETHEREUM_CHAIN_ID
        self.token_contract = os.getenv("SMARTRISK_PAYMENT_USDT_CONTRACT", USDT_ETHEREUM_CONTRACT).strip().lower()
        self.receiver_address = (os.getenv("SMARTRISK_PAYMENT_RECEIVER") or "").strip().lower()
        self.invoice_ttl_minutes = int(os.getenv("SMARTRISK_PAYMENT_INVOICE_TTL_MINUTES", "30"))
        self.scan_chunk = max(1, min(int(os.getenv("SMARTRISK_PAYMENT_SCAN_CHUNK", "1000")), 2000))
        self.poll_seconds = max(5, int(os.getenv("SMARTRISK_PAYMENT_POLL_SECONDS", "15")))
        self.scan_lookback = max(0, int(os.getenv("SMARTRISK_PAYMENT_SCAN_LOOKBACK_BLOCKS", "50")))
        self.rpc_url = os.getenv("SMARTRISK_PAYMENT_RPC_URL")
        self._rpc: AlchemyRpcClient | None = None
        self._monitor: PaymentMonitor | None = None

    def rpc_source_configured(self) -> bool:
        if self.rpc_url:
            return True
        names = (
            "ALCHEMY_API_KEY", "ALCHEMY_RPC_URL",
            "SMARTRISK_ETHEREUM_RPC_URL",
            "QUICKNODE_RPC_URL", "CHAINSTACK_RPC_URL",
            "SMARTRISK_ETHEREUM_QUICKNODE_RPC_URL",
            "SMARTRISK_ETHEREUM_CHAINSTACK_RPC_URL",
        )
        return any(os.getenv(name) for name in names)

    @property
    def configured(self) -> bool:
        return (
            self.enabled
            and bool(self.receiver_address)
            and ADDRESS_RE.fullmatch(self.receiver_address) is not None
            and self.token_contract == USDT_ETHEREUM_CONTRACT
            and self.rpc_source_configured()
        )

    def validate_config(self) -> None:
        if not self.enabled:
            raise BillingError("Crypto billing is disabled.", "BILLING_DISABLED", 503)
        if not ADDRESS_RE.fullmatch(self.receiver_address):
            raise BillingError("Payment receiver is not configured.", "PAYMENT_RECEIVER_NOT_CONFIGURED", 503)
        if self.token_contract != USDT_ETHEREUM_CONTRACT:
            raise BillingError("Configured USDT contract is not the approved Ethereum USDT contract.", "PAYMENT_TOKEN_INVALID", 503)
        if not self.rpc_source_configured():
            raise BillingError("No Ethereum RPC provider is configured for payment monitoring.", "PAYMENT_RPC_NOT_CONFIGURED", 503)

    def rpc(self) -> AlchemyRpcClient:
        self.validate_config()
        if self._rpc is None:
            self._rpc = AlchemyRpcClient(rpc_url=self.rpc_url, chain="eth-mainnet", timeout_seconds=20, retries=3)
        return self._rpc

    def plans(self, developer_store) -> list[dict[str, Any]]:
        plans = developer_store.plans()
        for plan in plans:
            if plan["active"] and plan["price_usdt"] > 0:
                plan["billing_currency"] = "USDT"
                plan["billing_network"] = "Ethereum"
        return plans

    def create_invoice(self, user: Any, plan_id: str, expected_payer_address: str | None, developer_store) -> dict[str, Any]:
        self.validate_config()
        plan = developer_store.plan(plan_id)
        if not plan["active"]:
            raise AuthError("The selected plan is inactive.", "PLAN_INACTIVE", 409)
        if plan["price_usdt"] <= 0:
            raise BillingError("The selected plan is not billable.", "PLAN_NOT_BILLABLE", 409)
        suffix = lambda: __import__("secrets").randbelow(999000) + 1000
        return self.store.create_invoice(
            user.id,
            plan,
            self.receiver_address,
            expected_payer_address,
            self.invoice_ttl_minutes,
            suffix,
            self.chain_id,
            self.token_contract,
        )

    def get_invoice(self, user: Any, invoice_id: str) -> dict[str, Any]:
        self.store.mark_expired()
        return self.store.get_invoice(invoice_id, user.id)

    def verify_transaction(self, user: Any, invoice_id: str, tx_hash: str, settle: bool = True) -> dict[str, Any]:
        self.validate_config()
        tx_hash = _validate_tx_hash(tx_hash)
        invoice = self.store.get_invoice(invoice_id, user.id)
        rpc = self.rpc()
        chain_id = rpc.get_chain_id()
        if _hex_int(chain_id) != 1:
            raise BillingError("Payment RPC is not connected to Ethereum Mainnet.", "PAYMENT_RPC_CHAIN_MISMATCH", 503)
        receipt = rpc.get_transaction_receipt(tx_hash)
        if not receipt:
            raise BillingError("Transaction has not been found yet.", "TX_NOT_FOUND", 404)
        if _hex_int(receipt.get("status")) != 1:
            raise BillingError("The Ethereum transaction failed.", "TX_FAILED", 422)
        tx_block = _hex_int(receipt.get("blockNumber"))
        if tx_block <= 0:
            raise BillingError("Transaction is not mined yet.", "TX_NOT_MINED", 409)
        block = rpc.request("eth_getBlockByNumber", [hex(tx_block), False])
        block_timestamp = _hex_int(block.get("timestamp")) if block else 0
        if block_timestamp:
            expires_dt = datetime.fromisoformat(invoice["expires_at"])
            if datetime.fromtimestamp(block_timestamp, tz=timezone.utc) > expires_dt:
                raise BillingError("This payment was included after the invoice expired.", "INVOICE_EXPIRED", 409)
        matching_logs = []
        receiver = invoice["receiver_address"]
        token = invoice["token_contract"]
        expected_payer = invoice["expected_payer_address"]
        logs = receipt.get("logs") or []
        for log in logs:
            if str(log.get("address", "")).lower() != token:
                continue
            topics = log.get("topics") or []
            if len(topics) < 3 or str(topics[0]).lower() != TRANSFER_TOPIC:
                continue
            from_addr = "0x" + str(topics[1])[-40:].lower()
            to_addr = "0x" + str(topics[2])[-40:].lower()
            amount_units = _hex_int(log.get("data"))
            if to_addr != receiver or amount_units != invoice["payment_amount_units"]:
                continue
            matching_logs.append({
                "log_index": _hex_int(log.get("logIndex")),
                "block_number": _hex_int(log.get("blockNumber")) or tx_block,
                "block_hash": str(log.get("blockHash") or receipt.get("blockHash") or "").lower(),
                "from_address": from_addr,
                "to_address": to_addr,
                "amount_units": amount_units,
            })
        if not matching_logs:
            raise BillingError("The transaction does not contain the exact USDT payment for this invoice.", "PAYMENT_MISMATCH", 422)
        if len(matching_logs) > 1:
            raise BillingError("The transaction contains multiple matching USDT transfers; automatic settlement is blocked.", "PAYMENT_AMBIGUOUS", 409)
        match = matching_logs[0]
        if expected_payer and expected_payer != match["from_address"]:
            raise BillingError("The payment sender does not match the invoice wallet.", "PAYER_MISMATCH", 422)

        finalized = rpc.request("eth_getBlockByNumber", ["finalized", False])
        finalized_block = _hex_int(finalized.get("number")) if finalized else 0
        confirmations = max(0, finalized_block - tx_block + 1) if finalized_block >= tx_block else 0
        event = self.store.insert_payment_event({
            "invoice_id": invoice["id"],
            "chain_id": self.chain_id,
            "tx_hash": tx_hash,
            "log_index": match["log_index"],
            "block_number": tx_block,
            "block_hash": match["block_hash"],
            "token_contract": token,
            "from_address": match["from_address"],
            "to_address": receiver,
            "amount_units": match["amount_units"],
            "receipt_status": 1,
            "confirmations": confirmations,
            "status": "confirmed" if finalized_block >= tx_block else "confirming",
        })
        if event["invoice_id"] is None or event["status"] in {"detected", "confirming"}:
            self.store.attach_invoice(event["id"], invoice, True)
            event = self.store.get_payment_event(event["id"])
        if finalized_block < tx_block:
            self.store.update_event_confirmation(event["id"], confirmations, "confirming")
            return {"invoice": self.store.get_invoice(invoice_id, user.id), "payment": self.store.get_payment_event(event["id"]), "settlement": None}
        self.store.update_event_confirmation(event["id"], confirmations, "confirmed")
        settlement = self.store.settle(invoice_id, event["id"])
        return {"invoice": self.store.get_invoice(invoice_id, user.id), "payment": self.store.get_payment_event(event["id"]), "settlement": settlement}

    def start_monitor(self) -> None:
        if not self.configured:
            return
        self._monitor = PaymentMonitor(self)
        self._monitor.start()

    def stop_monitor(self) -> None:
        if self._monitor:
            self._monitor.stop()


class PaymentMonitor:
    """Continuously discovers incoming USDT transfers and settles finalized payments."""

    def __init__(self, billing: BillingService):
        self.billing = billing
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self.run, name="smartrisk-payment-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self.billing.store.mark_expired()
                self.scan_once()
                self.reconcile_confirming()
            except Exception:
                # Payment processing is fail-closed. A transient RPC/database error must never grant access.
                pass
            self._stop.wait(self.billing.poll_seconds)

    def scan_once(self) -> int:
        rpc = self.billing.rpc()
        latest_block_data = rpc.request("eth_getBlockByNumber", ["latest", False])
        latest = _hex_int(latest_block_data.get("number")) if latest_block_data else 0
        if latest <= 0:
            return 0
        state_id = "ethereum-usdt"
        with self.billing.store._lock, self.billing.store._connect() as db:
            row = db.execute("SELECT next_block FROM payment_scanner_state WHERE id=?", (state_id,)).fetchone()
            next_block = int(row[0]) if row else max(0, latest - self.billing.scan_lookback)
            if next_block > latest:
                next_block = max(0, latest - self.billing.scan_lookback)
            db.execute(
                "INSERT INTO payment_scanner_state(id,next_block,updated_at) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET next_block=excluded.next_block,updated_at=excluded.updated_at",
                (state_id, next_block, _now()),
            )
        scanned = 0
        cursor = next_block
        while cursor <= latest and not self._stop.is_set():
            end = min(latest, cursor + self.billing.scan_chunk - 1)
            logs = rpc.request(
                "eth_getLogs",
                [
                    {
                        "fromBlock": hex(cursor),
                        "toBlock": hex(end),
                        "address": self.billing.token_contract,
                        "topics": [TRANSFER_TOPIC, None, _topic_address(self.billing.receiver_address)],
                    }
                ],
            ) or []
            for log in logs:
                scanned += 1
                self._process_log(rpc, log)
            cursor = end + 1
            with self.billing.store._lock, self.billing.store._connect() as db:
                db.execute("UPDATE payment_scanner_state SET next_block=?,updated_at=? WHERE id=?", (cursor, _now(), state_id))
        return scanned

    def _process_log(self, rpc: AlchemyRpcClient, log: dict[str, Any]) -> None:
        topics = log.get("topics") or []
        if len(topics) < 3 or str(topics[0]).lower() != TRANSFER_TOPIC:
            return
        tx_hash = _validate_tx_hash(str(log.get("transactionHash")))
        block_number = _hex_int(log.get("blockNumber"))
        block_hash = str(log.get("blockHash") or "").lower()
        from_address = "0x" + str(topics[1])[-40:].lower()
        to_address = "0x" + str(topics[2])[-40:].lower()
        amount_units = _hex_int(log.get("data"))
        invoice = self.billing.store.find_matching_invoice(amount_units, self.billing.receiver_address, from_address)
        event = self.billing.store.insert_payment_event({
            "invoice_id": invoice["id"] if invoice else None,
            "chain_id": ETHEREUM_CHAIN_ID,
            "tx_hash": tx_hash,
            "log_index": _hex_int(log.get("logIndex")),
            "block_number": block_number,
            "block_hash": block_hash,
            "token_contract": self.billing.token_contract,
            "from_address": from_address,
            "to_address": to_address,
            "amount_units": amount_units,
            "status": "detected",
        })
        if not invoice:
            return
        if event["invoice_id"] is None or event["status"] in {"detected", "confirming"}:
            self.billing.store.attach_invoice(event["id"], invoice, True)
            event = self.billing.store.get_payment_event(event["id"])
        # Manual-payment invoices without a known payer require the account owner
        # to submit the transaction hash; automatic settlement is intentionally blocked.
        auto_settle_allowed = bool(invoice.get("expected_payer_address"))
        # Confirm receipt status and finality before settlement.
        receipt = rpc.get_transaction_receipt(tx_hash)
        if not receipt or _hex_int(receipt.get("status")) != 1:
            return
        finalized = rpc.request("eth_getBlockByNumber", ["finalized", False])
        finalized_block = _hex_int(finalized.get("number")) if finalized else 0
        confirmations = max(0, finalized_block - block_number + 1) if finalized_block >= block_number else 0
        if finalized_block < block_number:
            self.billing.store.update_event_confirmation(event["id"], confirmations, "confirming")
            return
        self.billing.store.update_event_confirmation(event["id"], confirmations, "confirmed")
        if not auto_settle_allowed:
            return
        try:
            self.billing.store.settle(invoice["id"], event["id"])
        except BillingError:
            return

    def reconcile_confirming(self) -> None:
        rpc = self.billing.rpc()
        with self.billing.store._connect() as db:
            rows = db.execute(
                "SELECT id,invoice_id,tx_hash,block_number,block_hash,status FROM payment_events WHERE status='confirming' ORDER BY block_number LIMIT 200"
            ).fetchall()
        if not rows:
            return
        finalized = rpc.request("eth_getBlockByNumber", ["finalized", False])
        finalized_block = _hex_int(finalized.get("number")) if finalized else 0
        for event_id, invoice_id, tx_hash, block_number, block_hash, _ in rows:
            receipt = rpc.get_transaction_receipt(tx_hash)
            if not receipt:
                self.billing.store.update_event_confirmation(event_id, 0, "reorged")
                if invoice_id:
                    with self.billing.store._lock, self.billing.store._connect() as db:
                        db.execute("UPDATE payment_invoices SET status='awaiting_payment',updated_at=? WHERE id=? AND status='confirming'", (_now(), invoice_id))
                continue
            current_block_hash = str(receipt.get("blockHash") or "").lower()
            if current_block_hash and block_hash and current_block_hash != block_hash:
                self.billing.store.update_event_confirmation(event_id, 0, "reorged", current_block_hash)
                continue
            confirmations = max(0, finalized_block - block_number + 1) if finalized_block >= block_number else 0
            if finalized_block >= block_number:
                self.billing.store.update_event_confirmation(event_id, confirmations, "confirmed")
                if invoice_id:
                    try:
                        self.billing.store.settle(invoice_id, event_id)
                    except BillingError:
                        pass
            else:
                self.billing.store.update_event_confirmation(event_id, confirmations, "confirming")

from __future__ import annotations

import sqlite3
from decimal import Decimal

import pytest

from smartrisk.service.billing import (
    BillingService,
    BillingStore,
    BillingError,
    TRANSFER_TOPIC,
    USDT_ETHEREUM_CONTRACT,
    _money_to_units,
)
from smartrisk.service.developer_api import DeveloperStore


USER_ID = "user_test"
RECEIVER = "0x1111111111111111111111111111111111111111"
PAYER = "0x2222222222222222222222222222222222222222"


class FakeRpc:
    def __init__(self, receipt, finalized_block: int = 100):
        self.receipt = receipt
        self.finalized_block = finalized_block

    def get_chain_id(self):
        return "0x1"

    def get_transaction_receipt(self, tx_hash):
        return self.receipt

    def request(self, method, params=None):
        if method == "eth_getBlockByNumber" and params == ["finalized", False]:
            return {"number": hex(self.finalized_block)}
        if method == "eth_getBlockByNumber" and params and params[0] not in {"latest", "safe", "finalized"}:
            return {"number": params[0], "timestamp": hex(1_700_000_000)}
        raise AssertionError((method, params))


def seed_user(db_path):
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT)")
        db.execute("INSERT INTO users(id,email) VALUES(?,?)", (USER_ID, "u@example.test"))


def invoice_service(tmp_path, monkeypatch):
    db_path = str(tmp_path / "db.sqlite3")
    developer = DeveloperStore(db_path)
    seed_user(db_path)
    service = BillingService(db_path)
    monkeypatch.setattr(service, "validate_config", lambda: None)
    service.enabled = True
    service.receiver_address = RECEIVER
    service.token_contract = USDT_ETHEREUM_CONTRACT
    return service, developer, db_path


def test_money_is_exact_integer_units():
    assert _money_to_units(Decimal("29.000000")) == 29_000_000
    with pytest.raises(Exception):
        _money_to_units("29.0000001")


def test_invoice_reuses_same_open_invoice(tmp_path, monkeypatch):
    service, developer, _ = invoice_service(tmp_path, monkeypatch)
    user = type("U", (), {"id": USER_ID})()
    plan = developer.plan("developer")
    calls = []
    original = service.store.create_invoice
    monkeypatch.setattr(service.store, "create_invoice", original)
    i1 = service.create_invoice(user, "developer", PAYER, developer)
    i2 = service.create_invoice(user, "developer", PAYER, developer)
    assert i1["id"] == i2["id"]
    assert i1["payment_amount_units"] == i2["payment_amount_units"]
    assert i1["payment_amount_units"] != _money_to_units(plan["price_usdt"])


def test_settlement_is_idempotent(tmp_path, monkeypatch):
    service, developer, db_path = invoice_service(tmp_path, monkeypatch)
    user = type("U", (), {"id": USER_ID})()
    invoice = service.create_invoice(user, "developer", PAYER, developer)
    tx_hash = "0x" + "aa" * 32
    event = service.store.insert_payment_event({
        "invoice_id": invoice["id"], "chain_id": "1", "tx_hash": tx_hash, "log_index": 0,
        "block_number": 90, "block_hash": "0x" + "bb" * 32, "token_contract": USDT_ETHEREUM_CONTRACT,
        "from_address": PAYER, "to_address": RECEIVER, "amount_units": invoice["payment_amount_units"],
        "confirmations": 20, "status": "confirmed",
    })
    first = service.store.settle(invoice["id"], event["id"])
    second = service.store.settle(invoice["id"], event["id"])
    assert first["status"] == "settled"
    assert second["status"] == "settled"
    assert second["idempotent"] is True
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM payment_settlements WHERE invoice_id=?", (invoice["id"],)).fetchone()[0] == 1
        assert db.execute("SELECT ends_at FROM subscriptions WHERE user_id=?", (USER_ID,)).fetchone()[0]
        assert db.execute("SELECT COUNT(*) FROM payment_transactions WHERE tx_hash=?", (tx_hash,)).fetchone()[0] == 1


def test_verify_exact_usdt_transfer_and_activate(tmp_path, monkeypatch):
    service, developer, _ = invoice_service(tmp_path, monkeypatch)
    user = type("U", (), {"id": USER_ID})()
    invoice = service.create_invoice(user, "developer", PAYER, developer)
    tx_hash = "0x" + "12" * 32
    log = {
        "address": USDT_ETHEREUM_CONTRACT,
        "topics": [TRANSFER_TOPIC, "0x" + PAYER[2:].rjust(64, "0"), "0x" + RECEIVER[2:].rjust(64, "0")],
        "data": hex(invoice["payment_amount_units"]),
        "logIndex": "0x0",
        "blockNumber": hex(90),
        "blockHash": "0x" + "ab" * 32,
    }
    receipt = {"status": "0x1", "blockNumber": hex(90), "blockHash": log["blockHash"], "logs": [log]}
    service._rpc = FakeRpc(receipt, finalized_block=100)
    result = service.verify_transaction(user, invoice["id"], tx_hash)
    assert result["invoice"]["status"] == "paid"
    assert result["settlement"]["status"] == "settled"


def test_verify_wrong_amount_is_rejected(tmp_path, monkeypatch):
    service, developer, _ = invoice_service(tmp_path, monkeypatch)
    user = type("U", (), {"id": USER_ID})()
    invoice = service.create_invoice(user, "developer", PAYER, developer)
    tx_hash = "0x" + "34" * 32
    log = {
        "address": USDT_ETHEREUM_CONTRACT,
        "topics": [TRANSFER_TOPIC, "0x" + PAYER[2:].rjust(64, "0"), "0x" + RECEIVER[2:].rjust(64, "0")],
        "data": hex(invoice["payment_amount_units"] - 1),
        "logIndex": "0x0", "blockNumber": hex(90), "blockHash": "0x" + "cd" * 32,
    }
    service._rpc = FakeRpc({"status": "0x1", "blockNumber": hex(90), "blockHash": log["blockHash"], "logs": [log]})
    with pytest.raises(BillingError) as exc:
        service.verify_transaction(user, invoice["id"], tx_hash)
    assert exc.value.code == "PAYMENT_MISMATCH"


def test_invoice_amounts_are_unique_across_invoices(tmp_path, monkeypatch):
    service, developer, _ = invoice_service(tmp_path, monkeypatch)
    ids = []
    for idx in range(20):
        user_id = f"user_{idx}"
        with sqlite3.connect(service.store.path) as db:
            db.execute("INSERT INTO users(id,email) VALUES(?,?)", (user_id, f"{idx}@example.test"))
        user = type("U", (), {"id": user_id})()
        ids.append(service.create_invoice(user, "developer", PAYER, developer)["payment_amount_units"])
    assert len(ids) == len(set(ids))


def test_concurrent_settlement_only_creates_one_subscription_period(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    service, developer, db_path = invoice_service(tmp_path, monkeypatch)
    user = type("U", (), {"id": USER_ID})()
    invoice = service.create_invoice(user, "developer", PAYER, developer)
    event = service.store.insert_payment_event({
        "invoice_id": invoice["id"], "chain_id": "1", "tx_hash": "0x" + "55" * 32, "log_index": 0,
        "block_number": 90, "block_hash": "0x" + "66" * 32, "token_contract": USDT_ETHEREUM_CONTRACT,
        "from_address": PAYER, "to_address": RECEIVER, "amount_units": invoice["payment_amount_units"],
        "confirmations": 20, "status": "confirmed",
    })

    def settle():
        return service.store.settle(invoice["id"], event["id"])

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(lambda _: settle(), range(16)))
    assert sum(1 for r in results if not r.get("idempotent")) == 1
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM payment_settlements WHERE invoice_id=?", (invoice["id"],)).fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM subscriptions WHERE user_id=?", (USER_ID,)).fetchone()[0] == 1


def test_monitor_auto_settles_known_payer(tmp_path, monkeypatch):
    from smartrisk.service.billing import PaymentMonitor

    service, developer, _ = invoice_service(tmp_path, monkeypatch)
    user = type("U", (), {"id": USER_ID})()
    invoice = service.create_invoice(user, "developer", PAYER, developer)
    tx_hash = "0x" + "77" * 32
    log = {
        "address": USDT_ETHEREUM_CONTRACT,
        "topics": [TRANSFER_TOPIC, "0x" + PAYER[2:].rjust(64, "0"), "0x" + RECEIVER[2:].rjust(64, "0")],
        "data": hex(invoice["payment_amount_units"]),
        "transactionHash": tx_hash,
        "logIndex": "0x0", "blockNumber": hex(90), "blockHash": "0x" + "78" * 32,
    }
    fake = FakeRpc({"status": "0x1", "blockNumber": hex(90), "blockHash": log["blockHash"], "logs": [log]}, finalized_block=100)
    monitor = PaymentMonitor(service)
    monitor._process_log(fake, log)
    assert service.store.get_invoice(invoice["id"], USER_ID)["status"] == "paid"


def test_monitor_does_not_auto_settle_unknown_payer(tmp_path, monkeypatch):
    from smartrisk.service.billing import PaymentMonitor

    service, developer, _ = invoice_service(tmp_path, monkeypatch)
    user = type("U", (), {"id": USER_ID})()
    invoice = service.create_invoice(user, "developer", None, developer)
    tx_hash = "0x" + "88" * 32
    log = {
        "address": USDT_ETHEREUM_CONTRACT,
        "topics": [TRANSFER_TOPIC, "0x" + PAYER[2:].rjust(64, "0"), "0x" + RECEIVER[2:].rjust(64, "0")],
        "data": hex(invoice["payment_amount_units"]),
        "transactionHash": tx_hash,
        "logIndex": "0x0", "blockNumber": hex(90), "blockHash": "0x" + "89" * 32,
    }
    fake = FakeRpc({"status": "0x1", "blockNumber": hex(90), "blockHash": log["blockHash"], "logs": [log]}, finalized_block=100)
    monitor = PaymentMonitor(service)
    monitor._process_log(fake, log)
    assert service.store.get_invoice(invoice["id"], USER_ID)["status"] == "confirming"
    assert service.store.active_invoices()[0]["id"] == invoice["id"]

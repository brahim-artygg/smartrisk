from smartrisk.indexer.ledger import TRANSFER_TOPIC, TransferLedger


def log(tx, idx, block, from_addr, to_addr, amount, removed=False, block_hash="0xblock"):
    return {
        "address": "0xtoken",
        "topics": [TRANSFER_TOPIC, "0x" + from_addr[2:].rjust(64, "0"), "0x" + to_addr[2:].rjust(64, "0")],
        "data": hex(amount),
        "blockNumber": hex(block),
        "blockHash": block_hash,
        "transactionHash": tx,
        "logIndex": hex(idx),
        "removed": removed,
    }


def test_ledger_deduplicates_and_builds_holders():
    zero = "0x" + "0" * 40
    alice = "0x" + "a" * 40
    bob = "0x" + "b" * 40
    first = log("0xtx1", 0, 10, zero, alice, 100)
    second = log("0xtx2", 0, 11, alice, bob, 25)
    ledger = TransferLedger()
    stats = ledger.ingest_logs("0x1", [first, first, second])
    assert stats == {"accepted": 2, "duplicate": 1, "removed": 0, "malformed": 0}
    assert ledger.holder_snapshot("0xtoken") == {alice: 75, bob: 25}


def test_removed_log_rolls_back_canonical_event():
    zero = "0x" + "0" * 40
    alice = "0x" + "a" * 40
    event = log("0xtx1", 0, 10, zero, alice, 100)
    ledger = TransferLedger()
    ledger.ingest_logs("0x1", [event])
    removed = dict(event, removed=True)
    assert ledger.ingest_logs("0x1", [removed])["removed"] == 1
    assert ledger.holder_snapshot("0xtoken") == {}


def test_malformed_or_non_transfer_is_not_indexed():
    ledger = TransferLedger()
    assert ledger.ingest_logs("0x1", [{"topics": []}])["malformed"] == 1

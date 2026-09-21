from smartrisk.indexer.analytics import LedgerAnalytics
from smartrisk.indexer.canonical import CanonicalBlock, CanonicalChain
from smartrisk.indexer.ledger import TransferLedger, TRANSFER_TOPIC
from tests.indexer.test_ledger import log


def test_holder_analytics_and_counterparty_graph():
    zero = "0x" + "0" * 40
    alice = "0x" + "a" * 40
    bob = "0x" + "b" * 40
    ledger = TransferLedger()
    ledger.ingest_logs("0x1", [log("0x1", 0, 1, zero, alice, 100), log("0x2", 0, 2, alice, bob, 20)])
    analytics = LedgerAnalytics(ledger)
    assert analytics.holder_concentration("0xtoken", 1) == 80 / 100
    assert analytics.velocity("0xtoken", 1, 2)["transfer_count"] == 2
    assert bob in analytics.counterparty_graph("0xtoken")[alice]
    assert analytics.deployer_flows("0xtoken", alice)["deployer_outflow"] == 20


def test_canonical_chain_rebuilds_after_reorg():
    zero = "0x" + "0" * 40
    alice = "0x" + "a" * 40
    bob = "0x" + "b" * 40
    chain = CanonicalChain("0x1")
    chain.ingest_block(CanonicalBlock(1, "h1", None, [log("t1", 0, 1, zero, alice, 100, block_hash="h1")]))
    chain.ingest_block(CanonicalBlock(2, "h2", "h1", [log("t2", 0, 2, alice, bob, 20, block_hash="h2")]))
    result = chain.ingest_block(CanonicalBlock(2, "h2b", "h1", [log("t2b", 0, 2, alice, bob, 5, block_hash="h2b")]))
    assert result["reorg"] is True
    assert chain.ledger.holder_snapshot("0xtoken")[bob] == 5

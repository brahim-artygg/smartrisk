from smartrisk.core.alchemy_gateway import AlchemyGateway
from smartrisk.core.evidence_store import SQLiteEvidenceStore


class FakeRpc:
    rpc_url = "https://alchemy.test"
    def request(self, method, params=None):
        return {"ok": True}


def test_gateway_persists_raw_evidence_and_latency(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "evidence.sqlite3", max_rows=100)
    gateway = AlchemyGateway(FakeRpc(), evidence_store=store)
    _, evidence = gateway.call("eth_chainId")
    saved = store.get(evidence.evidence_id)
    assert saved["method"] == "eth_chainId"
    assert saved["latency_ms"] is not None
    assert store.count() == 1

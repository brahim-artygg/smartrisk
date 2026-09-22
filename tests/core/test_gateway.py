from smartrisk.core.alchemy_gateway import AlchemyGateway
from smartrisk.core.models import AnalysisJob, RawAlchemyEvidence, UnifiedAnchor


class FakeRpc:
    rpc_url = "https://alchemy.test/v2/key"
    def __init__(self):
        self.calls = []
    def request(self, method, params=None):
        self.calls.append((method, params))
        return {"ok": True, "method": method}


def test_analysis_job_has_stable_contract_fields():
    anchor = UnifiedAnchor("0x1", 100, "0xblock", "0xparent", "safe", "safe", 123)
    job = AnalysisJob.create("0x1", "0xtoken", anchor=anchor)
    payload = job.to_dict()
    assert payload["anchor"]["block_hash"] == "0xblock"
    assert payload["policy_version"] == "unified-v0.1"


def test_gateway_records_raw_evidence_and_cache():
    rpc = FakeRpc()
    gateway = AlchemyGateway(rpc, cache_ttl_seconds=60)
    first, evidence = gateway.call("eth_getCode", ["0xtoken", "0x64"])
    second, cached_evidence = gateway.call("eth_getCode", ["0xtoken", "0x64"])
    assert first == second
    assert len(rpc.calls) == 1
    assert evidence.provider == "alchemy"
    assert evidence.params_hash == cached_evidence.params_hash
    assert len(gateway.evidence) == 2


def test_raw_evidence_hash_is_deterministic_for_params():
    a = RawAlchemyEvidence.create("eth_chainId", "a", [], "0x1")
    b = RawAlchemyEvidence.create("eth_chainId", "b", [], "0x1")
    assert a.params_hash == b.params_hash
    assert a.evidence_id != b.evidence_id


def test_gateway_exposes_state_transaction_and_metadata_methods():
    gateway = AlchemyGateway(FakeRpc())
    gateway.eth_call({"to": "0xtoken", "data": "0x"})
    gateway.get_storage_at("0xtoken", "0x0")
    gateway.get_transaction("0xtx")
    gateway.get_receipt("0xtx")
    gateway.get_token_metadata("0xtoken")
    gateway.get_asset_transfers({"fromBlock": "0x1", "toBlock": "0x2"})
    assert {item.method for item in gateway.evidence} == {
        "eth_call", "eth_getStorageAt", "eth_getTransactionByHash",
        "eth_getTransactionReceipt", "alchemy_getTokenMetadata", "alchemy_getAssetTransfers",
    }


class PagedRpc(FakeRpc):
    def __init__(self):
        super().__init__()
        self.page = 0
    def request(self, method, params=None):
        self.calls.append((method, params))
        if method == "alchemy_getAssetTransfers":
            self.page += 1
            return {"transfers": [{"hash": f"0x{self.page}"}], "pageKey": "next" if self.page == 1 else None}
        return {"ok": True}


def test_gateway_asset_transfer_pagination_and_cache_metrics():
    gateway = AlchemyGateway(PagedRpc(), cache_ttl_seconds=60, max_cache_entries=2)
    items, evidence, diagnostics = gateway.get_asset_transfers_all({"fromBlock": "0x1", "toBlock": "0x2"})
    assert len(items) == 2
    assert len(evidence) == 2
    assert diagnostics == []
    metrics = gateway.cache_metrics()
    assert metrics["misses"] == 2
    gateway.call("eth_chainId", [])
    gateway.call("eth_chainId", [])
    assert gateway.cache_metrics()["hits"] == 1


def test_gateway_exposes_block_and_trace_helpers():
    gateway = AlchemyGateway(FakeRpc())
    gateway.get_block_by_number(100)
    gateway.get_transaction_count("0xowner")
    gateway.get_trace("0xtx")
    methods = {item.method for item in gateway.evidence}
    assert {"eth_getBlockByNumber", "eth_getTransactionCount", "debug_traceTransaction"}.issubset(methods)

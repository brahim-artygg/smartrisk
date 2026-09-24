from smartrisk.heuristics.alchemy_source import AlchemySource
from smartrisk.heuristics.models import ChainAnchor


class BusyRpc:
    """Alchemy-like limits: max 10k logs per response, optional tiny block-range limit."""

    def __init__(self, logs_per_block, block_limit=None):
        self.calls = 0
        self.logs_per_block = logs_per_block
        self.block_limit = block_limit

    def request(self, method, params):
        self.calls += 1
        start, end = int(params[0]["fromBlock"], 16), int(params[0]["toBlock"], 16)
        width = end - start + 1
        if self.block_limit and width > self.block_limit:
            raise RuntimeError(f"you can make eth_getLogs requests with up to a {self.block_limit} block range")
        if width * self.logs_per_block > 10_000:
            raise RuntimeError("Log response size exceeded")
        return [{"blockNumber": hex(b)} for b in range(start, end + 1) for _ in range(self.logs_per_block)]


ANCHOR = ChainAnchor("0x1", 20_000_000, "0xblock", "safe")


def test_busy_token_is_capped_instead_of_scanning_everything(monkeypatch):
    monkeypatch.setenv("SMARTRISK_LOG_MAX_LOGS", "30000")
    rpc = BusyRpc(logs_per_block=130)
    result = AlchemySource(rpc).get_logs("0xt", ANCHOR, ANCHOR.block_number - 10_000, ANCHOR.block_number, max_chunk_blocks=2000)
    assert result.payload["truncated"] is True
    assert result.payload["truncation_reason"] == "max_logs"
    assert len(result.payload["logs"]) <= 30_000
    assert rpc.calls < 80  # previously ~290 sequential calls and 1.3M logs in memory


def test_small_token_is_not_truncated():
    rpc = BusyRpc(logs_per_block=1)
    result = AlchemySource(rpc).get_logs("0xt", ANCHOR, ANCHOR.block_number - 3_000, ANCHOR.block_number, max_chunk_blocks=1000)
    assert result.payload["truncated"] is False
    assert len(result.payload["logs"]) == 3_001


def test_provider_block_range_limit_is_learned_and_call_count_bounded(monkeypatch):
    monkeypatch.setenv("SMARTRISK_LOG_MAX_CALLS", "40")
    rpc = BusyRpc(logs_per_block=1, block_limit=10)
    result = AlchemySource(rpc).get_logs("0xt", ANCHOR, ANCHOR.block_number - 10_000, ANCHOR.block_number, max_chunk_blocks=1500)
    assert result.payload["truncated"] is True
    assert result.payload["truncation_reason"] == "max_calls"
    assert rpc.calls < 80  # previously ~2,500 calls on a 10-block-limit plan
    assert result.payload["logs"]  # newest blocks are kept

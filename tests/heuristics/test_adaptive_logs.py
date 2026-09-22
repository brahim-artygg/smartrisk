from smartrisk.heuristics.alchemy_source import AlchemySource
from smartrisk.heuristics.models import ChainAnchor


class Rpc:
    def __init__(self):
        self.calls = []

    def request(self, method, params):
        self.calls.append((method, params))
        start = int(params[0]["fromBlock"], 16)
        end = int(params[0]["toBlock"], 16)
        if end - start + 1 > 2:
            raise RuntimeError("range too wide")
        return [{"blockNumber": hex(block)} for block in range(start, end + 1)]


def test_get_logs_adapts_when_range_is_rejected():
    rpc = Rpc()
    source = AlchemySource(rpc)
    anchor = ChainAnchor("0x1", 10, "0xblock", "safe")
    result = source.get_logs("0xtoken", anchor, 1, 6, max_chunk_blocks=6)
    assert len(result.payload["logs"]) == 6
    assert any(int(params[0]["toBlock"], 16) - int(params[0]["fromBlock"], 16) + 1 == 1 for _, params in rpc.calls)

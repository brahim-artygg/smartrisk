from types import SimpleNamespace

from smartrisk.state_fork.engine import StateForkEngine
from smartrisk.state_fork.models import BlockAnchor, SimulationScenario, SimulationResult


ANCHOR = BlockAnchor("0x1", 100, "0xblock", "0xparent", 123, "safe")


class FakeRpc:
    rpc_url = "https://alchemy.test/v2/key"

    def capability_probe(self):
        return {"provider": "alchemy", "status": "ready", "chain_id": {"available": True}}

    def get_chain_id(self):
        return "0x1"

    def get_anchor(self, tag):
        return 100, {"number": "0x64", "hash": "0xblock", "parentHash": "0xparent", "timestamp": "0x7b"}


class FakeFork:
    def __init__(self):
        self.started = None
        self.stopped = False

    def start(self, upstream, anchor):
        self.started = (upstream, anchor)
        return "http://127.0.0.1:8545"

    def rpc_request(self, method, params=None):
        assert method == "eth_getBlockByNumber"
        return {"hash": "0xblock"}

    def run_scenario(self, scenario, anchor):
        return SimulationResult(scenario.scenario_id, "success", anchor, tx_hash="0xtx")

    def stop(self):
        self.stopped = True


def test_scenario_encodes_transaction_fields():
    scenario = SimulationScenario("transfer", "0xfrom", "0xto", "0x1234", 15, 21000)
    assert scenario.rpc_transaction() == {
        "from": "0xfrom",
        "to": "0xto",
        "data": "0x1234",
        "value": "0xf",
        "gas": "0x5208",
    }


def test_engine_anchors_and_runs_scenarios():
    fork = FakeFork()
    result = StateForkEngine(rpc=FakeRpc(), fork=fork).analyze([
        SimulationScenario("call-1", "0xfrom", "0xto")
    ], run_id="fork-test", block_tag="safe")
    assert result.status == "complete"
    assert result.anchor.block_hash == "0xblock"
    assert result.results[0].tx_hash == "0xtx"
    assert fork.started[0] == "https://alchemy.test/v2/key"
    assert fork.stopped is True


def test_missing_alchemy_is_unknown():
    class MissingRpc:
        rpc_url = None
        def capability_probe(self):
            return {"provider": "alchemy", "status": "unavailable"}

    result = StateForkEngine(rpc=MissingRpc(), fork=FakeFork()).analyze([])
    assert result.status == "unknown"
    assert result.unknown_reasons

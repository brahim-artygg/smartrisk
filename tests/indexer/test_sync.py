from smartrisk.core.alchemy_gateway import AlchemyGateway
from smartrisk.indexer.canonical import CanonicalChain
from smartrisk.indexer.ledger import TRANSFER_TOPIC
from smartrisk.indexer.sync import PollingChainIndexer


def log(tx, idx, block, from_addr, to_addr, amount, block_hash):
    return {
        "address": "0xtoken",
        "topics": [TRANSFER_TOPIC, "0x" + from_addr[2:].rjust(64, "0"), "0x" + to_addr[2:].rjust(64, "0")],
        "data": hex(amount), "blockNumber": hex(block), "blockHash": block_hash,
        "transactionHash": tx, "logIndex": hex(idx), "removed": False,
    }


class FakeRpc:
    rpc_url = "https://alchemy.test/v2/key"
    def __init__(self):
        zero = "0x" + "0" * 40
        self.blocks = {
            1: {"number": "0x1", "hash": "h1", "parentHash": None},
            2: {"number": "0x2", "hash": "h2", "parentHash": "h1"},
            3: {"number": "0x3", "hash": "h3", "parentHash": "h2"},
        }
        self.logs = {
            1: [log("t1", 0, 1, zero, "0x" + "a"*40, 100, "h1")],
            2: [log("t2", 0, 2, "0x" + "a"*40, "0x" + "b"*40, 20, "h2")],
            3: [],
        }
        self.latest = 3

    def request(self, method, params=None):
        if method == "eth_getBlockByNumber":
            tag = params[0]
            if tag == "latest":
                return self.blocks[self.latest]
            number = int(tag, 16)
            return self.blocks[number]
        if method == "eth_getLogs":
            return self.logs.get(int(params[0]["fromBlock"], 16), [])
        return None


def test_polling_indexer_backfills_and_builds_canonical_ledger():
    rpc = FakeRpc()
    gateway = AlchemyGateway(rpc)
    chain = CanonicalChain("0x1")
    indexer = PollingChainIndexer(gateway, chain, "0xtoken", reorg_window=2)
    result = indexer.sync_once(from_block=1)
    assert result.status == "complete"
    assert result.processed_blocks == 3
    holders = chain.ledger.holder_snapshot("0xtoken")
    assert holders["0x" + "a"*40] == 80
    assert holders["0x" + "b"*40] == 20


def test_polling_indexer_reconciles_same_height_reorg():
    rpc = FakeRpc()
    gateway = AlchemyGateway(rpc)
    chain = CanonicalChain("0x1")
    indexer = PollingChainIndexer(gateway, chain, "0xtoken", reorg_window=3)
    indexer.sync_once(from_block=1)
    alice = "0x" + "a"*40
    bob = "0x" + "b"*40
    rpc.blocks[2] = {"number": "0x2", "hash": "h2b", "parentHash": "h1"}
    rpc.blocks[3] = {"number": "0x3", "hash": "h3b", "parentHash": "h2b"}
    rpc.logs[2] = [log("t2b", 0, 2, alice, bob, 5, "h2b")]
    rpc.logs[3] = []
    result = indexer.sync_once()
    assert result.reorgs >= 1
    assert chain.head == "h3b"
    assert chain.ledger.holder_snapshot("0xtoken")[bob] == 5

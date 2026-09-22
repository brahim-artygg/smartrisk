import asyncio
import json

import pytest

from smartrisk.indexer.websocket import ChainHead, ChainWebSocketSubscriber


def test_parse_new_head():
    head = ChainWebSocketSubscriber._parse_head({"number": "0x2a", "hash": "0xabc", "parentHash": "0xdef", "timestamp": "0x10"})
    assert isinstance(head, ChainHead)
    assert head.number == 42
    assert head.block_hash == "0xabc"
    assert head.timestamp == 16


def test_parse_invalid_head_returns_none():
    assert ChainWebSocketSubscriber._parse_head({"hash": "0xabc"}) is None

@pytest.mark.asyncio
async def test_subscriber_rejects_missing_urls():
    subscriber = ChainWebSocketSubscriber([])
    with pytest.raises(Exception):
        await subscriber.run_forever(lambda *_: None)


@pytest.mark.asyncio
async def test_subscriber_receives_new_head_from_real_websocket_server():
    websockets = pytest.importorskip("websockets")
    from websockets.asyncio.server import serve

    received = []
    subscriber = ChainWebSocketSubscriber([("test", "ws://127.0.0.1:0")])

    async def handler(ws):
        request = json.loads(await ws.recv())
        assert request["method"] == "eth_subscribe"
        await ws.send(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": "sub-1"}))
        await ws.send(json.dumps({"jsonrpc": "2.0", "method": "eth_subscription", "params": {
            "subscription": "sub-1", "result": {"number": "0x2a", "hash": "0xabc", "parentHash": "0xdef"}
        }}))
        await asyncio.sleep(0.05)

    async with serve(handler, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        subscriber.ws_urls = [("test", f"ws://127.0.0.1:{port}")]

        async def callback(head, provider):
            received.append((head.number, provider))
            subscriber.stop()

        await asyncio.wait_for(subscriber.run_forever(callback), timeout=2)

    assert received == [(42, "test")]
    assert subscriber.metrics.messages >= 1


@pytest.mark.asyncio
async def test_subscriber_fails_over_to_next_provider(monkeypatch):
    import smartrisk.indexer.websocket as module

    attempts = []

    class FakeContext:
        def __init__(self, provider, should_fail=False):
            self.provider = provider
            self.should_fail = should_fail

        async def __aenter__(self):
            attempts.append(self.provider)
            if self.should_fail:
                raise OSError(f"{self.provider} unavailable")
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def send(self, payload):
            self.payload = json.loads(payload)

        async def recv(self):
            return json.dumps({"jsonrpc": "2.0", "id": self.payload["id"], "result": "sub-2"})

        def __aiter__(self):
            async def iterator():
                yield json.dumps({"jsonrpc": "2.0", "method": "eth_subscription", "params": {
                    "subscription": "sub-2", "result": {"number": "0x2b", "hash": "0xbeef"}
                }})
            return iterator()

    def fake_connect(url, **kwargs):
        provider = "primary" if "primary" in url else "secondary"
        return FakeContext(provider, should_fail=(provider == "primary"))

    monkeypatch.setattr(module, "connect", fake_connect)
    subscriber = ChainWebSocketSubscriber([
        ("primary", "wss://primary.test"),
        ("secondary", "wss://secondary.test"),
    ], reconnect_initial=0.001, reconnect_max=0.002)
    received = []

    async def callback(head, provider):
        received.append((head.number, provider))
        subscriber.stop()

    await asyncio.wait_for(subscriber.run_forever(callback), timeout=1)
    assert attempts[:2] == ["primary", "secondary"]
    assert received == [(43, "secondary")]
    assert subscriber.metrics.errors >= 1

from __future__ import annotations

import asyncio
import inspect
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable

try:
    from websockets.asyncio.client import connect
    from websockets.exceptions import ConnectionClosed
except ImportError:  # pragma: no cover - exercised when optional dependency is absent
    connect = None  # type: ignore[assignment]
    ConnectionClosed = Exception  # type: ignore[assignment,misc]


class WebSocketUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class ChainHead:
    number: int
    block_hash: str
    parent_hash: str | None
    timestamp: int | None = None


@dataclass
class WebSocketMetrics:
    connections: int = 0
    reconnects: int = 0
    messages: int = 0
    malformed: int = 0
    errors: int = 0
    last_provider: str | None = None
    last_error: str | None = None
    last_head: ChainHead | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "connections": self.connections,
            "reconnects": self.reconnects,
            "messages": self.messages,
            "malformed": self.malformed,
            "errors": self.errors,
            "last_provider": self.last_provider,
            "last_error": self.last_error,
            "last_head": self.last_head.__dict__ if self.last_head else None,
        }


class ChainWebSocketSubscriber:
    """Reconnectable eth_subscribe(newHeads) consumer.

    The websocket is an acceleration path for head notifications; canonical
    correctness still comes from RPC backfill/reconciliation in the indexer.
    """

    def __init__(
        self,
        ws_urls: Iterable[tuple[str, str | None]],
        *,
        reconnect_initial: float = 0.5,
        reconnect_max: float = 15.0,
        ping_interval: float = 20.0,
        max_size: int = 1_048_576,
        auth_headers: dict[str, str] | None = None,
    ):
        self.ws_urls = [(name, url) for name, url in ws_urls if url]
        self.reconnect_initial = max(0.1, reconnect_initial)
        self.reconnect_max = max(self.reconnect_initial, reconnect_max)
        self.ping_interval = ping_interval
        self.max_size = max_size
        self.auth_headers = auth_headers or {}
        self.metrics = WebSocketMetrics()
        self._stop = asyncio.Event()

    def stop(self) -> None:
        self._stop.set()

    async def run_forever(self, on_head: Callable[[ChainHead, str], Awaitable[None] | None]) -> None:
        if connect is None:
            raise WebSocketUnavailable("install smartrisk[realtime] to enable WebSocket transport")
        if not self.ws_urls:
            raise WebSocketUnavailable("no WebSocket provider URLs configured")

        delay = self.reconnect_initial
        provider_index = 0
        while not self._stop.is_set():
            name, url = self.ws_urls[provider_index % len(self.ws_urls)]
            self.metrics.last_provider = name
            try:
                async with connect(
                    url,
                    additional_headers=self.auth_headers or None,
                    ping_interval=self.ping_interval,
                    max_size=self.max_size,
                    open_timeout=10,
                    close_timeout=10,
                ) as websocket:
                    self.metrics.connections += 1
                    await websocket.send(json.dumps({"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": "eth_subscribe", "params": ["newHeads"]}))
                    subscription = json.loads(await websocket.recv())
                    if subscription.get("error"):
                        raise WebSocketUnavailable(str(subscription["error"]))
                    subscription_id = subscription.get("result")
                    if not subscription_id:
                        raise WebSocketUnavailable("provider did not return a subscription id")
                    delay = self.reconnect_initial
                    async for raw in websocket:
                        self.metrics.messages += 1
                        try:
                            payload = json.loads(raw)
                            params = payload.get("params") or {}
                            if payload.get("method") != "eth_subscription" or params.get("subscription") != subscription_id:
                                continue
                            result = params.get("result") or {}
                            head = self._parse_head(result)
                            if head is None:
                                self.metrics.malformed += 1
                                continue
                            self.metrics.last_head = head
                            callback_result = on_head(head, name)
                            if inspect.isawaitable(callback_result):
                                await callback_result
                        except (TypeError, ValueError, json.JSONDecodeError):
                            self.metrics.malformed += 1
                    self.metrics.reconnects += 1
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.metrics.errors += 1
                self.metrics.last_error = str(exc)
                self.metrics.reconnects += 1
                provider_index += 1
                if not self._stop.is_set():
                    try:
                        await asyncio.wait_for(self._stop.wait(), timeout=delay)
                    except asyncio.TimeoutError:
                        pass
                delay = min(self.reconnect_max, delay * 2)

    def run_sync(self, on_head: Callable[[ChainHead, str], Awaitable[None] | None]) -> None:
        asyncio.run(self.run_forever(on_head))

    @staticmethod
    def _parse_head(payload: dict[str, Any]) -> ChainHead | None:
        if not isinstance(payload, dict) or not payload.get("number") or not payload.get("hash"):
            return None
        try:
            number = int(str(payload["number"]), 16)
            timestamp = int(str(payload["timestamp"]), 16) if payload.get("timestamp") else None
        except (TypeError, ValueError):
            return None
        return ChainHead(number, str(payload["hash"]), str(payload.get("parentHash")) if payload.get("parentHash") else None, timestamp)


class ReorgAwareRealtimeIndexer:
    """Bridge WebSocket newHeads into the existing canonical backfill engine."""

    def __init__(self, subscriber: ChainWebSocketSubscriber, indexer: Any, reorg_window: int = 12):
        self.subscriber = subscriber
        self.indexer = indexer
        self.reorg_window = max(1, reorg_window)
        self.last_sync: dict[str, Any] | None = None

    async def on_head(self, head: ChainHead, provider_name: str) -> None:
        start = max(0, head.number - self.reorg_window + 1)
        result = self.indexer.sync_once(from_block=start, to_block=head.number)
        self.last_sync = result.to_dict() if hasattr(result, "to_dict") else dict(result)
        self.last_sync["websocket_provider"] = provider_name
        self.last_sync["received_head_hash"] = head.block_hash

    async def run(self) -> None:
        await self.subscriber.run_forever(self.on_head)

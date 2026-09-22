from __future__ import annotations

import json
import os
import random
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from .networks import get_network, supported_networks


class ProviderError(RuntimeError):
    pass


class ProviderUnavailable(ProviderError):
    pass


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    rpc_url: str
    ws_url: str | None = None
    enabled: bool = True
    priority: int = 100

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProviderHealth:
    name: str
    failures: int = 0
    successes: int = 0
    requests: int = 0
    failovers: int = 0
    open_until: float = 0.0
    method_unavailable_until: dict[str, float] = field(default_factory=dict)
    last_error: str | None = None
    last_latency_ms: float | None = None
    total_latency_ms: float = 0.0

    @property
    def available(self) -> bool:
        return time.monotonic() >= self.open_until

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["available"] = self.available
        payload["error_rate"] = self.failures / self.requests if self.requests else 0.0
        payload["avg_latency_ms"] = self.total_latency_ms / self.successes if self.successes else None
        payload["method_unavailable"] = {k: round(max(0.0, v - time.monotonic()), 3) for k, v in self.method_unavailable_until.items() if v > time.monotonic()}
        return payload


class JsonRpcHttpProvider:
    """Dependency-free JSON-RPC provider used by MultiProviderRpc."""

    provider_name = "rpc"

    def __init__(self, spec: ProviderSpec, timeout_seconds: float = 20.0, retries: int = 1):
        self.spec = spec
        self.timeout_seconds = max(0.5, timeout_seconds)
        self.retries = max(0, retries)
        self.rpc_url = spec.rpc_url
        self.provider_name = spec.name

    def request(self, method: str, params: list[Any] | None = None) -> Any:
        body = json.dumps(
            {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method, "params": params or []},
            separators=(",", ":"),
        ).encode()
        request = urllib.request.Request(
            self.rpc_url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "smartrisk-rpc-router/0.9"},
            method="POST",
        )
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                if payload.get("error"):
                    error = payload["error"]
                    code = error.get("code") if isinstance(error, dict) else None
                    raise ProviderError(f"{method}: {error}") from None
                return payload.get("result")
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ProviderError) as exc:
                last_error = exc
                if isinstance(exc, ProviderError) and not MultiProviderRpc.is_retryable_error(exc):
                    raise
                if attempt < self.retries:
                    time.sleep(min(0.2 * (2**attempt) + random.random() * 0.05, 1.5))
        raise ProviderUnavailable(f"{self.provider_name}: {method} failed after retries: {last_error}")


class MultiProviderRpc:
    """RPC router with health tracking, circuit breakers and deterministic failover.

    It preserves a preferred provider but fails over on transient transport / rate-limit
    / provider-availability errors. Non-transient JSON-RPC application errors remain
    visible to the caller instead of being silently retried elsewhere.
    """

    def __init__(
        self,
        providers: list[ProviderSpec | JsonRpcHttpProvider],
        failure_threshold: int = 2,
        cool_down_seconds: float = 15.0,
        timeout_seconds: float = 20.0,
        retries_per_provider: int = 1,
        expected_chain_id: str | int | None = None,
    ):
        normalized: list[Any] = []
        for provider in providers:
            if isinstance(provider, ProviderSpec):
                normalized.append(JsonRpcHttpProvider(provider, timeout_seconds, retries_per_provider))
            elif hasattr(provider, "request") and hasattr(provider, "rpc_url") and hasattr(provider, "provider_name"):
                if not hasattr(provider, "spec"):
                    provider.spec = ProviderSpec(provider.provider_name, provider.rpc_url, getattr(provider, "ws_url", None))
                normalized.append(provider)
            else:
                raise TypeError("provider must be ProviderSpec or expose provider_name, rpc_url and request()")
        self.providers = [item for item in normalized if item.spec.enabled]
        self.failure_threshold = max(1, failure_threshold)
        self.cool_down_seconds = max(0.5, cool_down_seconds)
        self._health = {item.provider_name: ProviderHealth(item.provider_name) for item in self.providers}
        self._lock = threading.RLock()
        self._preferred_index = 0
        self.expected_chain_id = str(int(str(expected_chain_id), 16) if isinstance(expected_chain_id, str) and str(expected_chain_id).lower().startswith("0x") else int(expected_chain_id)) if expected_chain_id is not None else None
        self.last_provider: str | None = None
        self.last_failover_from: str | None = None
        self.failover_count = 0
        if not self.providers:
            raise ProviderUnavailable("no enabled RPC providers configured")

    @property
    def provider_name(self) -> str:
        return self.last_provider or self.providers[self._preferred_index].provider_name

    @property
    def rpc_url(self) -> str:
        return self.providers[self._preferred_index].rpc_url

    @property
    def ws_url(self) -> str | None:
        provider = self._choose_provider()
        return provider.spec.ws_url

    def request(self, method: str, params: list[Any] | None = None) -> Any:
        errors: list[str] = []
        ordered = self._ordered_indices()
        for position, index in enumerate(ordered):
            provider = self.providers[index]
            health = self._health[provider.provider_name]
            now = time.monotonic()
            if now < health.open_until or health.method_unavailable_until.get(method, 0.0) > now:
                continue
            health.requests += 1
            started = time.perf_counter()
            try:
                result = provider.request(method, params)
                elapsed = (time.perf_counter() - started) * 1000
                with self._lock:
                    health.successes += 1
                    health.failures = 0
                    health.open_until = 0.0
                    health.last_error = None
                    health.last_latency_ms = round(elapsed, 3)
                    health.total_latency_ms += elapsed
                    old_provider = self.last_provider
                    self.last_provider = provider.provider_name
                    if old_provider and old_provider != provider.provider_name:
                        health.failovers += 1
                if position > 0:
                    with self._lock:
                        self.last_failover_from = old_provider
                        self.failover_count += 1
                        self._preferred_index = index
                else:
                    with self._lock:
                        self._preferred_index = index
                return result
            except Exception as exc:
                elapsed = (time.perf_counter() - started) * 1000
                health.failures += 1
                health.last_error = str(exc)
                health.last_latency_ms = round(elapsed, 3)
                errors.append(f"{provider.provider_name}: {exc}")
                if self.is_method_capability_error(exc):
                    health.method_unavailable_until[method] = time.monotonic() + self.cool_down_seconds * 4
                    continue
                if self.is_retryable_error(exc):
                    if health.failures >= self.failure_threshold:
                        health.open_until = time.monotonic() + self.cool_down_seconds
                    continue
                raise
        raise ProviderUnavailable(f"all RPC providers failed for {method}: {' | '.join(errors)}")

    def _choose_provider(self) -> JsonRpcHttpProvider:
        for index in self._ordered_indices():
            provider = self.providers[index]
            if self._health[provider.provider_name].available:
                return provider
        return self.providers[self._preferred_index]

    def _ordered_indices(self) -> list[int]:
        with self._lock:
            start = self._preferred_index
        return [(start + offset) % len(self.providers) for offset in range(len(self.providers))]

    @staticmethod
    def is_method_capability_error(exc: Exception) -> bool:
        text = str(exc).lower()
        return "-32601" in text or "method not found" in text or "not supported" in text

    @staticmethod
    def is_retryable_error(exc: Exception) -> bool:
        text = str(exc).lower()
        if any(marker in text for marker in ("429", "rate limit", "timeout", "timed out", "temporarily unavailable", "connection reset", "connection refused", "502", "503", "504", "gateway")):
            return True
        if isinstance(exc, (ProviderUnavailable, urllib.error.URLError, TimeoutError)):
            return True
        # Provider-side method capability errors can be retried against another
        # provider because archive/debug methods differ across plans.
        if "-32601" in text or "method not found" in text or "not supported" in text:
            return True
        return False

    def websocket_urls(self) -> list[tuple[str, str]]:
        return [(item.provider_name, item.spec.ws_url) for item in self.providers if item.spec.ws_url]

    def health(self) -> dict[str, Any]:
        return {
            "selected_provider": self.last_provider,
            "preferred_provider": self.providers[self._preferred_index].provider_name,
            "failover_count": self.failover_count,
            "providers": [self._health[item.provider_name].to_dict() | {"spec": item.spec.to_dict()} for item in self.providers],
        }

    def capability_probe(self) -> dict[str, Any]:
        result: dict[str, Any] = {"status": "unknown", "providers": [], "router": self.health()}
        for provider in self.providers:
            item: dict[str, Any] = {"provider": provider.provider_name, "rpc_url_configured": bool(provider.rpc_url), "status": "unavailable"}
            try:
                chain_id = provider.request("eth_chainId", [])
                item["chain_id"] = chain_id
                actual_chain_id = int(str(chain_id), 16) if isinstance(chain_id, str) and chain_id.lower().startswith("0x") else int(chain_id)
                if self.expected_chain_id is not None and actual_chain_id != int(self.expected_chain_id):
                    item["status"] = "chain_mismatch"
                    item["expected_chain_id"] = self.expected_chain_id
                    item["error"] = f"provider chain {actual_chain_id} does not match expected chain {self.expected_chain_id}"
                    result["providers"].append(item)
                    continue
                latest = provider.request("eth_getBlockByNumber", ["latest", False])
                item["latest_block"] = latest.get("number") if isinstance(latest, dict) else None
                item["status"] = "ready"
            except Exception as exc:
                item["error"] = str(exc)
            result["providers"].append(item)
        result["status"] = "ready" if any(item["status"] == "ready" for item in result["providers"]) else "unavailable"
        return result

    @classmethod
    def from_environment(cls, chain: str = "eth-mainnet", **kwargs: Any) -> "MultiProviderRpc":
        profile = get_network(chain)
        providers: list[ProviderSpec] = []
        # Preserve explicit legacy environment variables first.
        explicit_rpc = os.getenv("ALCHEMY_RPC_URL") if profile.key == "ethereum" else None
        explicit_ws = os.getenv("ALCHEMY_WS_URL") if profile.key == "ethereum" else None
        alchemy_key = os.getenv("ALCHEMY_API_KEY")
        network_rpc = os.getenv(f"SMARTRISK_{profile.key.upper()}_RPC_URL")
        network_ws = os.getenv(f"SMARTRISK_{profile.key.upper()}_WS_URL")
        alchemy_url = network_rpc or explicit_rpc
        ws = network_ws or explicit_ws
        if not alchemy_url and alchemy_key:
            alchemy_url = f"https://{profile.rpc_chain}.g.alchemy.com/v2/{alchemy_key}"
            ws = ws or f"wss://{profile.rpc_chain}.g.alchemy.com/v2/{alchemy_key}"
        if alchemy_url:
            providers.append(ProviderSpec("alchemy", alchemy_url, ws, priority=10))

        quicknode_url = (os.getenv("QUICKNODE_RPC_URL") if profile.key == "ethereum" else None) or os.getenv(f"SMARTRISK_{profile.key.upper()}_QUICKNODE_RPC_URL")
        quicknode_ws = (os.getenv("QUICKNODE_WS_URL") if profile.key == "ethereum" else None) or os.getenv(f"SMARTRISK_{profile.key.upper()}_QUICKNODE_WS_URL")
        chainstack_url = (os.getenv("CHAINSTACK_RPC_URL") if profile.key == "ethereum" else None) or os.getenv(f"SMARTRISK_{profile.key.upper()}_CHAINSTACK_RPC_URL")
        chainstack_ws = (os.getenv("CHAINSTACK_WS_URL") if profile.key == "ethereum" else None) or os.getenv(f"SMARTRISK_{profile.key.upper()}_CHAINSTACK_WS_URL")
        if chainstack_url:
            providers.append(ProviderSpec("chainstack", chainstack_url, chainstack_ws, priority=20))
        if quicknode_url:
            providers.append(ProviderSpec("quicknode", quicknode_url, quicknode_ws, priority=30))
        if not providers:
            raise ProviderUnavailable(
                f"no RPC providers configured for {profile.name}; configure ALCHEMY_API_KEY/ALCHEMY_RPC_URL or network-specific SMARTRISK_{profile.key.upper()}_RPC_URL"
            )
        providers.sort(key=lambda item: (item.priority, item.name))
        return cls(providers, expected_chain_id=profile.chain_id, **kwargs)

    @classmethod
    def supported_networks(cls) -> list[dict[str, Any]]:
        return [profile.to_dict() for profile in supported_networks()]

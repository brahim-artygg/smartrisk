from __future__ import annotations

import hashlib
import json
import time
import threading
import uuid
from collections import deque
from typing import Any

from ..state_fork.alchemy_rpc import AlchemyRpcClient
from .evidence_store import SQLiteEvidenceStore
from .models import RawAlchemyEvidence


class AlchemyGateway:
    """Shared Alchemy boundary: cache, raw evidence, capability probes and RPC helpers."""

    def __init__(self, rpc: AlchemyRpcClient | None = None, cache_ttl_seconds: int = 30, max_cache_entries: int = 2048, evidence_store: SQLiteEvidenceStore | None = None):
        self.rpc = rpc or AlchemyRpcClient()
        self.cache_ttl_seconds = cache_ttl_seconds
        self.evidence_store = evidence_store
        self.max_cache_entries = max(1, max_cache_entries)
        self.cache_hits = 0
        self.cache_misses = 0
        self.request_count = 0
        self._cache: dict[str, tuple[float, Any, RawAlchemyEvidence]] = {}
        self._lock = threading.RLock()
        # Bounded: this gateway is long-lived; an unbounded list retained every raw response forever.
        self.evidence: deque[RawAlchemyEvidence] = deque(maxlen=512)
        self.rate_limit_events = 0
        self.trace_calls = 0
        self.trace_successes = 0

    def call(self, method: str, params: list[Any] | None = None, anchor: Any | None = None, use_cache: bool = True) -> tuple[Any, RawAlchemyEvidence]:
        params = params or []
        key = hashlib.sha256(json.dumps([method, params], sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
        with self._lock:
            cached = self._cache.get(key) if use_cache else None
        if use_cache and cached and time.time() - cached[0] <= self.cache_ttl_seconds:
            self.cache_hits += 1
            result = cached[1]
            evidence = RawAlchemyEvidence.create(method, str(uuid.uuid4()), params, result, provider=getattr(cached[2], "provider", "alchemy"), chain_id=getattr(anchor, "chain_id", None), block_number=getattr(anchor, "block_number", None), block_hash=getattr(anchor, "block_hash", None), latency_ms=0.0)
            self.evidence.append(evidence)
            if self.evidence_store is not None:
                self.evidence_store.put(evidence)
            return result, evidence
        self.cache_misses += 1
        self.request_count += 1
        request_id = str(uuid.uuid4())
        started = time.perf_counter()
        try:
            if method in {"debug_traceTransaction", "trace_transaction", "debug_traceCall"}:
                self.trace_calls += 1
            result = self.rpc.request(method, params)
            if method in {"debug_traceTransaction", "trace_transaction", "debug_traceCall"}:
                self.trace_successes += 1
            # Large log payloads are summarised in evidence and not cached: keeping every raw
            # eth_getLogs response in memory is what OOM-kills the container on busy tokens.
            bulky = method == "eth_getLogs" and isinstance(result, list) and len(result) > 100
            stored = {"summarized": True, "log_count": len(result)} if bulky else result
            evidence = RawAlchemyEvidence.create(method, request_id, params, stored, provider=getattr(self.rpc, "last_provider", getattr(self.rpc, "provider_name", "alchemy")), chain_id=getattr(anchor, "chain_id", None), block_number=getattr(anchor, "block_number", None), block_hash=getattr(anchor, "block_hash", None), latency_ms=round((time.perf_counter() - started) * 1000, 3))
            if not bulky:
                with self._lock:
                    self._cache[key] = (time.time(), result, evidence)
                    if len(self._cache) > self.max_cache_entries:
                        oldest_key = min(self._cache, key=lambda item: self._cache[item][0])
                        self._cache.pop(oldest_key, None)
            self.evidence.append(evidence)
            if self.evidence_store is not None:
                self.evidence_store.put(evidence)
            return result, evidence
        except Exception as exc:
            if "429" in str(exc) or "rate" in str(exc).lower():
                self.rate_limit_events += 1
            evidence = RawAlchemyEvidence.create(method, request_id, params, None, provider=getattr(self.rpc, "last_provider", getattr(self.rpc, "provider_name", "alchemy")), chain_id=getattr(anchor, "chain_id", None), block_number=getattr(anchor, "block_number", None), block_hash=getattr(anchor, "block_hash", None), error=str(exc), latency_ms=round((time.perf_counter() - started) * 1000, 3))
            self.evidence.append(evidence)
            if self.evidence_store is not None:
                self.evidence_store.put(evidence)
            raise

    def eth_call(self, transaction: dict[str, Any], block: str = "latest", state_override: dict[str, Any] | None = None, anchor: Any | None = None) -> tuple[Any, RawAlchemyEvidence]:
        params: list[Any] = [transaction, block]
        if state_override is not None:
            params.append(state_override)
        return self.call("eth_call", params, anchor)

    def get_storage_at(self, address: str, slot: str, block: str = "latest", anchor: Any | None = None):
        return self.call("eth_getStorageAt", [address, slot, block], anchor)

    def get_transaction(self, tx_hash: str, anchor: Any | None = None):
        return self.call("eth_getTransactionByHash", [tx_hash], anchor)

    def get_receipt(self, tx_hash: str, anchor: Any | None = None):
        return self.call("eth_getTransactionReceipt", [tx_hash], anchor)


    def get_block_by_number(self, block: str | int = "latest", full_transactions: bool = False, anchor: Any | None = None, fresh: bool = False):
        block_tag = hex(block) if isinstance(block, int) else block
        return self.call("eth_getBlockByNumber", [block_tag, full_transactions], anchor, use_cache=not fresh)

    def get_block_receipts(self, block: str | int, anchor: Any | None = None):
        block_tag = hex(block) if isinstance(block, int) else block
        return self.call("eth_getBlockReceipts", [block_tag], anchor)

    def get_logs(self, params: dict[str, Any], anchor: Any | None = None, fresh: bool = False):
        return self.call("eth_getLogs", [params], anchor, use_cache=not fresh)

    def get_transaction_count(self, address: str, block: str = "latest", anchor: Any | None = None):
        return self.call("eth_getTransactionCount", [address, block], anchor)

    def get_trace(self, tx_hash: str, tracer: str = "callTracer", anchor: Any | None = None):
        method = "debug_traceTransaction"
        return self.call(method, [tx_hash, {"tracer": tracer}], anchor)

    def get_token_metadata(self, token_address: str, anchor: Any | None = None):
        return self.call("alchemy_getTokenMetadata", [token_address], anchor)

    def get_asset_transfers(self, params: dict[str, Any], anchor: Any | None = None):
        return self.call("alchemy_getAssetTransfers", [params], anchor)

    @classmethod
    def from_environment(cls, chain: str = "eth-mainnet", **kwargs: Any) -> "AlchemyGateway":
        from .multi_provider import MultiProviderRpc
        return cls(MultiProviderRpc.from_environment(chain, **kwargs))

    def provider_health(self) -> dict[str, Any]:
        health = getattr(self.rpc, "health", None)
        return health() if callable(health) else {"selected_provider": getattr(self.rpc, "provider_name", "alchemy")}

    def capability_matrix(self, archive_probe_block: int | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {
            "provider": getattr(self.rpc, "provider_name", "alchemy"), "status": "unavailable", "checks": {},
            "limits": {"rate_limit_events": self.rate_limit_events},
        }
        if not self.rpc.rpc_url:
            return result
        checks = {
            "chain_id": ("eth_chainId", []),
            "safe": ("eth_getBlockByNumber", ["safe", False]),
            "finalized": ("eth_getBlockByNumber", ["finalized", False]),
            "latest": ("eth_getBlockByNumber", ["latest", False]),
            "logs": ("eth_getLogs", [{"fromBlock": "latest", "toBlock": "latest"}]),
            "storage": ("eth_getStorageAt", ["0x0000000000000000000000000000000000000000", "0x0", "latest"]),
            "transaction_by_hash": ("eth_getTransactionByHash", ["0x" + "0" * 64]),
            "receipt": ("eth_getTransactionReceipt", ["0x" + "0" * 64]),
            "eth_call": ("eth_call", [{"to": "0x0000000000000000000000000000000000000000", "data": "0x"}, "latest"]),
            "state_override": ("eth_call", [{"to": "0x0000000000000000000000000000000000000000", "data": "0x"}, "latest", {}]),
            "asset_transfers": ("alchemy_getAssetTransfers", [{"fromBlock": "latest", "toBlock": "latest", "category": ["external"], "maxCount": "0x1"}]),
            "token_balances": ("alchemy_getTokenBalances", ["0x0000000000000000000000000000000000000000", "erc20"]),
            "token_metadata": ("alchemy_getTokenMetadata", ["0x0000000000000000000000000000000000000000"]),
        }
        for name, (method, params) in checks.items():
            try:
                value, _ = self.call(method, params)
                checks_result = {"available": value is not None}
                if method in {"eth_getTransactionByHash", "eth_getTransactionReceipt"} and value is None:
                    checks_result["status"] = "not_found_valid_probe"
                result["checks"][name] = checks_result
            except Exception as exc:
                result["checks"][name] = {"available": False, "error": str(exc)}
        if archive_probe_block is None:
            result["checks"]["archive"] = {"available": None, "status": "not_probed", "reason": "provide archive_probe_block for a historical probe"}
        else:
            try:
                value, _ = self.call("eth_getBlockByNumber", [hex(archive_probe_block), False])
                result["checks"]["archive"] = {"available": value is not None, "probe_block": archive_probe_block}
            except Exception as exc:
                result["checks"]["archive"] = {"available": False, "probe_block": archive_probe_block, "error": str(exc)}
        result["checks"]["websocket"] = {"available": None, "status": "not_probed", "reason": "WebSocket requires a dedicated connection probe"}
        trace_checks = {}
        for name, method, params in (("debug_traceTransaction", "debug_traceTransaction", ["0x" + "0" * 64, {"tracer": "callTracer"}]), ("trace_transaction", "trace_transaction", ["0x" + "0" * 64])):
            try:
                value, _ = self.call(method, params)
                trace_checks[name] = {"available": value is not None}
            except Exception as exc:
                trace_checks[name] = {"available": False, "error": str(exc)}
        result["checks"]["trace"] = trace_checks
        result["trace_coverage"] = {"attempts": self.trace_calls, "successes": self.trace_successes, "ratio": self.trace_successes / self.trace_calls if self.trace_calls else None}
        result["cache"] = self.cache_metrics()
        result["provider_health"] = self.provider_health()
        result["limits"]["rate_limit_events"] = self.rate_limit_events
        result["status"] = "ready" if result["checks"].get("chain_id", {}).get("available") else "unavailable"
        return result

    def get_token_balances(self, owner: str, contract_addresses: list[str] | None = None, anchor: Any | None = None):
        params: list[Any] = [owner, contract_addresses or "erc20"]
        return self.call("alchemy_getTokenBalances", params, anchor)

    def get_asset_transfers_page(self, params: dict[str, Any], anchor: Any | None = None):
        return self.call("alchemy_getAssetTransfers", [dict(params)], anchor)

    def get_asset_transfers_all(
        self, params: dict[str, Any], anchor: Any | None = None, max_pages: int = 50
    ) -> tuple[list[Any], list[RawAlchemyEvidence], list[str]]:
        page_params = dict(params)
        items: list[Any] = []
        evidence: list[RawAlchemyEvidence] = []
        diagnostics: list[str] = []
        for _ in range(max(1, max_pages)):
            try:
                result, ev = self.get_asset_transfers_page(page_params, anchor)
            except Exception as exc:
                diagnostics.append(str(exc))
                break
            evidence.append(ev)
            if not isinstance(result, dict):
                diagnostics.append("alchemy_getAssetTransfers returned a non-object response")
                break
            transfers = result.get("transfers") or []
            if isinstance(transfers, list):
                items.extend(transfers)
            page_key = result.get("pageKey")
            if not page_key:
                break
            page_params["pageKey"] = page_key
        else:
            diagnostics.append(f"asset transfer pagination capped at {max_pages} pages")
        return items, evidence, diagnostics

    def cache_metrics(self) -> dict[str, Any]:
        total = self.cache_hits + self.cache_misses
        with self._lock:
            entries = len(self._cache)
        return {
            "entries": entries,
            "max_entries": self.max_cache_entries,
            "ttl_seconds": self.cache_ttl_seconds,
            "hits": self.cache_hits,
            "misses": self.cache_misses,
            "hit_ratio": self.cache_hits / total if total else None,
            "requests": self.request_count,
            "rate_limit_events": self.rate_limit_events,
        }

    def raw_evidence_dicts(self) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self.evidence]

    def evidence_metrics(self) -> dict[str, Any]:
        latencies = [item.latency_ms for item in self.evidence if item.latency_ms is not None]
        errors = sum(1 for item in self.evidence if item.error)
        return {
            "evidence_count": len(self.evidence),
            "error_count": errors,
            "avg_latency_ms": round(sum(latencies) / len(latencies), 3) if latencies else None,
            "max_latency_ms": round(max(latencies), 3) if latencies else None,
        }

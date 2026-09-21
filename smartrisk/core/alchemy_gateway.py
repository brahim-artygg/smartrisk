from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any

from ..state_fork.alchemy_rpc import AlchemyRpcClient
from .models import RawAlchemyEvidence


class AlchemyGateway:
    """Shared Alchemy boundary: cache, raw evidence, capability probes and RPC helpers."""

    def __init__(self, rpc: AlchemyRpcClient | None = None, cache_ttl_seconds: int = 30):
        self.rpc = rpc or AlchemyRpcClient()
        self.cache_ttl_seconds = cache_ttl_seconds
        self._cache: dict[str, tuple[float, Any, RawAlchemyEvidence]] = {}
        self.evidence: list[RawAlchemyEvidence] = []
        self.rate_limit_events = 0
        self.trace_calls = 0
        self.trace_successes = 0

    def call(self, method: str, params: list[Any] | None = None, anchor: Any | None = None) -> tuple[Any, RawAlchemyEvidence]:
        params = params or []
        key = hashlib.sha256(json.dumps([method, params], sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
        cached = self._cache.get(key)
        if cached and time.time() - cached[0] <= self.cache_ttl_seconds:
            result = cached[1]
            evidence = RawAlchemyEvidence.create(method, str(uuid.uuid4()), params, result, chain_id=getattr(anchor, "chain_id", None), block_number=getattr(anchor, "block_number", None), block_hash=getattr(anchor, "block_hash", None))
            self.evidence.append(evidence)
            return result, evidence
        request_id = str(uuid.uuid4())
        try:
            if method in {"debug_traceTransaction", "trace_transaction", "debug_traceCall"}:
                self.trace_calls += 1
            result = self.rpc.request(method, params)
            if method in {"debug_traceTransaction", "trace_transaction", "debug_traceCall"}:
                self.trace_successes += 1
            evidence = RawAlchemyEvidence.create(method, request_id, params, result, chain_id=getattr(anchor, "chain_id", None), block_number=getattr(anchor, "block_number", None), block_hash=getattr(anchor, "block_hash", None))
            self._cache[key] = (time.time(), result, evidence)
            self.evidence.append(evidence)
            return result, evidence
        except Exception as exc:
            if "429" in str(exc) or "rate" in str(exc).lower():
                self.rate_limit_events += 1
            evidence = RawAlchemyEvidence.create(method, request_id, params, None, chain_id=getattr(anchor, "chain_id", None), block_number=getattr(anchor, "block_number", None), block_hash=getattr(anchor, "block_hash", None), error=str(exc))
            self.evidence.append(evidence)
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

    def get_token_metadata(self, token_address: str, anchor: Any | None = None):
        return self.call("alchemy_getTokenMetadata", [token_address], anchor)

    def get_asset_transfers(self, params: dict[str, Any], anchor: Any | None = None):
        return self.call("alchemy_getAssetTransfers", [params], anchor)

    def capability_matrix(self, archive_probe_block: int | None = None) -> dict[str, Any]:
        result: dict[str, Any] = {"provider": "alchemy", "status": "unavailable", "checks": {}, "limits": {"rate_limit_events": self.rate_limit_events}}
        if not self.rpc.rpc_url:
            return result
        checks = {
            "chain_id": ("eth_chainId", []),
            "safe": ("eth_getBlockByNumber", ["safe", False]),
            "finalized": ("eth_getBlockByNumber", ["finalized", False]),
            "latest": ("eth_getBlockByNumber", ["latest", False]),
            "logs": ("eth_getLogs", [{"fromBlock": "latest", "toBlock": "latest"}]),
            "state_override": ("eth_call", [{"to": "0x0000000000000000000000000000000000000000", "data": "0x"}, "latest", {}]),
            "trace": ("debug_traceTransaction", ["0x" + "0" * 64, {"tracer": "callTracer"}]),
        }
        for name, (method, params) in checks.items():
            try:
                value, _ = self.call(method, params)
                result["checks"][name] = {"available": value is not None}
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
        result["trace_coverage"] = {"attempts": self.trace_calls, "successes": self.trace_successes, "ratio": self.trace_successes / self.trace_calls if self.trace_calls else None}
        result["limits"]["rate_limit_events"] = self.rate_limit_events
        result["status"] = "ready" if result["checks"].get("chain_id", {}).get("available") else "unavailable"
        return result

    def raw_evidence_dicts(self) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self.evidence]

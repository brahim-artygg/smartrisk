from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any

from ..state_fork.alchemy_rpc import AlchemyRpcClient, AlchemyRpcError
from .models import RawAlchemyEvidence


class AlchemyGateway:
    """Shared Alchemy boundary: cache, evidence metadata, and bounded retries."""

    def __init__(self, rpc: AlchemyRpcClient | None = None, cache_ttl_seconds: int = 30):
        self.rpc = rpc or AlchemyRpcClient()
        self.cache_ttl_seconds = cache_ttl_seconds
        self._cache: dict[str, tuple[float, Any, RawAlchemyEvidence]] = {}
        self.evidence: list[RawAlchemyEvidence] = []

    def call(self, method: str, params: list[Any] | None = None, anchor: Any | None = None) -> tuple[Any, RawAlchemyEvidence]:
        params = params or []
        key = hashlib.sha256(json.dumps([method, params], sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
        cached = self._cache.get(key)
        if cached and time.time() - cached[0] <= self.cache_ttl_seconds:
            result, previous = cached[1], cached[2]
            evidence = RawAlchemyEvidence.create(method, str(uuid.uuid4()), params, result, chain_id=getattr(anchor, "chain_id", None), block_number=getattr(anchor, "block_number", None), block_hash=getattr(anchor, "block_hash", None))
            self.evidence.append(evidence)
            return result, evidence
        request_id = str(uuid.uuid4())
        try:
            result = self.rpc.request(method, params)
            evidence = RawAlchemyEvidence.create(method, request_id, params, result, chain_id=getattr(anchor, "chain_id", None), block_number=getattr(anchor, "block_number", None), block_hash=getattr(anchor, "block_hash", None))
            self._cache[key] = (time.time(), result, evidence)
            self.evidence.append(evidence)
            return result, evidence
        except Exception as exc:
            evidence = RawAlchemyEvidence.create(method, request_id, params, None, chain_id=getattr(anchor, "chain_id", None), block_number=getattr(anchor, "block_number", None), block_hash=getattr(anchor, "block_hash", None), error=str(exc))
            self.evidence.append(evidence)
            raise

    def capability_matrix(self) -> dict[str, Any]:
        result = {"provider": "alchemy", "status": "unavailable", "checks": {}}
        if not self.rpc.rpc_url:
            return result
        checks = {
            "chain_id": ("eth_chainId", []),
            "safe": ("eth_getBlockByNumber", ["safe", False]),
            "finalized": ("eth_getBlockByNumber", ["finalized", False]),
            "latest": ("eth_getBlockByNumber", ["latest", False]),
            "logs": ("eth_getLogs", [{"fromBlock": "latest", "toBlock": "latest"}]),
            "trace": ("debug_traceTransaction", ["0x" + "0" * 64, {"tracer": "callTracer"}]),
        }
        for name, (method, params) in checks.items():
            try:
                value, _ = self.call(method, params)
                result["checks"][name] = {"available": value is not None}
            except Exception as exc:
                result["checks"][name] = {"available": False, "error": str(exc)}
        result["status"] = "ready" if result["checks"].get("chain_id", {}).get("available") else "unavailable"
        return result

    def raw_evidence_dicts(self) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self.evidence]

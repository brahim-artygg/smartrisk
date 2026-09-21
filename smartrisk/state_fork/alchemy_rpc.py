from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
import uuid
from typing import Any


class AlchemyRpcError(RuntimeError):
    pass


class AlchemyRpcClient:
    """Small dependency-free JSON-RPC client for Alchemy EVM endpoints."""

    def __init__(
        self,
        rpc_url: str | None = None,
        api_key: str | None = None,
        chain: str = "eth-mainnet",
        timeout_seconds: float = 20.0,
        retries: int = 2,
    ):
        self.chain = chain
        self.api_key = api_key or os.getenv("ALCHEMY_API_KEY")
        self.rpc_url = rpc_url or self._url_from_env()
        self.timeout_seconds = timeout_seconds
        self.retries = retries

    def _url_from_env(self) -> str | None:
        explicit = os.getenv("ALCHEMY_RPC_URL")
        if explicit:
            return explicit
        if self.api_key:
            return f"https://{self.chain}.g.alchemy.com/v2/{self.api_key}"
        return None

    def request(self, method: str, params: list[Any] | None = None) -> Any:
        if not self.rpc_url:
            raise AlchemyRpcError("ALCHEMY_API_KEY or ALCHEMY_RPC_URL is required")
        body = json.dumps({"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method, "params": params or []}).encode()
        request = urllib.request.Request(
            self.rpc_url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "smartrisk-state-fork/0.1"},
            method="POST",
        )
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                if payload.get("error"):
                    raise AlchemyRpcError(f"{method}: {payload['error']}")
                return payload.get("result")
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, AlchemyRpcError) as exc:
                last_error = exc
                if isinstance(exc, AlchemyRpcError) and "429" not in str(exc):
                    raise
                if attempt < self.retries:
                    time.sleep(min(0.25 * (2**attempt), 2.0))
        raise AlchemyRpcError(f"{method} failed after retries: {last_error}")

    def capability_probe(self) -> dict[str, Any]:
        capabilities: dict[str, Any] = {"provider": "alchemy", "rpc_url_configured": bool(self.rpc_url)}
        if not self.rpc_url:
            capabilities["status"] = "unavailable"
            return capabilities
        checks = {
            "chain_id": ("eth_chainId", []),
            "latest_block": ("eth_getBlockByNumber", ["latest", False]),
            "finalized_block": ("eth_getBlockByNumber", ["finalized", False]),
            "safe_block": ("eth_getBlockByNumber", ["safe", False]),
        }
        for name, (method, params) in checks.items():
            try:
                result = self.request(method, params)
                capabilities[name] = {"available": result is not None}
                if name == "finalized_block":
                    capabilities[name]["block_number"] = result.get("number") if result else None
            except AlchemyRpcError as exc:
                capabilities[name] = {"available": False, "error": str(exc)}
        capabilities["status"] = "ready" if capabilities.get("chain_id", {}).get("available") else "unavailable"
        return capabilities

    def get_anchor(self, tag: str = "safe") -> tuple[int, dict[str, Any]]:
        block = self.request("eth_getBlockByNumber", [tag, False])
        if not block or not block.get("hash") or not block.get("number"):
            raise AlchemyRpcError(f"Alchemy returned an invalid {tag} block")
        return int(block["number"], 16), block

    def get_chain_id(self) -> str:
        return self.request("eth_chainId")

    def get_transaction_receipt(self, tx_hash: str) -> dict[str, Any] | None:
        return self.request("eth_getTransactionReceipt", [tx_hash])

    def get_code(self, address: str, block: str = "latest") -> str:
        return self.request("eth_getCode", [address, block])

    def get_balance(self, address: str, block: str = "latest") -> str:
        return self.request("eth_getBalance", [address, block])

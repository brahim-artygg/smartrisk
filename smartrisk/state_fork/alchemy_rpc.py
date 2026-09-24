from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

from ..core.networks import get_network


class AlchemyRpcError(RuntimeError):
    pass


class AlchemyRpcClient:
    """Small dependency-free JSON-RPC client for Alchemy EVM endpoints."""

    def __init__(
        self,
        rpc_url: str | None = None,
        api_key: str | None = None,
        chain: str = "eth-mainnet",
        timeout_seconds: float | None = None,
        retries: int | None = None,
        failover: bool = True,
    ):
        self.network = get_network(chain)
        self.chain = self.network.rpc_chain
        self.expected_chain_id = self.network.chain_id
        self.api_key = api_key or os.getenv("ALCHEMY_API_KEY")
        self.timeout_seconds = float(timeout_seconds if timeout_seconds is not None else os.getenv("SMARTRISK_RPC_TIMEOUT_SECONDS", "20"))
        self.retries = max(0, int(retries if retries is not None else os.getenv("SMARTRISK_RPC_RETRIES", "2")))
        self._rpc_url = rpc_url or self._url_from_env()
        self._router = None
        if rpc_url is None and failover:
            try:
                from ..core.multi_provider import MultiProviderRpc
                router = MultiProviderRpc.from_environment(chain=chain, timeout_seconds=self.timeout_seconds, retries_per_provider=max(0, self.retries - 1))
                if len(router.providers) >= 2:
                    self._router = router
                    self._rpc_url = None
            except (ImportError, TypeError, RuntimeError):
                self._router = None

    @property
    def rpc_url(self) -> str | None:
        return self._router.rpc_url if self._router is not None else self._rpc_url

    @property
    def provider_name(self) -> str:
        return self._router.provider_name if self._router is not None else "alchemy"

    @property
    def last_provider(self) -> str | None:
        return self._router.last_provider if self._router is not None else ("alchemy" if self._rpc_url else None)

    def websocket_urls(self) -> list[tuple[str, str]]:
        if self._router is not None:
            return self._router.websocket_urls()
        urls: list[tuple[str, str]] = []
        alchemy_ws = os.getenv(f"SMARTRISK_{self.network.key.upper()}_WS_URL")
        if not alchemy_ws and self.network.key == "ethereum":
            alchemy_ws = os.getenv("ALCHEMY_WS_URL")
        if not alchemy_ws and self.api_key:
            alchemy_ws = f"wss://{self.chain}.g.alchemy.com/v2/{self.api_key}"
        if alchemy_ws:
            urls.append(("alchemy", alchemy_ws))
        websocket_env = (("quicknode", "QUICKNODE_WS_URL"), ("chainstack", "CHAINSTACK_WS_URL")) if self.network.key == "ethereum" else (
            ("quicknode", f"SMARTRISK_{self.network.key.upper()}_QUICKNODE_WS_URL"),
            ("chainstack", f"SMARTRISK_{self.network.key.upper()}_CHAINSTACK_WS_URL"),
        )
        for name, env_name in websocket_env:
            value = os.getenv(env_name)
            if value:
                urls.append((name, value))
        return urls

    def _url_from_env(self) -> str | None:
        network_specific = os.getenv(f"SMARTRISK_{self.network.key.upper()}_RPC_URL")
        if network_specific:
            return network_specific
        explicit = os.getenv("ALCHEMY_RPC_URL") if self.network.key == "ethereum" else None
        if explicit:
            return explicit
        if self.api_key:
            return f"https://{self.chain}.g.alchemy.com/v2/{self.api_key}"
        return None

    def request(self, method: str, params: list[Any] | None = None) -> Any:
        if self._router is not None:
            return self._router.request(method, params)
        if not self._rpc_url:
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
        if self._router is not None:
            return self._router.capability_probe()
        capabilities: dict[str, Any] = {"provider": "alchemy", "rpc_url_configured": bool(self.rpc_url), "expected_chain_id": self.expected_chain_id}
        if not self.rpc_url:
            capabilities["status"] = "unavailable"
            return capabilities
        # This is a readiness check, not a feature benchmark. Probing latest,
        # finalized and safe here consumed three additional quota units before
        # the real scan even started and made a rate-limited Alchemy key look
        # unavailable. The scan itself probes the selected anchor as needed.
        try:
            result = self.request("eth_chainId", [])
            capabilities["chain_id"] = {"available": result is not None}
            if result is not None:
                actual = int(str(result), 16) if isinstance(result, str) and str(result).lower().startswith("0x") else int(result)
                capabilities["chain_id"]["actual_chain_id"] = str(actual)
                if actual != int(self.expected_chain_id):
                    capabilities["chain_id"]["available"] = False
                    capabilities["chain_id"]["error"] = f"provider chain {actual} does not match expected chain {self.expected_chain_id}"
        except AlchemyRpcError as exc:
            capabilities["chain_id"] = {"available": False, "error": str(exc)}
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

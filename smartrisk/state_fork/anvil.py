from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .alchemy_rpc import AlchemyRpcError
from .models import BlockAnchor, SimulationScenario, SimulationResult


class AnvilUnavailable(RuntimeError):
    pass


class AnvilFork:
    def __init__(self, anvil_executable: str = "anvil", startup_timeout: float = 10.0):
        self.anvil_executable = anvil_executable
        self.startup_timeout = startup_timeout
        self.process: subprocess.Popen[str] | None = None
        self.rpc_url: str | None = None

    def available(self) -> bool:
        return shutil.which(self.anvil_executable) is not None

    def start(self, upstream_url: str, anchor: BlockAnchor, port: int = 0) -> str:
        if not self.available():
            raise AnvilUnavailable("anvil was not found on PATH")
        actual_port = port or 8545
        command = [
            self.anvil_executable,
            "--fork-url", upstream_url,
            "--fork-block-number", str(anchor.block_number),
            "--port", str(actual_port),
            "--host", "127.0.0.1",
            "--silent",
        ]
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.rpc_url = f"http://127.0.0.1:{actual_port}"
        deadline = time.monotonic() + self.startup_timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                stderr = self.process.stderr.read() if self.process.stderr else ""
                raise AnvilUnavailable(f"anvil exited during startup: {stderr[-1000:]}")
            try:
                self.rpc_request("eth_chainId", [])
                return self.rpc_url
            except Exception:
                time.sleep(0.1)
        self.stop()
        raise AnvilUnavailable("anvil did not become ready before timeout")

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process = None
        self.rpc_url = None

    def __enter__(self) -> "AnvilFork":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()

    def rpc_request(self, method: str, params: list[Any] | None = None) -> Any:
        if not self.rpc_url:
            raise AnvilUnavailable("fork is not running")
        import urllib.request
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
        request = urllib.request.Request(self.rpc_url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode())
        if payload.get("error"):
            raise AlchemyRpcError(f"{method}: {payload['error']}")
        return payload.get("result")

    def snapshot(self) -> str:
        return self.rpc_request("evm_snapshot")

    def revert(self, snapshot_id: str) -> bool:
        return bool(self.rpc_request("evm_revert", [snapshot_id]))

    def run_scenario(self, scenario: SimulationScenario, anchor: BlockAnchor) -> SimulationResult:
        snapshot = self.snapshot()
        try:
            try:
                # The sender is impersonated only inside the local fork. No
                # private key is created or transmitted to Alchemy.
                self.rpc_request("anvil_impersonateAccount", [scenario.from_address])
                self.rpc_request("anvil_setBalance", [scenario.from_address, hex(10**21)])
                tx_hash = self.rpc_request("eth_sendTransaction", [scenario.rpc_transaction()])
            except Exception as exc:
                return SimulationResult(scenario.scenario_id, "reverted", anchor, error=str(exc), assumptions=["transaction was not broadcast to the real network"])
            receipt = self._wait_receipt(tx_hash)
            if not receipt:
                return SimulationResult(scenario.scenario_id, "unknown", anchor, tx_hash=tx_hash, error="receipt timeout")
            succeeded = receipt.get("status") == "0x1"
            trace = None
            try:
                trace = self.rpc_request("debug_traceTransaction", [tx_hash, {"tracer": "callTracer"}])
            except Exception as exc:
                trace = {"unavailable": str(exc)}
            return SimulationResult(
                scenario.scenario_id,
                "success" if succeeded else "reverted",
                anchor,
                tx_hash=tx_hash,
                receipt=receipt,
                trace=trace,
                logs=receipt.get("logs", []),
                assumptions=["execution occurred only on a local Anvil fork"],
            )
        finally:
            self.revert(snapshot)

    def _wait_receipt(self, tx_hash: str, timeout: float = 15.0) -> dict[str, Any] | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            receipt = self.rpc_request("eth_getTransactionReceipt", [tx_hash])
            if receipt:
                return receipt
            time.sleep(0.1)
        return None

from __future__ import annotations

import json
import shutil
import subprocess
import time
from typing import Any

from .alchemy_rpc import AlchemyRpcError
from .models import BlockAnchor, HoneypotSequence, SimulationScenario, SimulationResult


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
            return self._execute_scenario(scenario, anchor)
        finally:
            self.revert(snapshot)

    def run_sequence(self, sequence: HoneypotSequence, anchor: BlockAnchor) -> list[SimulationResult]:
        """Execute buy -> optional approve -> sell in one state, then revert it."""
        snapshot = self.snapshot()
        results: list[SimulationResult] = []
        try:
            for scenario in sequence.steps():
                result = self._execute_scenario(scenario, anchor)
                results.append(result)
                if result.status != "success":
                    break
            return results
        finally:
            self.revert(snapshot)

    def _execute_scenario(self, scenario: SimulationScenario, anchor: BlockAnchor) -> SimulationResult:
        before_state = self._capture_state(scenario)
        try:
            # The sender is impersonated only inside the local fork. No
            # private key is created or transmitted to Alchemy.
            self.rpc_request("anvil_impersonateAccount", [scenario.from_address])
            self.rpc_request("anvil_setBalance", [scenario.from_address, hex(10**21)])
            tx_hash = self.rpc_request("eth_sendTransaction", [scenario.rpc_transaction()])
        except Exception as exc:
            return SimulationResult(
                scenario.scenario_id,
                "reverted",
                anchor,
                error=str(exc),
                state_diff={"before": before_state, "after": None, "delta": None},
                assumptions=["transaction was not broadcast to the real network"],
            )
        receipt = self._wait_receipt(tx_hash)
        if not receipt:
            return SimulationResult(scenario.scenario_id, "unknown", anchor, tx_hash=tx_hash, error="receipt timeout")
        after_state = self._capture_state(scenario)
        state_diff = self._diff_state(before_state, after_state)
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
            state_diff=state_diff,
            assumptions=["execution occurred only on a local Anvil fork"],
        )

    def _capture_state(self, scenario: SimulationScenario) -> dict[str, Any]:
        state: dict[str, Any] = {"address": scenario.from_address, "native_balance_wei": None, "token_balances": {}, "errors": []}
        try:
            state["native_balance_wei"] = int(self.rpc_request("eth_getBalance", [scenario.from_address, "latest"]), 16)
        except Exception as exc:
            state["errors"].append(f"native balance unavailable: {exc}")
        for token in scenario.observed_tokens:
            try:
                data = "0x70a08231" + scenario.from_address.lower().removeprefix("0x").rjust(64, "0")
                result = self.rpc_request("eth_call", [{"to": token, "data": data}, "latest"])
                state["token_balances"][token] = int(result or "0x0", 16)
            except Exception as exc:
                state["token_balances"][token] = None
                state["errors"].append(f"token balance unavailable for {token}: {exc}")
        return state

    @staticmethod
    def _diff_state(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
        native_before, native_after = before.get("native_balance_wei"), after.get("native_balance_wei")
        delta: dict[str, Any] = {"native_balance_delta_wei": native_after - native_before if native_before is not None and native_after is not None else None, "token_balance_delta": {}}
        tokens = set(before.get("token_balances", {})) | set(after.get("token_balances", {}))
        for token in tokens:
            old, new = before.get("token_balances", {}).get(token), after.get("token_balances", {}).get(token)
            delta["token_balance_delta"][token] = new - old if old is not None and new is not None else None
        return {"before": before, "after": after, "delta": delta}

    def _wait_receipt(self, tx_hash: str, timeout: float = 15.0) -> dict[str, Any] | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            receipt = self.rpc_request("eth_getTransactionReceipt", [tx_hash])
            if receipt:
                return receipt
            time.sleep(0.1)
        return None

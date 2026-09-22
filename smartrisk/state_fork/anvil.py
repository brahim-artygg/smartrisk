from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from typing import Any

from .alchemy_rpc import AlchemyRpcError
from .models import BlockAnchor, HoneypotSequence, SimulationScenario, SimulationResult
from .state_diff import normalize_prestate_diff
from .revert import decode_revert_data
from .honeypot import _failure_cause
from ..core.keccak import keccak256


class AnvilUnavailable(RuntimeError):
    pass


TRANSFER_TOPIC = "0x" + keccak256(b"Transfer(address,address,uint256)").hex()
APPROVAL_TOPIC = "0x" + keccak256(b"Approval(address,address,uint256)").hex()
ALLOWANCE_SELECTOR = "0xdd62ed3e"
GET_RESERVES_SELECTOR = "0x0902f1ac"
BALANCE_OF_SELECTOR = "0x70a08231"
TOKEN0_SELECTOR = "0x0dfe1681"
TOKEN1_SELECTOR = "0xd21220a7"


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

    def run_scenario(self, scenario: SimulationScenario, anchor: BlockAnchor, trace_mode: str = "callTracer") -> SimulationResult:
        snapshot = self.snapshot()
        try:
            return self._execute_scenario(scenario, anchor, trace_mode=trace_mode)
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

    def run_trade_matrix(self, plan, anchor: BlockAnchor, run_id: str, modes: tuple[str, ...] = ("baseline", "micro_sell", "small_sell", "partial_sell", "sell_all", "transfer_only")):
        """Execute independent native buy/approve/sell attempts on one anchored fork."""
        from .models import TradeAttemptResult, TradeMatrixRun
        from .trade_builder import scenario_from_sell_template, scenario_from_transfer_template
        from .trade_analysis import correlate_trade_sequence

        if not getattr(plan, "executable", False) or not plan.buy or not plan.approve or not plan.route:
            return TradeMatrixRun(
                run_id=run_id, status="unknown", anchor=anchor, token_address=plan.token_address,
                pair_address=plan.pair.pair_address, plan=plan.to_dict(),
                unknown_reasons=[getattr(plan, "reason", None) or "trade plan is not executable"],
            )

        outer_snapshot = self.snapshot()
        attempts: list[TradeAttemptResult] = []
        try:
            for mode in modes:
                template = plan.sell_templates.get(mode) or (plan.sell_templates.get("transfer") if mode == "transfer_only" else None)
                if not template:
                    attempts.append(TradeAttemptResult(mode, "unknown", unknown_reasons=["sell template is missing"]))
                    continue
                self.revert(outer_snapshot)
                attempt_snapshot = self.snapshot()
                try:
                    pre_buy_approve = None
                    if getattr(plan, "pre_buy_approve", None) is not None:
                        pre_buy_approve = self._execute_scenario(plan.pre_buy_approve, anchor)
                        if pre_buy_approve.status != "success":
                            classification = "buy_failed" if pre_buy_approve.status == "reverted" else "unknown"
                            attempts.append(TradeAttemptResult(
                                mode, classification, buy=None, pre_buy_approve=pre_buy_approve,
                                unknown_reasons=[pre_buy_approve.error] if classification == "unknown" and pre_buy_approve.error else [],
                            ))
                            continue
                    buy = self._execute_scenario(plan.buy, anchor)
                    if buy.status != "success":
                        classification = "buy_failed" if buy.status == "reverted" else "unknown"
                        attempts.append(TradeAttemptResult(mode, classification, buy=buy, pre_buy_approve=pre_buy_approve, unknown_reasons=[buy.error] if classification == "unknown" and buy.error else []))
                        continue
                    bought = ((buy.state_diff or {}).get("delta") or {}).get("token_balance_delta", {}).get(plan.token_address)
                    if not isinstance(bought, int) or bought <= 0:
                        attempts.append(TradeAttemptResult(mode, "unknown", buy=buy, pre_buy_approve=pre_buy_approve, unknown_reasons=["buy succeeded but positive token delta was not observed"]))
                        continue
                    if mode == "transfer_only":
                        transfer = scenario_from_transfer_template(template, bought, plan.pair.pair_address)
                        transfer_result = self._execute_scenario(transfer, anchor)
                        classification = ("transfer_succeeded" if transfer_result.status == "success" else "transfer_blocked" if transfer_result.status == "reverted" and _failure_cause(transfer_result) == "token_restriction" else "unknown")
                        attempts.append(TradeAttemptResult(
                            mode, classification, buy=buy, pre_buy_approve=pre_buy_approve, observed_buy_token_delta=bought, sell=transfer_result,
                            analysis={"mode": "transfer_only", "requested_transfer_amount": bought, "failure_cause": _failure_cause(transfer_result) if transfer_result.status == "reverted" else None},
                            unknown_reasons=[transfer_result.error] if classification == "unknown" and transfer_result.error else [],
                        ))
                        continue
                    approve = self._execute_scenario(plan.approve, anchor)
                    if approve.status != "success":
                        classification = "approve_failed" if approve.status == "reverted" else "unknown"
                        attempts.append(TradeAttemptResult(mode, classification, buy=buy, approve=approve, observed_buy_token_delta=bought, unknown_reasons=[approve.error] if classification == "unknown" and approve.error else []))
                        continue
                    sell = scenario_from_sell_template(template, bought, plan.route.router_address, plan.pair.pair_address, mode=mode)
                    sell_result = self._execute_scenario(sell, anchor)
                    failure_cause = _failure_cause(sell_result) if sell_result.status == "reverted" else None
                    classification = "sell_succeeded" if sell_result.status == "success" else "sell_blocked" if sell_result.status == "reverted" and failure_cause == "token_restriction" else "unknown"
                    analysis = correlate_trade_sequence(
                        buy, approve, sell_result, token_address=plan.token_address,
                        pair_address=plan.pair.pair_address, wrapped_native=plan.route.wrapped_native,
                        requested_sell_amount=bought * int(template.get("fraction_bps", 10000)) // 10000,
                        buy_amount_wei=plan.buy.value_wei,
                        sell_output_is_erc20=getattr(plan.route, "native_asset_is_erc20", False) or not getattr(plan.route, "native_out", True),
                    )
                    input_tax = analysis.get("sell", {}).get("input_tax_bps")
                    if "effective_sell_tax_bps" not in analysis.get("sell", {}):
                        analysis["sell"]["effective_sell_tax_bps"] = input_tax if isinstance(input_tax, int) else None
                    analysis["sell"]["failure_cause"] = failure_cause
                    analysis["sell"]["requested_fraction_bps"] = int(template.get("fraction_bps", 10000))
                    attempts.append(TradeAttemptResult(
                        mode, classification, buy=buy, approve=approve, pre_buy_approve=pre_buy_approve, sell=sell_result,
                        observed_buy_token_delta=bought, analysis=analysis,
                        unknown_reasons=[sell_result.error] if classification == "unknown" and sell_result.error else [],
                    ))
                finally:
                    self.revert(attempt_snapshot)
        finally:
            self.revert(outer_snapshot)

        hard_signals = []
        for attempt in attempts:
            if attempt.classification == "sell_blocked":
                hard_signals.append({
                    "signal_id": f"honeypot.{attempt.mode}.sell_blocked",
                    "severity": "critical",
                    "status": "confirmed_in_scenario",
                    "evidence_refs": [item for item in (attempt.buy.tx_hash if attempt.buy else None, attempt.approve.tx_hash if attempt.approve else None, attempt.sell.tx_hash if attempt.sell else None) if item],
                    "explanation": (f"The {attempt.mode} transfer reverted after a successful buy in the same fork scenario." if attempt.mode == "transfer_only" else f"The {attempt.mode} sell reverted after a successful buy and approval in the same fork scenario."),
                    "classification": "sell_blocked",
                })
            if attempt.mode != "transfer_only":
                tax = attempt.analysis.get("sell", {}).get("effective_sell_tax_bps") if isinstance(attempt.analysis, dict) else None
                if isinstance(tax, int):
                    if tax >= 9500:
                        hard_signals.append({
                            "signal_id": f"tax.{attempt.mode}.effectively_blocked",
                            "severity": "critical",
                            "status": "confirmed_in_scenario",
                            "evidence_refs": [item for item in (attempt.buy.tx_hash if attempt.buy else None, attempt.sell.tx_hash if attempt.sell else None) if item],
                            "explanation": f"The token retained only {10_000 - tax} bps of the requested sell amount before the pair received it ({tax / 100:.2f}% effective input tax).",
                            "tax_bps": tax,
                        })
                    elif tax >= 5000:
                        hard_signals.append({
                            "signal_id": f"tax.{attempt.mode}.high_sell_tax",
                            "severity": "high",
                            "status": "confirmed_in_scenario",
                            "evidence_refs": [item for item in (attempt.buy.tx_hash if attempt.buy else None, attempt.sell.tx_hash if attempt.sell else None) if item],
                            "explanation": f"The token applied {tax / 100:.2f}% effective input tax on the {int(attempt.analysis.get('sell', {}).get('requested_fraction_bps', 10000)) / 100:.2f}% sell-size scenario.",
                            "tax_bps": tax,
                        })
        # Detect tax that changes materially with sell size. A large change is a
        # high-risk trading signal, but not a scam proof on its own.
        tax_samples = [
            (int(a.analysis.get("sell", {}).get("requested_fraction_bps", 10_000)), int(a.analysis.get("sell", {}).get("effective_sell_tax_bps")))
            for a in attempts
            if a.mode != "transfer_only" and isinstance(a.analysis, dict) and isinstance(a.analysis.get("sell", {}).get("effective_sell_tax_bps"), int)
        ]
        if len(tax_samples) >= 2:
            min_size, min_tax = min(tax_samples, key=lambda item: item[0])
            max_size, max_tax = max(tax_samples, key=lambda item: item[0])
            if abs(max_tax - min_tax) >= 1000:
                hard_signals.append({
                    "signal_id": "tax.dynamic_sell_behavior",
                    "severity": "high",
                    "status": "confirmed_in_scenario",
                    "evidence_refs": [r for a in attempts for r in (a.sell.tx_hash if a.sell else None,) if r],
                    "explanation": f"Effective sell tax changed materially with sell size ({min_size / 100:.2f}% scenario: {min_tax / 100:.2f}%; {max_size / 100:.2f}% scenario: {max_tax / 100:.2f}%).",
                    "tax_samples_bps": [{"fraction_bps": size, "tax_bps": tax} for size, tax in sorted(tax_samples)],
                })
        # Detect amount-dependent sell restrictions using the same observed buy state.
        successful = [a for a in attempts if a.mode != "transfer_only" and a.classification == "sell_succeeded"]
        blocked = [a for a in attempts if a.mode != "transfer_only" and a.classification == "sell_blocked"]
        if successful and blocked:
            min_success = min(int(a.analysis.get("sell", {}).get("requested_fraction_bps", 10_000)) for a in successful)
            max_block = max(int(a.analysis.get("sell", {}).get("requested_fraction_bps", 10_000)) for a in blocked)
            if min_success < max_block:
                hard_signals.append({
                    "signal_id": "honeypot.amount_threshold.sell_restriction",
                    "severity": "critical",
                    "status": "confirmed_in_scenario",
                    "evidence_refs": [r for a in successful + blocked for r in (a.sell.tx_hash if a.sell else None,) if r],
                    "explanation": f"Sell behavior changed by amount: a {min_success / 100:.2f}% balance sell succeeded while a larger {max_block / 100:.2f}% sell was blocked.",
                    "successful_fraction_bps": min_success,
                    "blocked_fraction_bps": max_block,
                })
        status = "complete" if attempts and not any(item.classification == "unknown" for item in attempts) else "partial" if attempts else "unknown"
        verdict, verdict_label, primary = self._trade_verdict(status, hard_signals)
        return TradeMatrixRun(
            run_id, status, anchor, plan.token_address, plan.pair.pair_address, plan.to_dict(),
            attempts, hard_signals, [], verdict, verdict_label, primary,
        )

    @staticmethod
    def _trade_verdict(status: str, hard_signals: list[dict[str, Any]]) -> tuple[str, str, dict[str, Any]]:
        honeypot = next((item for item in hard_signals if str(item.get("signal_id", "")).startswith("honeypot.") and item.get("severity") == "critical"), None)
        if honeypot:
            return "HONEYPOT_DETECTED", "HONEYPOT DETECTED", {
                "type": "honeypot",
                "title": honeypot.get("explanation", "Sell behavior was blocked after a successful buy"),
                "signal_id": honeypot.get("signal_id"),
                "evidence_refs": honeypot.get("evidence_refs") or honeypot.get("evidence", []),
            }
        critical = next((item for item in hard_signals if item.get("severity") == "critical"), None)
        if critical:
            return "CRITICAL_RISK", "CRITICAL RISK", {
                "type": "trading",
                "title": critical.get("explanation", "Critical trading risk detected"),
                "signal_id": critical.get("signal_id"),
                "evidence_refs": critical.get("evidence_refs") or critical.get("evidence", []),
            }
        high = next((item for item in hard_signals if item.get("severity") == "high"), None)
        if high:
            return "HIGH_RISK", "HIGH RISK", {
                "type": "trading",
                "title": high.get("explanation", "High trading risk detected"),
                "signal_id": high.get("signal_id"),
                "evidence_refs": high.get("evidence_refs") or high.get("evidence", []),
            }
        if status == "unknown":
            return "UNVERIFIED", "UNVERIFIED", {"type": "insufficient_evidence", "title": "Trade verification could not be completed"}
        return "LOW_RISK", "LOW RISK", {"type": "trading", "title": "No high-severity trading risk detected in the tested scenarios"}

    def _execute_scenario(self, scenario: SimulationScenario, anchor: BlockAnchor, trace_mode: str = "callTracer") -> SimulationResult:
        # Configure the impersonated account before taking the baseline snapshot.
        # This keeps native balance deltas attributable to the transaction itself.
        try:
            self.rpc_request("anvil_impersonateAccount", [scenario.from_address])
            self.rpc_request("anvil_setBalance", [scenario.from_address, hex(10**21)])
        except Exception as exc:
            return SimulationResult(
                scenario.scenario_id,
                "unknown",
                anchor,
                error=f"fork account setup failed: {exc}",
                state_diff={"before": None, "after": None, "delta": None},
                assumptions=["transaction was not broadcast to the real network"],
            )
        before_state = self._capture_state(scenario)
        return_data = None
        try:
            return_data = self.rpc_request("eth_call", [scenario.rpc_transaction(), "latest"])
        except Exception:
            # A mutating transaction may be valid only with the fork's exact
            # execution context; preserve the unknown return-data state.
            pass
        try:
            # The sender is impersonated only inside the local fork. No
            # private key is created or transmitted to Alchemy.
            tx_hash = self.rpc_request("eth_sendTransaction", [scenario.rpc_transaction()])
        except Exception as exc:
            revert_info = decode_revert_data(self._extract_revert_payload(exc))
            return SimulationResult(
                scenario.scenario_id,
                "reverted",
                anchor,
                error=str(exc),
                revert_data=revert_info.get("raw") if revert_info.get("status") == "decoded" else self._revert_selector(str(exc)),
                revert_reason=revert_info.get("reason"),
                revert_info=revert_info,
                return_data=return_data,
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
            if trace_mode == "structLogs":
                trace = self.rpc_request("debug_traceTransaction", [tx_hash, {"disableStorage": True, "disableMemory": True, "disableStack": True}])
            elif trace_mode != "none":
                trace = self.rpc_request("debug_traceTransaction", [tx_hash, {"tracer": "callTracer"}])
        except Exception as exc:
            trace = {"unavailable": str(exc), "trace_mode": trace_mode}
        storage_trace = None
        try:
            storage_trace = self.rpc_request("debug_traceTransaction", [tx_hash, {"tracer": "prestateTracer", "tracerConfig": {"diffMode": True}}])
        except Exception:
            pass
        receipt_gas = self._hex_int(receipt.get("gasUsed"))
        gas_price = self._hex_int(receipt.get("effectiveGasPrice"))
        if storage_trace is not None:
            state_diff["storage_trace"] = storage_trace
            state_diff["storage_diff"] = normalize_prestate_diff(storage_trace)
        state_diff["event_analysis"] = self._decode_event_logs(receipt.get("logs", []))
        receipt_revert_raw = None if succeeded else self._extract_revert_payload(receipt)
        receipt_revert = decode_revert_data(receipt_revert_raw) if receipt_revert_raw else {"status": "unknown", "raw": None, "selector": None, "reason": None}
        state_diff["accounting"] = self._accounting_summary(state_diff, receipt_gas, gas_price)
        return SimulationResult(
            scenario.scenario_id,
            "success" if succeeded else "reverted",
            anchor,
            tx_hash=tx_hash,
            receipt=receipt,
            trace=trace,
            return_data=return_data,
            revert_data=receipt_revert.get("raw") if receipt_revert.get("status") == "decoded" else None,
            revert_reason=receipt_revert.get("reason"),
            revert_info=receipt_revert,
            logs=receipt.get("logs", []),
            state_diff=state_diff,
            assumptions=["execution occurred only on a local Anvil fork", f"gas_used={receipt_gas}", f"effective_gas_price={gas_price}"],
        )

    @staticmethod
    def _extract_revert_payload(value: Any) -> str | None:
        if isinstance(value, dict):
            for key in ("data", "returnData", "revertData", "result"):
                candidate = value.get(key)
                if isinstance(candidate, str) and candidate.startswith("0x"):
                    return candidate
            error = value.get("error")
            if error is not None:
                return AnvilFork._extract_revert_payload(error)
        text = str(value or "")
        match = re.search(r"0x[a-fA-F0-9]{8,}", text)
        return match.group(0) if match else None

    @staticmethod
    def _accounting_summary(state_diff: dict[str, Any], gas_used: int | None, gas_price: int | None) -> dict[str, Any]:
        delta = state_diff.get("delta") or {}
        token = delta.get("token_balance_delta") or {}
        allowances = delta.get("allowance_delta") or {}
        reserves = delta.get("pair_reserve_delta") or {}
        storage_diff = state_diff.get("storage_diff") or {}
        accounts = storage_diff.get("accounts") or {} if isinstance(storage_diff, dict) else {}
        storage_accounts = 0
        storage_slots = 0
        code_changes = 0
        for account in accounts.values() if isinstance(accounts, dict) else []:
            if not isinstance(account, dict):
                continue
            storage = account.get("storage") or {}
            storage_slots += len(storage) if isinstance(storage, dict) else 0
            if account.get("code", {}).get("changed") if isinstance(account.get("code"), dict) else False:
                code_changes += 1
            if storage:
                storage_accounts += 1
        gas_cost = gas_used * gas_price if gas_used is not None and gas_price is not None else None
        return {
            "native_balance_delta_wei": delta.get("native_balance_delta_wei"),
            "token_delta_count": len(token),
            "allowance_delta_count": len(allowances),
            "pair_reserve_delta_count": len(reserves),
            "storage_accounts_changed": storage_accounts,
            "storage_slots_changed": storage_slots,
            "code_accounts_changed": code_changes,
            "gas_used": gas_used,
            "effective_gas_price": gas_price,
            "gas_cost_wei": gas_cost,
        }

    @staticmethod
    def _hex_int(value: Any) -> int | None:
        try:
            return int(value, 16) if isinstance(value, str) else int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _revert_selector(error: str) -> str | None:
        match = re.search(r"0x[a-fA-F0-9]{8}", error)
        return match.group(0) if match else None

    def _capture_state(self, scenario: SimulationScenario) -> dict[str, Any]:
        state: dict[str, Any] = {
            "address": scenario.from_address,
            "native_balance_wei": None,
            "token_balances": {},
            "allowances": {},
            "pair_reserves": {},
            "pair_tokens": {},
            "errors": [],
        }
        try:
            state["native_balance_wei"] = int(self.rpc_request("eth_getBalance", [scenario.from_address, "latest"]), 16)
        except Exception as exc:
            state["errors"].append(f"native balance unavailable: {exc}")
        for token in scenario.observed_tokens:
            try:
                data = BALANCE_OF_SELECTOR + scenario.from_address.lower().removeprefix("0x").rjust(64, "0")
                result = self.rpc_request("eth_call", [{"to": token, "data": data}, "latest"])
                state["token_balances"][token] = int(result or "0x0", 16)
            except Exception as exc:
                state["token_balances"][token] = None
                state["errors"].append(f"token balance unavailable for {token}: {exc}")
        for token, spender in scenario.observed_allowances:
            try:
                data = ALLOWANCE_SELECTOR + scenario.from_address.lower().removeprefix("0x").rjust(64, "0") + spender.lower().removeprefix("0x").rjust(64, "0")
                result = self.rpc_request("eth_call", [{"to": token, "data": data}, "latest"])
                state["allowances"][f"{token}:{spender}"] = int(result or "0x0", 16)
            except Exception as exc:
                state["allowances"][f"{token}:{spender}"] = None
                state["errors"].append(f"allowance unavailable for {token}:{spender}: {exc}")
        for pair in scenario.observed_pairs:
            try:
                token0 = self.rpc_request("eth_call", [{"to": pair, "data": TOKEN0_SELECTOR}, "latest"])
                token1 = self.rpc_request("eth_call", [{"to": pair, "data": TOKEN1_SELECTOR}, "latest"])
                state["pair_tokens"][pair] = {
                    "token0": "0x" + str(token0 or "0x")[-40:].lower(),
                    "token1": "0x" + str(token1 or "0x")[-40:].lower(),
                }
            except Exception as exc:
                state["pair_tokens"][pair] = None
                state["errors"].append(f"pair token addresses unavailable for {pair}: {exc}")
            try:
                result = self.rpc_request("eth_call", [{"to": pair, "data": GET_RESERVES_SELECTOR}, "latest"])
                raw = (result or "0x").removeprefix("0x")
                if len(raw) >= 192:
                    state["pair_reserves"][pair] = {
                        "reserve0": int(raw[0:64], 16),
                        "reserve1": int(raw[64:128], 16),
                        "block_timestamp_last": int(raw[128:192], 16),
                    }
                else:
                    state["pair_reserves"][pair] = None
            except Exception as exc:
                state["pair_reserves"][pair] = None
                state["errors"].append(f"pair reserves unavailable for {pair}: {exc}")
        return state

    @staticmethod
    def _decode_event_logs(logs: list[dict[str, Any]]) -> dict[str, Any]:
        transfers: list[dict[str, Any]] = []
        approvals: list[dict[str, Any]] = []
        for log in logs or []:
            topics = log.get("topics") or []
            if not topics:
                continue
            topic0 = str(topics[0]).lower()
            data = str(log.get("data") or "0x").removeprefix("0x")
            if topic0 == TRANSFER_TOPIC.lower() and len(topics) >= 3 and len(data) >= 64:
                transfers.append({
                    "token": log.get("address"),
                    "from": "0x" + str(topics[1])[-40:],
                    "to": "0x" + str(topics[2])[-40:],
                    "amount": int(data[:64], 16),
                    "log_index": log.get("logIndex"),
                })
            elif topic0 == APPROVAL_TOPIC.lower() and len(topics) >= 3 and len(data) >= 64:
                approvals.append({
                    "token": log.get("address"),
                    "owner": "0x" + str(topics[1])[-40:],
                    "spender": "0x" + str(topics[2])[-40:],
                    "amount": int(data[:64], 16),
                    "log_index": log.get("logIndex"),
                })
        return {"erc20_transfers": transfers, "erc20_approvals": approvals}

    @staticmethod
    def _diff_state(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
        native_before, native_after = before.get("native_balance_wei"), after.get("native_balance_wei")
        delta: dict[str, Any] = {
            "native_balance_delta_wei": native_after - native_before if native_before is not None and native_after is not None else None,
            "token_balance_delta": {},
            "allowance_delta": {},
            "pair_reserve_delta": {},
        }
        for token in set(before.get("token_balances", {})) | set(after.get("token_balances", {})):
            old, new = before.get("token_balances", {}).get(token), after.get("token_balances", {}).get(token)
            delta["token_balance_delta"][token] = new - old if old is not None and new is not None else None
        for key in set(before.get("allowances", {})) | set(after.get("allowances", {})):
            old, new = before.get("allowances", {}).get(key), after.get("allowances", {}).get(key)
            delta["allowance_delta"][key] = new - old if old is not None and new is not None else None
        for pair in set(before.get("pair_reserves", {})) | set(after.get("pair_reserves", {})):
            old, new = before.get("pair_reserves", {}).get(pair), after.get("pair_reserves", {}).get(pair)
            if isinstance(old, dict) and isinstance(new, dict):
                delta["pair_reserve_delta"][pair] = {
                    "reserve0": new.get("reserve0") - old.get("reserve0"),
                    "reserve1": new.get("reserve1") - old.get("reserve1"),
                }
            else:
                delta["pair_reserve_delta"][pair] = None
        return {"before": before, "after": after, "delta": delta}

    def _wait_receipt(self, tx_hash: str, timeout: float = 15.0) -> dict[str, Any] | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            receipt = self.rpc_request("eth_getTransactionReceipt", [tx_hash])
            if receipt:
                return receipt
            time.sleep(0.1)
        return None

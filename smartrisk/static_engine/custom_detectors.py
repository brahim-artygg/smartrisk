from __future__ import annotations

import importlib.util
import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..core.sandbox import CommandSandbox, SandboxUnavailable
from .models import Evidence, Finding, SourceLocation


RULES = {
    "access.unprotected-sensitive-function": {
        "title": "Externally reachable sensitive storage write lacks authorization",
        "description": "A public or external function writes a privileged state variable without a detected authorization path.",
        "severity": "high",
        "remediation": "Restrict the state transition with a well-defined role/owner check and test unauthorized callers.",
    },
    "upgrade.unprotected": {
        "title": "Upgrade state write lacks authorization",
        "description": "A public or external function writes implementation/proxy administration state without a detected authorization path.",
        "severity": "critical",
        "remediation": "Protect upgrades with a dedicated role, timelock or multisig and emit an upgrade event.",
    },
    "token.unprotected-mint-burn": {
        "title": "Unprotected supply-changing storage write",
        "description": "A public or external function changes supply and balance storage without a detected authorization path.",
        "severity": "critical",
        "remediation": "Restrict supply-changing operations and test totalSupply and balance invariants.",
    },
    "token.unprotected-blacklist": {
        "title": "Blacklist storage write lacks authorization",
        "description": "A public or external function writes blacklist/whitelist storage without a detected authorization path.",
        "severity": "high",
        "remediation": "Restrict blacklist changes to a documented role and emit auditable events.",
    },
    "token.unprotected-pause": {
        "title": "Pause storage write lacks authorization",
        "description": "A public or external function writes pause storage without a detected authorization path.",
        "severity": "high",
        "remediation": "Restrict pause controls and define emergency governance and unpause conditions.",
    },
    "token.unprotected-fee": {
        "title": "Fee storage write lacks authorization",
        "description": "A public or external function writes fee/tax storage without a detected authorization path.",
        "severity": "high",
        "remediation": "Restrict fee changes, enforce a maximum, and test buy/sell accounting under the limit.",
    },
    "token.unprotected-trading-control": {
        "title": "Unprotected trading-control state write",
        "description": "A public or external function changes trading limits or transfer-control state without a detected authorization path.",
        "severity": "high",
        "remediation": "Protect trading controls with explicit authorization and validate max-transaction, max-wallet and launch-state invariants.",
    },
    "token.unbounded-fee": {
        "title": "Unprotected and unbounded fee storage write",
        "description": "A public or external function writes fee/tax storage without authorization and without a detected upper-bound check.",
        "severity": "high",
        "remediation": "Restrict fee changes and enforce a maximum before writing the fee state variable.",
    },
}

# These are used to classify the storage target, not to decide whether a
# function is suspicious. The detector first requires an actual state write.
STATE_GROUPS = {
    "access": ("owner", "admin", "role", "governor", "guardian"),
    "upgrade": ("implementation", "proxy", "beacon", "upgrade"),
    "blacklist": ("blacklist", "whitelist", "denylist", "allowlist"),
    "pause": ("pause", "paused"),
    "fee": ("fee", "tax", "basispoint", "bps"),
    "trading": ("trading", "tradingenabled", "maxtx", "maxwallet", "cooldown", "transferdelay", "selllimit", "buylimit", "txlimit", "walletlimit"),
}
AUTH_HINTS = (
    "owner", "onlyowner", "admin", "role", "auth", "operator", "governor", "guardian",
    "checkrole", "hasrole", "_authorize", "_checkowner",
)
SUPPLY_HINTS = ("totalsupply", "supply", "balance", "balances", "rowned", "towned", "ttotal", "rtotal", "reflection", "ramount", "tamount")


class CustomDetectorRunner:
    """Data-flow/storage-write detectors on Slither's semantic model.

    A detector fires only when a public/external function has state writes and
    the written variables/IR operations support the risk classification. Names
    are used to classify the written storage target, not as a standalone trigger.
    """

    def __init__(self, timeout_seconds: int = 120):
        self.timeout_seconds = timeout_seconds

    def available(self) -> bool:
        return importlib.util.find_spec("slither") is not None

    def run_sandboxed(
        self, project: Path, env: dict[str, str] | None = None, sandbox: CommandSandbox | None = None
    ) -> tuple[list[Finding], list[Evidence], list[str]]:
        """Run the Slither-backed semantic detectors in an isolated worker process."""
        worker = sandbox or CommandSandbox()
        child_env = dict(env or {})
        child_env.setdefault("PYTHONPATH", os.pathsep.join(path for path in sys.path if path))
        result = worker.run(
            [sys.executable, "-m", "smartrisk.static_engine.custom_worker", str(project)],
            cwd=project,
            env=child_env,
            readonly_paths=(project,),
            timeout_seconds=self.timeout_seconds,
        )
        if result.status == "timeout":
            raise RuntimeError("custom detector worker timed out")
        if result.status in {"failed", "resource_exceeded"} and not result.stdout:
            raise RuntimeError(f"custom detector worker failed: {result.stderr[-500:]}")
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("custom detector worker returned invalid JSON") from exc
        findings: list[Finding] = []
        for item in payload.get("findings", []):
            location = item.get("source_location")
            findings.append(Finding(**{**item, "source_location": SourceLocation(**location) if location else None}))
        evidence = [Evidence(**item) for item in payload.get("evidence", [])]
        diagnostics = list(payload.get("diagnostics", [])) + list(result.diagnostics)
        return findings, evidence, diagnostics

    def run(
        self, project: Path, env: dict[str, str] | None = None
    ) -> tuple[list[Finding], list[Evidence], list[str]]:
        if not self.available():
            raise RuntimeError("Slither Python package is not installed")
        from slither import Slither  # type: ignore

        with self._temporary_environment(env):
            slither = Slither(str(project))
            return self._run_on_slither(slither)

    def _run_on_slither(self, slither: Any) -> tuple[list[Finding], list[Evidence], list[str]]:
        findings: list[Finding] = []
        evidence: list[Evidence] = []
        for contract in slither.contracts:
            for function in contract.functions_and_modifiers:
                if not self._externally_reachable(function):
                    continue
                writes = self._storage_writes(function)
                if not writes:
                    continue
                group = self._group_for_function(function, writes)
                if group is None:
                    continue
                authorization = self._authorization_evidence(function)
                if authorization["detected"]:
                    continue
                bounded_fee = group == "fee" and self._has_fee_bound(function)
                rule_id = self._rule_id(group, bounded_fee)
                rule = RULES[rule_id]
                evidence_id = f"custom:{rule_id}:{contract.name}:{function.name}"
                location = self._location(function)
                evidence.append(Evidence(
                    evidence_id=evidence_id,
                    kind="slither-dataflow",
                    source="smartrisk-custom-detectors",
                    locator={
                        "contract": contract.name,
                        "function": function.name,
                        "file": location.file if location else None,
                        "line": location.line if location else None,
                    },
                    details={
                        "storage_variables_written": writes,
                        "ir_operations": self._ir_text(function),
                        "authorization": authorization,
                        "fee_bound_detected": bounded_fee,
                    },
                ))
                findings.append(Finding(
                    finding_id=evidence_id,
                    engine="static",
                    rule_id=rule_id,
                    title=rule["title"],
                    description=f"{rule['description']} Function: {contract.name}.{function.name}.",
                    severity=rule["severity"],
                    confidence=0.9,
                    status="likely",
                    source_location=location,
                    evidence_refs=[evidence_id],
                    remediation=rule["remediation"],
                    metadata={
                        "contract": contract.name,
                        "function": function.name,
                        "detector": "slither-dataflow",
                        "storage_variables_written": writes,
                        "authorization": authorization,
                    },
                ))
        return findings, evidence, []

    @classmethod
    def _storage_writes(cls, function: Any, _visited: set[int] | None = None) -> list[str]:
        visited = _visited or set()
        marker = id(function)
        if marker in visited:
            return []
        visited.add(marker)
        variables = list(getattr(function, "state_variables_written", []) or [])
        if not variables:
            variables = list(getattr(function, "variables_written", []) or [])
        names: list[str] = []
        for variable in variables:
            name = getattr(variable, "name", None) or str(variable)
            if name not in names:
                names.append(name)
        # Slither does not expose identical transitive write lists across all
        # versions. Walk internal calls as a deterministic fallback so a public
        # wrapper cannot hide a sensitive write in an internal setter.
        for callee in getattr(function, "internal_calls", []) or []:
            for name in cls._storage_writes(callee, visited):
                if name not in names:
                    names.append(name)
        return names

    @classmethod
    def _group_for_writes(cls, writes: list[str]) -> str | None:
        normalized = [cls._normalized_name(value) for value in writes]
        if any(any(term in value for term in STATE_GROUPS["upgrade"]) for value in normalized):
            return "upgrade"
        if any(any(term in value for term in STATE_GROUPS["blacklist"]) for value in normalized):
            return "blacklist"
        if any(any(term in value for term in STATE_GROUPS["pause"]) for value in normalized):
            return "pause"
        if any(any(term in value for term in STATE_GROUPS["fee"]) for value in normalized):
            return "fee"
        if any(any(term in value for term in STATE_GROUPS["access"]) for value in normalized):
            return "access"
        if any(any(term in value for term in SUPPLY_HINTS) for value in normalized) and "totalsupply" in normalized:
            return "mint_burn"
        return None

    @classmethod
    def _group_for_function(cls, function: Any, writes: list[str]) -> str | None:
        group = cls._group_for_writes(writes)
        if group is not None:
            return group
        fn_text = cls._normalized_name(getattr(function, "name", ""))
        ir_text = " ".join(cls._ir_text(function)).lower()
        if any(term in fn_text for term in ("mint", "burn")) and any(
            cls._normalized_name(name) in {"balance", "balances", "totalsupply", "supply"}
            or any(hint in cls._normalized_name(name) for hint in SUPPLY_HINTS)
            for name in writes
        ):
            return "mint_burn"
        if any(term in fn_text for term in ("setbalance", "setbalances", "setsupply", "setsupplies", "setaccountbalance")) and any(
            any(hint in cls._normalized_name(name) for hint in ("balance", "balances", "supply", "totalsupply", "rowned", "towned"))
            for name in writes
        ):
            return "mint_burn"
        if any(term in fn_text for term in ("settrading", "enabletrading", "disabletrading", "setmax", "setcooldown", "setlimit", "setantibot", "setbot", "setexempt", "setfeeexempt")):
            return "trading"
        if ("fee" in fn_text or "tax" in fn_text) and ("set" in fn_text or "update" in fn_text or "change" in fn_text):
            return "fee"
        if any(any(term in cls._normalized_name(name) for term in STATE_GROUPS["trading"]) for name in writes):
            return "trading"
        if any(term in ir_text for term in ("tradingenabled", "maxtx", "maxwallet", "cooldown", "transferdelay", "selllimit", "buylimit")):
            return "trading"
        return None

    @staticmethod
    def _rule_id(group: str, bounded_fee: bool) -> str:
        if group == "upgrade":
            return "upgrade.unprotected"
        if group == "mint_burn":
            return "token.unprotected-mint-burn"
        if group == "blacklist":
            return "token.unprotected-blacklist"
        if group == "pause":
            return "token.unprotected-pause"
        if group == "fee":
            return "token.unprotected-fee" if bounded_fee else "token.unbounded-fee"
        if group == "trading":
            return "token.unprotected-trading-control"
        return "access.unprotected-sensitive-function"

    @classmethod
    def _authorization_evidence(cls, function: Any, _visited: set[int] | None = None) -> dict[str, Any]:
        visited = _visited or set()
        marker = id(function)
        if marker in visited:
            return {
                "detected": False, "strength": "none", "modifier_hits": [],
                "internal_call_hits": [], "inline_check_hits": [],
                "recursive_authorized_path": [], "authorization_observed": False,
            }
        visited.add(marker)
        modifiers = [str(getattr(modifier, "name", "")).lower() for modifier in getattr(function, "modifiers", []) or []]
        calls = list(getattr(function, "internal_calls", []) or [])
        internal = [str(getattr(call, "name", "")).lower() for call in calls]
        ir_lines = cls._ir_text(function)
        modifier_hits = [value for value in modifiers if any(hint in value for hint in AUTH_HINTS)]
        internal_hits = [value for value in internal if any(hint in value for hint in AUTH_HINTS)]
        inline_hits: list[str] = []
        for line in ir_lines:
            text = str(line).lower()
            if "msg.sender" in text and any(hint in text for hint in AUTH_HINTS):
                if any(token in text for token in ("require", "assert", "revert", "==", "!=")):
                    inline_hits.append("sender-authorization-check")
                    break
        recursive_paths: list[str] = []
        for callee in calls:
            child = cls._authorization_evidence(callee, visited)
            if child.get("detected"):
                recursive_paths.append(str(getattr(callee, "name", "<internal>")))
                recursive_paths.extend(str(item) for item in child.get("recursive_authorized_path", []))
        strength = "strong" if modifier_hits or internal_hits or recursive_paths else "medium" if inline_hits else "none"
        return {
            "detected": strength != "none",
            "strength": strength,
            "modifier_hits": modifier_hits,
            "internal_call_hits": internal_hits,
            "inline_check_hits": inline_hits,
            "recursive_authorized_path": sorted(set(recursive_paths)),
            "authorization_observed": strength != "none",
        }

    @staticmethod
    def _has_fee_bound(function: Any) -> bool:
        text = " ".join(CustomDetectorRunner._ir_text(function)).lower()
        bound_tokens = ("<=", "<", "max", "basispoint", "bps", "10000")
        return "require" in text and any(token in text for token in bound_tokens)

    @staticmethod
    def _ir_text(function: Any) -> list[str]:
        values: list[str] = []
        for node in getattr(function, "nodes", []) or []:
            for ir in getattr(node, "irs", []) or []:
                values.append(str(ir))
        return values

    @staticmethod
    def _externally_reachable(function: Any) -> bool:
        return str(getattr(function, "visibility", "")).lower() in {"public", "external"}

    @staticmethod
    def _normalized_name(value: str) -> str:
        return "".join(ch.lower() for ch in value if ch.isalnum())

    @staticmethod
    def _location(function: Any) -> SourceLocation | None:
        source = getattr(function, "source_mapping", None)
        if not source:
            return None
        filename_obj = getattr(source, "filename", None)
        filename = (
            getattr(filename_obj, "relative", None)
            or getattr(filename_obj, "used", None)
            or getattr(source, "filename_relative", None)
            or getattr(source, "filename_absolute", None)
        )
        lines = getattr(source, "lines", None) or []
        if not filename:
            return None
        return SourceLocation(file=str(filename), line=lines[0] if lines else None)

    @staticmethod
    @contextmanager
    def _temporary_environment(env: dict[str, str] | None):
        if env is None:
            yield
            return
        previous = os.environ.copy()
        os.environ.clear()
        os.environ.update(env)
        try:
            yield
        finally:
            os.environ.clear()
            os.environ.update(previous)

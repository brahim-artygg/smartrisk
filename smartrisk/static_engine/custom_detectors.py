from __future__ import annotations

import importlib.util
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any

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
}
AUTH_HINTS = (
    "owner", "onlyowner", "admin", "role", "auth", "operator", "governor", "guardian",
    "checkrole", "hasrole", "_authorize", "_checkowner",
)
SUPPLY_HINTS = ("totalsupply", "supply", "balance", "balances")


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
                group = self._group_for_writes(writes)
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

    @staticmethod
    def _storage_writes(function: Any) -> list[str]:
        variables = list(getattr(function, "state_variables_written", []) or [])
        if not variables:
            variables = list(getattr(function, "variables_written", []) or [])
        names = []
        for variable in variables:
            name = getattr(variable, "name", None) or str(variable)
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
        return "access.unprotected-sensitive-function"

    @classmethod
    def _authorization_evidence(cls, function: Any) -> dict[str, Any]:
        modifiers = [str(getattr(modifier, "name", "")).lower() for modifier in function.modifiers]
        internal = [str(getattr(call, "name", "")).lower() for call in getattr(function, "internal_calls", [])]
        ir_text = " ".join(cls._ir_text(function)).lower()
        modifier_hits = [value for value in modifiers if any(hint in value for hint in AUTH_HINTS)]
        internal_hits = [value for value in internal if any(hint in value for hint in AUTH_HINTS)]
        inline_hits = []
        if "msg.sender" in ir_text and any(token in ir_text for token in ("require", "assert", "revert", "owner", "admin", "role")):
            inline_hits.append("sender-check")
        return {
            "detected": bool(modifier_hits or internal_hits or inline_hits),
            "modifier_hits": modifier_hits,
            "internal_call_hits": internal_hits,
            "inline_check_hits": inline_hits,
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

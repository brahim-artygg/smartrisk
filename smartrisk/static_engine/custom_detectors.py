from __future__ import annotations

import importlib.util
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .models import Evidence, Finding, SourceLocation


RULES = {
    "access.unprotected-sensitive-function": {
        "title": "Sensitive function lacks an obvious authorization modifier",
        "description": "A public or external function changes privileged state but no owner/admin/role modifier was detected.",
        "severity": "high",
        "remediation": "Restrict the function with a well-defined role/owner modifier and test unauthorized callers.",
    },
    "upgrade.unprotected": {
        "title": "Upgrade or implementation control is not obviously protected",
        "description": "An upgrade or implementation-changing function is externally callable without an obvious authorization modifier.",
        "severity": "critical",
        "remediation": "Protect upgrades with a dedicated role, timelock or multisig and emit an upgrade event.",
    },
    "token.unprotected-mint-burn": {
        "title": "Mint or burn function lacks an obvious authorization modifier",
        "description": "A public or external mint/burn function is exposed without an obvious owner/admin/role modifier.",
        "severity": "critical",
        "remediation": "Restrict supply-changing operations and test totalSupply and balance invariants.",
    },
    "token.unprotected-blacklist": {
        "title": "Blacklist control lacks an obvious authorization modifier",
        "description": "A public or external blacklist/whitelist mutator is exposed without an obvious authorization modifier.",
        "severity": "high",
        "remediation": "Restrict blacklist changes to a documented role and emit auditable events.",
    },
    "token.unprotected-pause": {
        "title": "Pause control lacks an obvious authorization modifier",
        "description": "A public or external pause/unpause mutator is exposed without an obvious authorization modifier.",
        "severity": "high",
        "remediation": "Restrict pause controls and define emergency governance and unpause conditions.",
    },
    "token.unbounded-fee": {
        "title": "Fee or tax mutator has no obvious authorization modifier or bound",
        "description": "A public or external fee/tax mutator is exposed without an obvious authorization modifier or a detectable bound.",
        "severity": "high",
        "remediation": "Restrict fee changes, enforce a maximum, and test buy/sell accounting under the limit.",
    },
}

SENSITIVE_GROUPS = {
    "access": ("owner", "admin", "role", "governor", "guardian"),
    "upgrade": ("upgrade", "implementation", "proxy", "admin"),
    "mint_burn": ("mint", "burn"),
    "blacklist": ("blacklist", "whitelist", "denylist", "allowlist"),
    "pause": ("pause", "unpause"),
    "fee": ("fee", "tax", "basispoint", "bps"),
}
AUTH_HINTS = ("owner", "onlyowner", "admin", "role", "auth", "operator", "governor", "guardian")


class CustomDetectorRunner:
    """Semantic detectors using Slither's parsed contract model.

    The runner is optional: if Slither is unavailable the main engine returns
    unknown rather than pretending that source heuristics are AST evidence.
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
                name = self._normalized_name(function.name)
                group = self._group_for(name)
                if group is None:
                    continue
                protected = self._has_auth_hint(function)
                if protected:
                    continue
                rule_id = {
                    "access": "access.unprotected-sensitive-function",
                    "upgrade": "upgrade.unprotected",
                    "mint_burn": "token.unprotected-mint-burn",
                    "blacklist": "token.unprotected-blacklist",
                    "pause": "token.unprotected-pause",
                    "fee": "token.unbounded-fee",
                }[group]
                evidence_id = f"custom:{rule_id}:{contract.name}:{function.name}"
                location = self._location(function)
                evidence.append(Evidence(
                    evidence_id=evidence_id,
                    kind="slither-semantic",
                    source="smartrisk-custom-detectors",
                    locator={"contract": contract.name, "function": function.name},
                    details={"group": group, "modifiers": [m.name for m in function.modifiers]},
                ))
                rule = RULES[rule_id]
                findings.append(Finding(
                    finding_id=evidence_id,
                    engine="static",
                    rule_id=rule_id,
                    title=rule["title"],
                    description=f"{rule['description']} Function: {contract.name}.{function.name}.",
                    severity=rule["severity"],
                    confidence=0.78,
                    status="likely",
                    source_location=location,
                    evidence_refs=[evidence_id],
                    remediation=rule["remediation"],
                    metadata={"contract": contract.name, "function": function.name, "detector": "slither-semantic"},
                ))
        return findings, evidence, []

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

    @staticmethod
    def _externally_reachable(function: Any) -> bool:
        return str(getattr(function, "visibility", "")).lower() in {"public", "external"}

    @staticmethod
    def _normalized_name(value: str) -> str:
        return "".join(ch.lower() for ch in value if ch.isalnum())

    @staticmethod
    def _group_for(name: str) -> str | None:
        for group, terms in SENSITIVE_GROUPS.items():
            if any(term in name for term in terms):
                return group
        return None

    @staticmethod
    def _has_auth_hint(function: Any) -> bool:
        modifiers = [str(getattr(modifier, "name", "")).lower() for modifier in function.modifiers]
        if any(any(hint in modifier for hint in AUTH_HINTS) for modifier in modifiers):
            return True
        # Internal calls to common authorization helpers are a useful semantic hint.
        internal = [str(getattr(call, "name", "")).lower() for call in getattr(function, "internal_calls", [])]
        return any(any(hint in call for hint in AUTH_HINTS) for call in internal)

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

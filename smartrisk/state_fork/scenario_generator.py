from __future__ import annotations

import re
from typing import Any

from .models import SimulationScenario

KNOWN_SELECTORS = {
    "transfer(address,uint256)": "a9059cbb",
    "approve(address,uint256)": "095ea7b3",
    "transferFrom(address,address,uint256)": "23b872dd",
    "mint(address,uint256)": "40c10f19",
    "burn(uint256)": "42966c68",
    "pause()": "8456cb59",
    "unpause()": "3f4ba83a",
    "upgradeTo(address)": "3659cfe6",
    "upgradeToAndCall(address,bytes)": "4f1ef286",
    "grantRole(bytes32,address)": "2f2ff15d",
    "revokeRole(bytes32,address)": "d547741f",
    "renounceRole(bytes32,address)": "36568abe",
    "owner()": "8da5cb5b",
}

RISK_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("upgrade", ("upgrade", "implementation", "proxy", "authorizeupgrade")),
    ("privilege", ("owner", "admin", "role", "governor", "guardian", "operator")),
    ("supply", ("mint", "burn", "supply", "rebase")),
    ("restriction", ("blacklist", "whitelist", "allowlist", "denylist", "blocklist")),
    ("pause", ("pause", "unpause", "paused")),
    ("fee", ("fee", "tax", "basispoint", "bps")),
    ("limit", ("maxtx", "maxwallet", "maxtransaction", "maxbuy", "maxsell")),
    ("trading_gate", ("trading", "open", "enable", "launch")),
    ("drain", ("withdraw", "rescue", "recover", "emergency")),
    ("trading", ("swap", "buy", "sell", "router", "pair")),
    ("token_transfer", ("transfer", "approve", "transferfrom")),
)


class ScenarioGenerator:
    def __init__(self, sender: str, target: str, observed_tokens: tuple[str, ...] = (), amount: int = 1):
        self.sender = sender
        self.target = target
        self.observed_tokens = observed_tokens
        self.amount = amount

    def from_abi(self, abi: list[dict[str, Any]]) -> list[SimulationScenario]:
        scenarios: list[SimulationScenario] = []
        seen: set[str] = set()
        for item in abi:
            if item.get("type", "function") != "function" or not item.get("name"):
                continue
            inputs = item.get("inputs", [])
            signature = f"{item['name']}({','.join(input_type(i) for i in inputs)})"
            selector = KNOWN_SELECTORS.get(signature) or self._selector(signature)
            if signature in seen:
                continue
            seen.add(signature)
            args = [self._default_arg(i, item["name"], position) for position, i in enumerate(inputs)]
            category, tags = self.classify_function(item["name"])
            if item.get("stateMutability") in {"view", "pure"}:
                category, tags = "introspection", ("introspection",)
            scenarios.append(SimulationScenario(
                scenario_id=f"abi:{item['name']}", from_address=self.sender, to_address=self.target,
                data="0x" + selector + "".join(args), gas_limit=500_000,
                description=f"generated from {signature}", observed_tokens=self.observed_tokens,
                category=category, risk_tags=tags,
            ))
        return scenarios

    def from_source(self, source: str) -> list[SimulationScenario]:
        scenarios: list[SimulationScenario] = []
        seen: set[str] = set()
        for match in re.finditer(r"function\s+(\w+)\s*\(([^)]*)\)", source):
            name = match.group(1)
            raw_inputs = match.group(2)
            types = []
            for raw in raw_inputs.split(",") if raw_inputs.strip() else []:
                parts = raw.strip().split()
                if parts:
                    types.append(parts[0])
            signature = f"{name}({','.join(types)})"
            if signature in seen:
                continue
            seen.add(signature)
            category, tags = self.classify_function(name)
            scenarios.append(SimulationScenario(
                scenario_id=f"source:{name}", from_address=self.sender, to_address=self.target,
                data="0x" + self._selector(signature), gas_limit=500_000,
                description=f"selector generated from {signature}", observed_tokens=self.observed_tokens,
                category=category, risk_tags=tags,
            ))
        return scenarios

    def standard_scenarios(self) -> list[SimulationScenario]:
        """Generate a bounded set of standard control/supply/transfer probes.

        These are intentionally candidate scenarios. Execution code must treat
        reverts and unavailable prerequisites as observed outcomes, not as
        maliciousness conclusions.
        """
        candidates = [
            ("transfer", [self.target, self.amount], "token_transfer", ("token_transfer",)),
            ("approve", [self.target, self.amount], "token_transfer", ("approve",)),
            ("transferFrom", [self.sender, self.target, self.amount], "token_transfer", ("transfer_from",)),
            ("mint", [self.sender, self.amount], "supply", ("mint",)),
            ("burn", [self.amount], "supply", ("burn",)),
            ("pause", [], "pause", ("pause",)),
            ("unpause", [], "pause", ("pause",)),
            ("upgradeTo", [self.target], "upgrade", ("upgrade", "proxy")),
            ("grantRole", ["0x" + "00" * 32, self.sender], "privilege", ("role", "privilege")),
            ("revokeRole", ["0x" + "00" * 32, self.sender], "privilege", ("role", "privilege")),
            ("renounceRole", ["0x" + "00" * 32], "privilege", ("role", "privilege")),
            ("owner", [], "introspection", ("introspection",)),
        ]
        scenarios: list[SimulationScenario] = []
        for name, args, category, tags in candidates:
            signature = self._standard_signature(name, args)
            selector = KNOWN_SELECTORS.get(signature) or self._selector(signature)
            encoded = "".join(self._encode_standard_arg(arg) for arg in args)
            scenarios.append(SimulationScenario(
                scenario_id=f"standard:{name}", from_address=self.sender, to_address=self.target,
                data="0x" + selector + encoded, gas_limit=500_000,
                description=f"standard probe for {signature}", observed_tokens=self.observed_tokens,
                category=category, risk_tags=tags,
            ))
        return scenarios

    @staticmethod
    def _standard_signature(name: str, args: list[Any]) -> str:
        types = {"transfer": ["address", "uint256"], "approve": ["address", "uint256"], "transferFrom": ["address", "address", "uint256"], "mint": ["address", "uint256"], "burn": ["uint256"], "upgradeTo": ["address"], "grantRole": ["bytes32", "address"], "revokeRole": ["bytes32", "address"], "renounceRole": ["bytes32", "address"], "pause": [], "unpause": [], "owner": []}
        return f"{name}({','.join(types.get(name, ["uint256"] * len(args)))})"

    @staticmethod
    def _encode_standard_arg(value: Any) -> str:
        if isinstance(value, int):
            return hex(value)[2:].rjust(64, "0")
        text = str(value)
        if text.startswith("0x") and len(text) <= 42:
            return text[2:].lower().rjust(64, "0")
        if text.startswith("0x") and len(text) == 66:
            return text[2:].lower()
        return "0".rjust(64, "0")

    @staticmethod
    def classify_function(function_name: str) -> tuple[str, tuple[str, ...]]:
        normalized = re.sub(r"[^a-z0-9]", "", function_name.lower())
        tags: list[str] = []
        for category, terms in RISK_PATTERNS:
            if any(term in normalized for term in terms) and category not in tags:
                tags.append(category)
        return (tags[0], tuple(tags)) if tags else ("generic", ("generic",))

    @staticmethod
    def _selector(signature: str) -> str:
        from ..core.keccak import ethereum_selector
        return ethereum_selector(signature)

    def _default_arg(self, item: dict[str, Any], function_name: str, position: int) -> str:
        type_name = item.get("type", "")
        if type_name == "address":
            value = self.sender if function_name in {"transferFrom", "approve", "grantRole", "revokeRole", "renounceRole"} and position == 0 else self.target
            return value[2:].lower().rjust(64, "0")
        if type_name.startswith("uint") or type_name.startswith("int"):
            return hex(max(1, self.amount))[2:].rjust(64, "0")
        if type_name == "bool":
            return "1".rjust(64, "0")
        if type_name == "bytes32":
            return "0".rjust(64, "0")
        if type_name.startswith("bytes") or type_name == "string":
            return "0".rjust(64, "0")
        return "0".rjust(64, "0")


def input_type(item: dict[str, Any]) -> str:
    return str(item.get("type", ""))

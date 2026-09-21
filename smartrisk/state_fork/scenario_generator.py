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
    "grantRole(bytes32,address)": "2f2ff15d",
    "revokeRole(bytes32,address)": "d547741f",
    "renounceRole(bytes32,address)": "36568abe",
    "owner()": "8da5cb5b",
}


class ScenarioGenerator:
    def __init__(self, sender: str, target: str, observed_tokens: tuple[str, ...] = (), amount: int = 1):
        self.sender = sender
        self.target = target
        self.observed_tokens = observed_tokens
        self.amount = amount

    def from_abi(self, abi: list[dict[str, Any]]) -> list[SimulationScenario]:
        scenarios = []
        for item in abi:
            if item.get("type", "function") != "function" or not item.get("name"):
                continue
            inputs = item.get("inputs", [])
            signature = f"{item['name']}({','.join(input_type(i) for i in inputs)})"
            selector = KNOWN_SELECTORS.get(signature) or self._selector(signature)
            if not selector:
                continue
            args = [self._default_arg(i, item["name"], position) for position, i in enumerate(inputs)]
            data = "0x" + selector + "".join(args)
            scenarios.append(SimulationScenario(
                scenario_id=f"abi:{item['name']}", from_address=self.sender, to_address=self.target,
                data=data, gas_limit=500_000, description=f"generated from {signature}", observed_tokens=self.observed_tokens,
            ))
        return scenarios

    def from_source(self, source: str) -> list[SimulationScenario]:
        scenarios = []
        for match in re.finditer(r"function\s+(\w+)\s*\(([^)]*)\)", source):
            name = match.group(1)
            types = []
            for raw in match.group(2).split(",") if match.group(2).strip() else []:
                parts = raw.strip().split()
                if parts:
                    types.append(parts[0])
            signature = f"{name}({','.join(types)})"
            selector = KNOWN_SELECTORS.get(signature) or self._selector(signature)
            if selector:
                scenarios.append(SimulationScenario(f"source:{name}", self.sender, self.target, "0x" + selector, gas_limit=500_000, description=f"selector generated from {signature}", observed_tokens=self.observed_tokens))
        return scenarios

    @staticmethod
    def _selector(signature: str) -> str | None:
        try:
            from Crypto.Hash import keccak
            digest = keccak.new(digest_bits=256)
            digest.update(signature.encode())
            return digest.hexdigest()[:8]
        except ImportError:
            return None

    def _default_arg(self, item: dict[str, Any], function_name: str, position: int) -> str:
        type_name = item.get("type", "")
        if type_name == "address":
            value = self.sender if function_name in {"transferFrom", "approve", "grantRole", "revokeRole", "renounceRole"} and position == 0 else self.target
            return value[2:].lower().rjust(64, "0")
        if type_name.startswith("uint") or type_name.startswith("int"):
            return hex(self.amount)[2:].rjust(64, "0")
        if type_name == "bool":
            return "1".rjust(64, "0")
        if type_name == "bytes32":
            return "0".rjust(64, "0")
        return "0".rjust(64, "0")


def input_type(item: dict[str, Any]) -> str:
    return str(item.get("type", ""))

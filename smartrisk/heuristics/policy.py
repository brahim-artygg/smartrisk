from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PolicyRegistry:
    version: str
    rules: dict[str, dict[str, Any]]
    families: dict[str, dict[str, Any]]

    @classmethod
    def load(cls, path: str | Path | None = None) -> "PolicyRegistry":
        if path is None:
            default_path = Path(__file__).resolve().parents[2] / "policies" / "score-v0.4.json"
            if default_path.exists():
                path = default_path
            else:
                return cls("score-v0.4", {}, {})
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(payload["version"], payload.get("rules", {}), payload.get("families", {}))

    def rule(self, rule_id: str) -> dict[str, Any]:
        return self.rules.get(rule_id, {})

    def weight(self, rule_id: str, fallback: float) -> float:
        return float(self.rule(rule_id).get("weight", fallback))

    def family(self, family: str) -> dict[str, Any]:
        return self.families.get(family, {})

    def family_cap(self, family: str, fallback: float = 100.0) -> float:
        return float(self.family(family).get("cap", fallback))

    def expired(self, rule_id: str) -> bool:
        expiry = self.rule(rule_id).get("expiry")
        return bool(expiry and date.today() > date.fromisoformat(expiry))

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.version:
            errors.append("policy version is empty")
        for family, config in self.families.items():
            cap = config.get("cap")
            if cap is None or not isinstance(cap, (int, float)) or cap < 0:
                errors.append(f"family {family} has an invalid cap")
        for rule_id, config in self.rules.items():
            weight = config.get("weight", 0)
            if not isinstance(weight, (int, float)) or weight < 0:
                errors.append(f"rule {rule_id} has an invalid weight")
            family = config.get("family", rule_id.split(".")[0])
            if family not in self.families:
                errors.append(f"rule {rule_id} references unknown family {family}")
            factor = config.get("confidence_factor", 1.0)
            if not isinstance(factor, (int, float)) or not 0 <= factor <= 1:
                errors.append(f"rule {rule_id} has invalid confidence_factor")
            expiry = config.get("expiry")
            if expiry:
                try:
                    date.fromisoformat(str(expiry))
                except ValueError:
                    errors.append(f"rule {rule_id} has invalid expiry")
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "rules": self.rules, "families": self.families}

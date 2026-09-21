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
            return cls("score-v0.1", {}, {})
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

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "rules": self.rules, "families": self.families}

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

from .contract_intelligence import BytecodeProfile


@dataclass(frozen=True)
class Fingerprint:
    fingerprint_id: str
    category: str
    confidence: float
    signals: tuple[str, ...]
    explanation: str
    status: str = "indicator"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ScamFingerprintAnalyzer:
    """Deterministic combinations of observable bytecode signals.

    Fingerprints are correlation indicators only. No single fingerprint is a
    maliciousness verdict, and missing information stays unknown.
    """

    VERSION = "fingerprints-v0.1"

    def analyze(self, profile: BytecodeProfile) -> list[Fingerprint]:
        flags = profile.flags
        selectors = {item.lower() for item in profile.push4_selectors}
        findings: list[Fingerprint] = []

        if flags.get("has_timestamp") or flags.get("has_block_number"):
            time_signals = []
            if flags.get("has_timestamp"):
                time_signals.append("TIMESTAMP opcode")
            if flags.get("has_block_number"):
                time_signals.append("NUMBER opcode")
            if flags.get("has_sstore"):
                time_signals.append("SSTORE state mutation")
            if flags.get("has_delegatecall") or flags.get("has_call"):
                time_signals.append("external execution primitive")
            if len(time_signals) >= 2:
                findings.append(Fingerprint(
                    "deferred.time-dependent-state", "deferred_behavior", 0.72,
                    tuple(time_signals),
                    "Time/block-dependent execution is combined with state mutation or external execution; deferred behavior merits control-flow review.",
                ))

        upgrade_selectors = {"0x3659cfe6", "0x4f1ef286"}
        if selectors & upgrade_selectors and (flags.get("has_delegatecall") or flags.get("has_sstore")):
            findings.append(Fingerprint(
                "upgrade.runtime-control-surface", "privileged_upgrade", 0.78,
                tuple(sorted(selectors & upgrade_selectors)) + (("DELEGATECALL",) if flags.get("has_delegatecall") else ()) + (("SSTORE",) if flags.get("has_sstore") else ()),
                "Upgrade-related selector evidence coincides with runtime delegate execution or state mutation.",
            ))

        if flags.get("has_selfdestruct") and (flags.get("has_delegatecall") or flags.get("has_call")):
            findings.append(Fingerprint(
                "destruction.external-control", "destructive_capability", 0.75,
                tuple(x for x in ("SELFDESTRUCT", "DELEGATECALL" if flags.get("has_delegatecall") else "CALL") if x),
                "Destructive bytecode capability is combined with external execution. This is a capability correlation, not proof of malicious use.",
            ))

        fee_markers = {"0x8456cb59", "0x3f4ba83a"} & selectors
        if fee_markers and (flags.get("has_sstore") or flags.get("has_call")):
            findings.append(Fingerprint(
                "control.pause-surface", "trading_control", 0.62,
                tuple(sorted(fee_markers)) + (("SSTORE",) if flags.get("has_sstore") else ()) + (("CALL",) if flags.get("has_call") else ()),
                "Pause/unpause selector evidence is present with a stateful or external execution surface; review authorization and event coverage.",
            ))

        if flags.get("has_origin") and flags.get("has_sstore"):
            findings.append(Fingerprint(
                "authorization.tx-origin-state", "authorization", 0.68,
                ("ORIGIN opcode", "SSTORE"),
                "The runtime reads transaction origin and also mutates state. Review whether origin participates in authorization decisions.",
            ))

        if flags.get("has_create2") and (flags.get("has_timestamp") or flags.get("has_block_number")):
            findings.append(Fingerprint(
                "deployment.deterministic-time-coupling", "deferred_behavior", 0.58,
                ("CREATE2", "TIMESTAMP/NUMBER"),
                "Deterministic deployment is combined with time/block dependence; inspect whether deployment behavior varies with chain context.",
            ))

        return findings

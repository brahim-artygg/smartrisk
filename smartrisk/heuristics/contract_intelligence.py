from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any



# Minimal EVM opcode table sufficient for deterministic bytecode profiling.
# PUSH/DUP/SWAP ranges are derived from the yellow-paper opcode layout.
OPCODES: dict[int, str] = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV",
    0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD",
    0x0A: "EXP", 0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ",
    0x15: "ISZERO", 0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT", 0x1A: "BYTE",
    0x20: "KECCAK256", 0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER",
    0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY",
    0x38: "CODESIZE", 0x39: "CODECOPY", 0x3A: "GASPRICE", 0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY", 0x3D: "RETURNDATASIZE", 0x3E: "RETURNDATACOPY", 0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER", 0x44: "DIFFICULTY",
    0x45: "GASLIMIT", 0x46: "CHAINID", 0x47: "SELFBALANCE", 0x48: "BASEFEE", 0x50: "POP",
    0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8", 0x54: "SLOAD", 0x55: "SSTORE",
    0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE", 0x5A: "GAS", 0x5B: "JUMPDEST",
    0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN", 0xF4: "DELEGATECALL",
    0xF5: "CREATE2", 0xFA: "STATICCALL", 0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
}

EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"


def _hex_to_bytes(code: str) -> bytes:
    value = (code or "0x").lower()
    if value.startswith("0x"):
        value = value[2:]
    if not value:
        return b""
    if len(value) % 2:
        value = "0" + value
    try:
        return bytes.fromhex(value)
    except ValueError:
        return b""


def normalize_address(value: Any) -> str | None:
    if not isinstance(value, str) or not value.startswith("0x"):
        return None
    raw = value[2:]
    if len(raw) != 40:
        return None
    try:
        int(raw, 16)
    except ValueError:
        return None
    address = "0x" + raw.lower()
    return None if int(raw, 16) == 0 else address


def word_to_address(word: str | None) -> str | None:
    if not isinstance(word, str):
        return None
    value = word.lower().replace("0x", "")
    if len(value) < 40:
        return None
    return normalize_address("0x" + value[-40:])


@dataclass
class BytecodeProfile:
    code_hash: str
    byte_length: int
    opcode_count: int
    push4_selectors: list[str] = field(default_factory=list)
    opcode_counts: dict[str, int] = field(default_factory=dict)
    flags: dict[str, bool] = field(default_factory=dict)
    suspicious_constants: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code_hash": self.code_hash,
            "byte_length": self.byte_length,
            "opcode_count": self.opcode_count,
            "push4_selectors": self.push4_selectors,
            "opcode_counts": self.opcode_counts,
            "flags": self.flags,
            "suspicious_constants": self.suspicious_constants,
        }


class BytecodeAnalyzer:
    """Dependency-free EVM bytecode profiler and high-signal capability detector."""

    def analyze(self, code: str) -> BytecodeProfile:
        raw = _hex_to_bytes(code)
        digest = hashlib.sha256(raw).hexdigest()
        counts: dict[str, int] = {}
        selectors: list[str] = []
        suspicious: list[str] = []
        i = 0
        opcode_count = 0
        while i < len(raw):
            op = raw[i]
            name = OPCODES.get(op)
            if name is None:
                if 0x60 <= op <= 0x7F:
                    name = f"PUSH{op - 0x5F}"
                elif 0x80 <= op <= 0x8F:
                    name = f"DUP{op - 0x7F}"
                elif 0x90 <= op <= 0x9F:
                    name = f"SWAP{op - 0x8F}"
                elif 0xA0 <= op <= 0xA4:
                    name = f"LOG{op - 0x9F}"
                else:
                    name = f"0x{op:02x}"
            counts[name] = counts.get(name, 0) + 1
            opcode_count += 1
            if 0x60 <= op <= 0x7F:
                width = op - 0x5F
                data = raw[i + 1:i + 1 + width]
                if op == 0x63 and len(data) == 4:
                    selector = "0x" + data.hex()
                    if selector not in selectors:
                        selectors.append(selector)
                i += 1 + width
                continue
            i += 1
        for value, label in ((0x3659CFE6, "upgradeTo(address) selector-like constant"),
                             (0x4F1EF286, "upgradeToAndCall(address,bytes) selector-like constant"),
                             (0x8456CB59, "pause() selector-like constant"),
                             (0x3F4BA83A, "unpause() selector-like constant"),
                             (0x8DA5CB5B, "owner() selector-like constant")):
            marker = value.to_bytes(4, "big")
            if marker in raw:
                suspicious.append(label)
        flags = {
            "has_sstore": counts.get("SSTORE", 0) > 0,
            "has_sload": counts.get("SLOAD", 0) > 0,
            "has_delegatecall": counts.get("DELEGATECALL", 0) > 0,
            "has_call": counts.get("CALL", 0) > 0,
            "has_staticcall": counts.get("STATICCALL", 0) > 0,
            "has_create": counts.get("CREATE", 0) > 0,
            "has_create2": counts.get("CREATE2", 0) > 0,
            "has_selfdestruct": counts.get("SELFDESTRUCT", 0) > 0,
            "has_origin": counts.get("ORIGIN", 0) > 0,
            "has_timestamp": counts.get("TIMESTAMP", 0) > 0,
            "has_block_number": counts.get("NUMBER", 0) > 0,
        }
        return BytecodeProfile(digest, len(raw), opcode_count, selectors[:256], counts, flags, suspicious[:32])


@dataclass
class PrivilegeProfile:
    owner: str | None = None
    admin: str | None = None
    implementation: str | None = None
    beacon: str | None = None
    upgradeable: bool | None = None
    observable_capabilities: dict[str, bool] = field(default_factory=dict)
    storage_observations: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "owner": self.owner,
            "admin": self.admin,
            "implementation": self.implementation,
            "beacon": self.beacon,
            "upgradeable": self.upgradeable,
            "observable_capabilities": self.observable_capabilities,
            "storage_observations": self.storage_observations,
        }


class ContractIntelligence:
    """Builds deterministic contract facts from runtime code and optional storage reads."""

    def build_recursive_profile(
        self,
        code: str,
        storage: dict[str, str] | None = None,
        calls: dict[str, Any] | None = None,
        implementation_loader: Any | None = None,
        max_depth: int = 2,
    ) -> dict[str, Any]:
        """Build the local proxy profile and recursively inspect EIP-1967 implementations.

        The loader is deliberately injected so this class remains deterministic and
        dependency-free. A failed loader yields an explicit unknown entry.
        """
        profile = self.build_profile(code, storage=storage, calls=calls)
        chain: list[dict[str, Any]] = []
        implementation = profile.get("privileges", {}).get("implementation")
        visited: set[str] = set()
        current = implementation
        depth = 0
        while current and depth < max_depth:
            normalized = str(current).lower()
            if normalized in visited:
                chain.append({"depth": depth + 1, "address": current, "status": "cycle_detected"})
                break
            visited.add(normalized)
            if not callable(implementation_loader):
                chain.append({"depth": depth + 1, "address": current, "status": "unknown", "reason": "implementation loader unavailable"})
                break
            try:
                implementation_code = implementation_loader(current)
            except Exception as exc:
                chain.append({"depth": depth + 1, "address": current, "status": "unknown", "reason": str(exc)})
                break
            nested = self.build_profile(str(implementation_code or "0x"))
            bytecode = nested.get("bytecode", {})
            chain.append({
                "depth": depth + 1,
                "address": current,
                "status": "observed" if nested.get("is_contract") else "unknown",
                "code_hash": bytecode.get("code_hash"),
                "byte_length": bytecode.get("byte_length"),
                "observable_capabilities": nested.get("observable_capabilities", {}),
                "scam_fingerprints": nested.get("scam_fingerprints", {}),
            })
            current = nested.get("privileges", {}).get("implementation")
            depth += 1
        profile["proxy_chain"] = {"max_depth": max_depth, "items": chain, "depth_observed": len(chain)}
        return profile

    def build_profile(
        self,
        code: str,
        storage: dict[str, str] | None = None,
        calls: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        code_present = bool(_hex_to_bytes(code))
        bytecode = BytecodeAnalyzer().analyze(code)
        from .scam_fingerprints import ScamFingerprintAnalyzer
        fingerprints = [item.to_dict() for item in ScamFingerprintAnalyzer().analyze(bytecode)]
        flags = bytecode.flags
        storage = storage or {}
        calls = calls or {}
        implementation = word_to_address(storage.get(EIP1967_IMPLEMENTATION_SLOT))
        admin = word_to_address(storage.get(EIP1967_ADMIN_SLOT))
        beacon = word_to_address(storage.get(EIP1967_BEACON_SLOT))
        proxy_detected = bool(implementation or beacon)
        owner = normalize_address(calls.get("owner"))
        capability = {
            "can_execute_delegatecall": flags["has_delegatecall"],
            "can_call_external": flags["has_call"],
            "can_write_storage": flags["has_sstore"],
            "can_selfdestruct_pattern": flags["has_selfdestruct"],
            "can_create_contract": flags["has_create"] or flags["has_create2"],
            "uses_time_or_block_condition": flags["has_timestamp"] or flags["has_block_number"],
            "owner_readable": owner is not None,
            "proxy_detected": proxy_detected,
        }
        return {
            "is_contract": code_present,
            "bytecode": bytecode.to_dict(),
            "observable_capabilities": capability,
            "scam_fingerprints": {
                "version": ScamFingerprintAnalyzer.VERSION,
                "items": fingerprints,
                "count": len(fingerprints),
            },
            "privileges": {
                "owner": owner,
                "admin": admin,
                "implementation": implementation,
                "beacon": beacon,
                "upgradeable": proxy_detected,
                "storage": {
                    "implementation": storage.get(EIP1967_IMPLEMENTATION_SLOT),
                    "admin": storage.get(EIP1967_ADMIN_SLOT),
                    "beacon": storage.get(EIP1967_BEACON_SLOT),
                },
                "calls": calls,
            },
        }

from __future__ import annotations

from typing import Any

ERROR_STRING_SELECTOR = "0x08c379a0"
PANIC_SELECTOR = "0x4e487b71"


def decode_revert_data(data: Any) -> dict[str, Any]:
    """Decode common Solidity revert payloads without guessing unknown formats."""
    raw = str(data or "")
    if not raw.startswith("0x"):
        return {"status": "unknown", "raw": data, "selector": None, "reason": None}
    payload = raw[2:]
    if len(payload) < 8:
        return {"status": "unknown", "raw": raw, "selector": None, "reason": None}
    selector = "0x" + payload[:8]
    body = payload[8:]
    if selector == ERROR_STRING_SELECTOR and len(body) >= 128:
        try:
            offset = int(body[:64], 16)
            length_pos = offset * 2
            length = int(body[length_pos:length_pos + 64], 16)
            text_start = length_pos + 64
            text = bytes.fromhex(body[text_start:text_start + length * 2]).decode("utf-8", errors="replace")
            return {"status": "decoded", "raw": raw, "selector": selector, "type": "Error(string)", "reason": text}
        except (ValueError, UnicodeDecodeError):
            pass
    if selector == PANIC_SELECTOR and len(body) >= 64:
        try:
            code = int(body[:64], 16)
            known = {
                0x01: "assertion failed",
                0x11: "arithmetic overflow/underflow",
                0x12: "division or modulo by zero",
                0x21: "invalid enum conversion",
                0x22: "incorrectly encoded storage byte array",
                0x31: "pop on empty array",
                0x32: "array index out of bounds",
                0x41: "memory allocation overflow",
                0x51: "call to uninitialized function",
            }
            return {"status": "decoded", "raw": raw, "selector": selector, "type": "Panic(uint256)", "panic_code": code, "reason": known.get(code, f"panic code 0x{code:x}")}
        except ValueError:
            pass
    return {"status": "unknown", "raw": raw, "selector": selector, "reason": None}

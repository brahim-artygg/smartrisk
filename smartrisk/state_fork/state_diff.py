from __future__ import annotations

from typing import Any


def normalize_prestate_diff(trace: Any) -> dict[str, Any]:
    """Normalize common Geth/Anvil prestateTracer diff shapes.

    The tracer is optional. Unsupported shapes are retained as ``raw`` and do
    not become a false zero-diff result.
    """
    if not isinstance(trace, dict):
        return {"status": "unknown", "accounts": {}, "raw": trace, "unknown_reasons": ["prestate trace is not an object"]}

    pre = trace.get("pre") if isinstance(trace.get("pre"), dict) else None
    post = trace.get("post") if isinstance(trace.get("post"), dict) else None
    if pre is not None or post is not None:
        return _compare_account_maps(pre or {}, post or {}, raw=trace)

    accounts: dict[str, Any] = {}
    direct_entries = {k: v for k, v in trace.items() if isinstance(v, dict) and k not in {"error", "type"}}
    for address, entry in direct_entries.items():
        if any(key in entry for key in ("from", "to")):
            accounts[address.lower()] = _account_from_diff(entry)
        elif isinstance(entry.get("pre"), dict) or isinstance(entry.get("post"), dict):
            pair = _account_from_pre_post(entry.get("pre") or {}, entry.get("post") or {})
            accounts[address.lower()] = pair
        elif isinstance(entry.get("storage"), dict):
            changed_storage = {}
            for slot, value in entry["storage"].items():
                if isinstance(value, dict) and ("from" in value or "to" in value):
                    changed_storage[str(slot)] = {"before": value.get("from"), "after": value.get("to")}
            if changed_storage:
                accounts[address.lower()] = {"storage": changed_storage}

    if accounts:
        return {"status": "complete", "accounts": accounts, "raw": trace, "unknown_reasons": []}
    return {"status": "unknown", "accounts": {}, "raw": trace, "unknown_reasons": ["unsupported prestateTracer response shape"]}


def _compare_account_maps(pre: dict[str, Any], post: dict[str, Any], raw: Any) -> dict[str, Any]:
    accounts: dict[str, Any] = {}
    for address in sorted(set(pre) | set(post)):
        accounts[address.lower()] = _account_from_pre_post(pre.get(address) or {}, post.get(address) or {})
    changed = {address: value for address, value in accounts.items() if value}
    return {"status": "complete", "accounts": changed, "raw": raw, "unknown_reasons": []}


def _account_from_pre_post(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if before.get("balance") is not None or after.get("balance") is not None:
        old = _hex_int(before.get("balance"))
        new = _hex_int(after.get("balance"))
        result["balance"] = {"before": old, "after": new, "delta": new - old if old is not None and new is not None else None}
    if before.get("nonce") is not None or after.get("nonce") is not None:
        old = _hex_int(before.get("nonce"))
        new = _hex_int(after.get("nonce"))
        result["nonce"] = {"before": old, "after": new, "delta": new - old if old is not None and new is not None else None}
    if "code" in before or "code" in after:
        old = before.get("code")
        new = after.get("code")
        if old != new:
            result["code"] = {"before": old, "after": new, "changed": True}
    storage = _storage_diff(before.get("storage") or {}, after.get("storage") or {})
    if storage:
        result["storage"] = storage
    return result


def _account_from_diff(entry: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for field in ("balance", "nonce"):
        value = entry.get(field)
        if isinstance(value, dict) and ("from" in value or "to" in value):
            old = _hex_int(value.get("from"))
            new = _hex_int(value.get("to"))
            result[field] = {"before": old, "after": new, "delta": new - old if old is not None and new is not None else None}
    if isinstance(entry.get("code"), dict):
        old, new = entry["code"].get("from"), entry["code"].get("to")
        if old != new:
            result["code"] = {"before": old, "after": new, "changed": True}
    if isinstance(entry.get("storage"), dict):
        storage = {}
        for slot, value in entry["storage"].items():
            if isinstance(value, dict) and ("from" in value or "to" in value):
                storage[str(slot)] = {"before": value.get("from"), "after": value.get("to")}
        if storage:
            result["storage"] = storage
    return result


def _storage_diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    changes: dict[str, Any] = {}
    for slot in sorted(set(before) | set(after)):
        old = before.get(slot)
        new = after.get(slot)
        if old != new:
            changes[str(slot)] = {"before": old, "after": new}
    return changes


def _hex_int(value: Any) -> int | None:
    try:
        if isinstance(value, str):
            return int(value, 16) if value.startswith("0x") else int(value)
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None

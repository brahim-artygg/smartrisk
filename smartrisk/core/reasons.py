from __future__ import annotations


def reason_code_for_exception(exc: BaseException) -> str:
    """Map provider/runtime failures to stable machine-readable codes."""
    text = str(exc).lower()
    if "budget" in text or "cap exceeded" in text:
        return "RPC_BUDGET_EXCEEDED"
    if "429" in text or "rate limit" in text or "rate_limit" in text:
        return "RPC_RATE_LIMITED"
    if "timeout" in text or "timed out" in text:
        return "RPC_TIMEOUT"
    if "required" in text and ("alchemy" in text or "rpc" in text):
        return "RPC_NOT_CONFIGURED"
    if "invalid" in text or "malformed" in text:
        return "RPC_INVALID_RESPONSE"
    if "method" in text and ("not found" in text or "unsupported" in text):
        return "RPC_METHOD_UNSUPPORTED"
    return "RPC_ERROR"


def reasoned_message(exc: BaseException) -> str:
    return f"{reason_code_for_exception(exc)}: {str(exc)[:300]}"

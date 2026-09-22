from __future__ import annotations

import re
from typing import Any

from ..core.networks import try_get_network

ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

_DIMENSION_LABELS = {
    "contract_security": "Contract Security",
    "ownership_security": "Owner Permissions",
    "trading_security": "Sellability & Trading",
    "liquidity_market": "Liquidity",
    "holder_distribution": "Holder Concentration",
    "historical_behavior": "Historical Behavior",
}

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def validate_address(value: Any) -> str:
    if not isinstance(value, str) or not ADDRESS_RE.fullmatch(value.strip()):
        raise ValueError("Enter a valid EVM contract address.")
    return value.strip().lower()


def _text(value: Any, default: str = "", limit: int = 500) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text[:limit]


def _network_name(chain_id: Any) -> str | None:
    if chain_id in (None, ""):
        return None
    profile = try_get_network(str(chain_id))
    return profile.name if profile else f"Chain {chain_id}"


def _public_finding(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "title": _text(item.get("title") or item.get("rule_id") or "Risk signal", "Risk signal", 180),
        "severity": _text(item.get("severity"), "signal", 40).lower(),
        "status": _text(item.get("status"), "observed", 80),
        "description": _text(item.get("description"), "", 500),
    }


def format_public_result(job: dict[str, Any], *, base_path: str = "/scan") -> dict[str, Any]:
    """Return a minimal, user-facing representation of an Embed scan.

    This deliberately excludes the raw request, evidence graph, engine reports,
    internal assumptions and other implementation details.
    """
    request = job.get("request") or {}
    report = job.get("result") or {}
    chain_id = request.get("chain_id")
    address = request.get("token_address")
    risk = dict(report.get("risk") or {})
    verdict = dict(report.get("verdict") or {})
    primary = dict(verdict.get("primary_detection") or report.get("primary_detection") or {})

    findings = [item for item in (report.get("findings") or []) if isinstance(item, dict)]
    findings.sort(key=lambda item: _SEVERITY_RANK.get(str(item.get("severity") or "").lower(), 9))

    dimensions: list[dict[str, Any]] = []
    for key, value in (report.get("risk_dimensions") or {}).items():
        if not isinstance(value, dict):
            continue
        signals = value.get("signals")
        severity = value.get("severity") or value.get("band")
        if signals is None and severity is None and not value:
            continue
        dimensions.append({
            "id": _text(key, limit=80),
            "label": _DIMENSION_LABELS.get(key, key.replace("_", " ").title()),
            "signals": int(signals or 0) if str(signals or "").isdigit() else signals,
            "severity": _text(severity, "unknown", 40).lower(),
        })

    return {
        "schema_version": "1.0",
        "job_id": job.get("job_id"),
        "status": job.get("status"),
        "address": address,
        "chain_id": chain_id,
        "network": _network_name(chain_id),
        "risk": {
            "score": risk.get("score"),
            "band": _text(risk.get("band"), "unknown", 40).lower(),
            "confidence": risk.get("confidence"),
            "coverage": risk.get("coverage"),
            "score_direction": "higher_is_more_risky",
        },
        "verdict": {
            "code": _text(verdict.get("code"), "UNVERIFIED", 80),
            "label": _text(verdict.get("label"), "UNVERIFIED", 120),
        },
        "primary_detection": {
            "title": _text(primary.get("title") or primary.get("label"), "No primary detection", 180),
            "explanation": _text(primary.get("explanation") or primary.get("description"), "", 500),
        },
        "signals": [_public_finding(item) for item in findings[:6]],
        "risk_dimensions": dimensions[:8],
        "unknowns_count": len(report.get("unknowns") or []),
        "full_report_url": f"{base_path}/{job.get('job_id')}",
    }

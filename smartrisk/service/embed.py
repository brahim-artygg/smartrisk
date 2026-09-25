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

# Curated, non-sensitive measurements that the free report may show. The public
# envelope used to drop every feature, so the results page could only ever render
# "Not verified" for a clean token. Only scalar values from this allow-list leave the server.
_PUBLIC_METRICS = (
    "chain.token_has_code",
    "market.best_liquidity_usd", "market.pair_count", "market.volume_h24_usd",
    "market.buys_h24", "market.sells_h24", "market.pair_age_hours",
    "liquidity.pair_count_analyzed", "liquidity.max_lp_top1_share", "liquidity.max_lp_burned_share",
    "holders.holder_count", "holders.top10_concentration", "holders.top20_concentration",
    "holders.deployer_candidate_share",
    "history.transfer_count", "history.unique_buyers", "history.unique_sellers",
    "contract.owner_observed", "contract.admin_observed", "contract.proxy_detected",
)


def _public_metrics(report: dict[str, Any]) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    for engine in report.get("engines") or []:
        if not isinstance(engine, dict) or engine.get("name") != "heuristics":
            continue
        features = ((engine.get("report") or {}).get("risk") or {}).get("features") or []
        for item in features:
            if not isinstance(item, dict):
                continue
            feature_id = item.get("feature_id")
            value = item.get("value")
            if feature_id in _PUBLIC_METRICS and value is not None and isinstance(value, (bool, int, float)):
                metrics[feature_id] = value
    return metrics


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


def _public_check(item: dict[str, Any]) -> dict[str, Any]:
    """Keep check state explicit while excluding raw payloads and internal traces."""
    return {
        "check_id": _text(item.get("check_id"), "unknown", 100),
        "label": _text(item.get("label"), "Check", 180),
        "state": _text(item.get("state"), "unknown", 30).lower(),
        "value": item.get("value"),
        "reason_code": _text(item.get("reason_code"), "", 80) or None,
        "reason": _text(item.get("reason"), "", 300) or None,
        "source": [_text(source, "unknown", 60) for source in (item.get("source") or [])][:5],
        "coverage": item.get("coverage", 0.0),
        "included_in_score": bool(item.get("included_in_score", False)),
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
    engine_statuses = []
    for engine in report.get("engines") or []:
        if not isinstance(engine, dict):
            continue
        engine_statuses.append({
            "name": _text(engine.get("name"), "unknown", 60),
            "status": _text(engine.get("status"), "unknown", 30).lower(),
            "coverage": engine.get("coverage"),
            "confidence": engine.get("confidence"),
            "unknowns_count": len(engine.get("unknowns") or []),
        })
    unknowns = [_text(item, "Unknown evidence", 240) for item in (report.get("unknowns") or [])]
    checks = [_public_check(item) for item in (report.get("checks") or []) if isinstance(item, dict)]

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
        "schema_version": "1.1",
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
        "metrics": _public_metrics(report),
        "signals": [_public_finding(item) for item in findings[:5]],
        "finding_count": len(findings),
        "checks": checks,
        "scan_budget": {
            "profile": _text((report.get("scan_budget") or {}).get("profile"), "unknown", 50),
            "alchemy_request_cap": (report.get("scan_budget") or {}).get("alchemy_request_cap"),
            "max_pairs": (report.get("scan_budget") or {}).get("max_pairs"),
            "max_log_chunks": (report.get("scan_budget") or {}).get("max_log_chunks"),
        },
        "risk_dimensions": dimensions[:6],
        "engine_statuses": engine_statuses[:6],
        "unknowns": unknowns[:8],
        "unknowns_count": len(unknowns),
        "upgrade_available": True,
    }

import json

from smartrisk.service.embed import format_public_result


def _job():
    features = [
        {"feature_id": "market.best_liquidity_usd", "value": 250000},
        {"feature_id": "holders.top10_concentration", "value": 0.31},
        {"feature_id": "contract.owner_observed", "value": False},
        {"feature_id": "holders.excluded_pair_balance", "value": 123456789},  # not allow-listed
        {"feature_id": "market.pair_count", "value": None},                  # no value -> dropped
    ]
    return {
        "job_id": "j", "status": "complete",
        "request": {"chain_id": "1", "token_address": "0x" + "1" * 40},
        "result": {
            "risk": {"score": 3, "band": "low", "confidence": 0.9, "coverage": 0.97},
            "verdict": {"code": "NO_MAJOR_SIGNALS", "label": "NO MAJOR SIGNALS (LIMITED CHECK)", "primary_detection": {}},
            "engines": [{"name": "heuristics", "status": "partial", "report": {"risk": {"features": features}}}],
            "evidence": [{"secret": True}],
        },
    }


def test_public_result_exposes_allow_listed_metrics_only():
    out = format_public_result(_job())
    assert out["metrics"] == {
        "market.best_liquidity_usd": 250000,
        "holders.top10_concentration": 0.31,
        "contract.owner_observed": False,
    }
    assert "secret" not in json.dumps(out)
    assert "engines" not in out


def test_public_result_without_heuristics_has_empty_metrics():
    job = _job()
    job["result"]["engines"] = []
    assert format_public_result(job)["metrics"] == {}

from pathlib import Path

from smartrisk.service.embed import format_public_result


def test_public_scan_payload_is_renderable_by_report_page():
    job = {
        "job_id": "job-1",
        "status": "unknown",
        "request": {"token_address": "0x" + "1" * 40, "chain_id": "1"},
        "result": {
            "risk": {"score": 0, "band": "unknown", "confidence": 0, "coverage": 0},
            "verdict": {"code": "UNVERIFIED", "label": "UNVERIFIED"},
            "risk_dimensions": {},
            "unknowns": ["provider unavailable"],
            "engines": [{"name": "heuristics", "status": "partial", "coverage": 0.2, "confidence": 0.4, "unknowns": ["RPC timeout"]}],
            "checks": [{"check_id": "trading.honeypot", "label": "Buy/sell simulation", "state": "not_tested", "reason_code": "QUICK_CHECK_SCOPE", "reason": "Not included in quick free check.", "source": ["state_fork"]}],
            "scan_budget": {"profile": "quick_free_v1", "alchemy_request_cap": 16, "max_pairs": 1, "max_log_chunks": 2},
        },
    }
    payload = format_public_result(job)
    assert payload["risk"]
    assert payload["verdict"]
    assert payload["status"] == "unknown"
    assert payload["engine_statuses"][0]["status"] == "partial"
    assert payload["unknowns"] == ["provider unavailable"]
    assert payload["checks"][0]["state"] == "not_tested"
    assert payload["checks"][0]["reason_code"] == "QUICK_CHECK_SCOPE"
    assert payload["scan_budget"]["profile"] == "quick_free_v1"
    assert payload["scan_budget"]["alchemy_request_cap"] == 16
    assert "result" not in payload

    script = Path("smartrisk/web/results.js").read_text(encoding="utf-8")
    assert "renderOverview(report);" in script
    assert "renderOverview(job.result);" not in script

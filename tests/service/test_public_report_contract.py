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
        },
    }
    payload = format_public_result(job)
    assert payload["risk"]
    assert payload["verdict"]
    assert payload["status"] == "unknown"
    assert "result" not in payload

    script = Path("smartrisk/web/results.js").read_text(encoding="utf-8")
    assert "renderOverview(report);" in script
    assert "renderOverview(job.result);" not in script

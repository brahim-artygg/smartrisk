from smartrisk.ai import AIExplainer


def test_ai_explanation_is_opt_in_and_does_not_run_by_default(monkeypatch):
    monkeypatch.delenv("SMARTRISK_AI_EXPLANATION_ENABLED", raising=False)
    assert AIExplainer().explain({"risk": {"score": 12}, "verdict": {"code": "UNVERIFIED"}}) is None


def test_ai_output_is_bounded_and_has_no_decision_fields():
    value = AIExplainer._bounded_output({
        "summary": "A" * 2000,
        "key_findings": [{"title": "T", "explanation": "E", "check_id": "c", "evidence_refs": ["x"]}],
        "evidence_gaps": ["gap"],
        "limitations": ["limit"],
        "score": 99,
        "verdict": "HONEYPOT_DETECTED",
    })
    assert len(value["summary"]) == 1200
    assert "score" not in value
    assert "verdict" not in value
    assert value["key_findings"][0]["check_id"] == "c"

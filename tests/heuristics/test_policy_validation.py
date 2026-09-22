from smartrisk.heuristics.policy import PolicyRegistry


def test_active_policy_validates_cleanly():
    policy = PolicyRegistry.load()
    assert policy.validate() == []


def test_policy_validation_catches_bad_rule_configuration():
    policy = PolicyRegistry("bad", {"r.bad": {"family": "missing", "weight": -1, "confidence_factor": 2}}, {"known": {"cap": 10}})
    errors = policy.validate()
    assert any("unknown family" in item for item in errors)
    assert any("invalid weight" in item for item in errors)
    assert any("confidence_factor" in item for item in errors)

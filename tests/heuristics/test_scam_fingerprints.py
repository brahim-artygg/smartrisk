from smartrisk.heuristics.contract_intelligence import BytecodeAnalyzer
from smartrisk.heuristics.scam_fingerprints import ScamFingerprintAnalyzer


def test_deferred_behavior_fingerprint_requires_combined_signals():
    # TIMESTAMP + SSTORE, encoded as executable bytecode bytes.
    profile = BytecodeAnalyzer().analyze("0x4255")
    items = ScamFingerprintAnalyzer().analyze(profile)
    assert any(item.fingerprint_id == "deferred.time-dependent-state" for item in items)
    assert all(item.status == "indicator" for item in items)


def test_tx_origin_state_fingerprint_is_not_malicious_verdict():
    profile = BytecodeAnalyzer().analyze("0x3255")
    items = ScamFingerprintAnalyzer().analyze(profile)
    item = next(item for item in items if item.fingerprint_id == "authorization.tx-origin-state")
    assert item.category == "authorization"
    assert item.confidence < 1.0

from dataclasses import dataclass

from smartrisk.validation import (
    DeterministicCalldataFuzzer,
    EvmBoundedSymbolicAnalyzer,
    LabeledScore,
    StatisticalCalibrator,
    trace_coverage_key,
)


def test_calldata_fuzzer_is_deterministic():
    a = DeterministicCalldataFuzzer(seed=7).generate("0x12345678" + "00" * 32, 12)
    b = DeterministicCalldataFuzzer(seed=7).generate("0x12345678" + "00" * 32, 12)
    assert [item.data for item in a] == [item.data for item in b]
    assert len(a) > 4


def test_trace_coverage_key_changes_with_pc():
    one = trace_coverage_key({"structLogs": [{"pc": 1}, {"pc": 2}]})
    two = trace_coverage_key({"structLogs": [{"pc": 1}, {"pc": 3}]})
    assert one != two


def test_symbolic_guidance_detects_selector_and_jump():
    # PUSH4 selector / EQ / PUSH1 destination / JUMPI pattern.
    bytecode = "0x63deadbeef14600a57"
    result = EvmBoundedSymbolicAnalyzer().analyze(bytecode)
    assert result["status"] == "complete"
    assert "0xdeadbeef" in result["function_selectors"]
    assert result["branches"]


def test_calibrator_requires_labeled_corpus():
    report = StatisticalCalibrator(min_samples_per_class=3).fit([
        LabeledScore("a", 10, 0), LabeledScore("b", 20, 0), LabeledScore("c", 30, 1), LabeledScore("d", 40, 1),
    ])
    assert report.status == "insufficient_data"


def test_calibrator_group_aware_holdout_avoids_group_leakage():
    records = [
        *[LabeledScore(f"n{i}", 5 + i, 0, "contract-n") for i in range(30)],
        *[LabeledScore(f"p{i}", 70 + i, 1, "contract-p") for i in range(30)],
        *[LabeledScore(f"n2-{i}", 20 + i, 0, "contract-n2") for i in range(10)],
        *[LabeledScore(f"p2-{i}", 80 + i, 1, "contract-p2") for i in range(10)],
    ]
    report = StatisticalCalibrator(min_samples_per_class=10, seed=11).fit(records)
    assert report.status == "ready"
    assert report.test_size > 0


def test_calibrator_rejects_duplicate_sample_ids():
    report = StatisticalCalibrator(min_samples_per_class=2).fit([
        LabeledScore("same", 10, 0), LabeledScore("same", 20, 1),
        LabeledScore("n2", 15, 0), LabeledScore("p2", 80, 1),
    ])
    assert report.status == "invalid_corpus"


def test_calibrator_produces_threshold_and_confidence_intervals():
    records = [
        *[LabeledScore(f"n{i}", 5 + i, 0) for i in range(20)],
        *[LabeledScore(f"p{i}", 70 + i, 1) for i in range(20)],
    ]
    report = StatisticalCalibrator(min_samples_per_class=10, seed=3).fit(records)
    assert report.status == "ready"
    assert report.selected_threshold is not None
    assert report.test_metrics is not None
    assert 0.0 <= report.test_metrics.fpr <= 1.0
    assert 0.0 <= report.test_metrics.fnr <= 1.0
    assert "recall" in report.test_metric_intervals


def test_symbolic_guidance_marks_time_dependent_state_branch():
    # TIMESTAMP, PUSH constant, GT, PUSH destination, JUMPI, SSTORE proximity.
    bytecode = "0x4260011160035755"
    result = EvmBoundedSymbolicAnalyzer().analyze(bytecode)
    assert result["branches"]
    assert "timestamp" in result["branches"][0]["guard_signals"]
    assert "nearby_sstore" in result["branches"][0]["guard_signals"]
    assert result["risk_hints"]["deferred_state_branches"] >= 1


def test_symbolic_guidance_marks_calldata_guard():
    bytecode = "0x3560011460025755"
    result = EvmBoundedSymbolicAnalyzer().analyze(bytecode)
    assert result["branches"]
    assert "calldata" in result["branches"][0]["guard_signals"]

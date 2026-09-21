from smartrisk.state_fork.models import BlockAnchor, ForkRun, SimulationResult


def test_fork_report_serializes_anchor_and_results():
    anchor = BlockAnchor("0x1", 42, "0xhash", "0xparent", 100, "finalized")
    report = ForkRun(
        "run-1",
        "complete",
        anchor,
        results=[SimulationResult("s1", "reverted", anchor, revert_data="0x08c379a0")],
    )
    payload = report.to_dict()
    assert payload["anchor"]["block_number"] == 42
    assert payload["results"][0]["status"] == "reverted"

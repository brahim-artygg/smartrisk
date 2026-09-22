from smartrisk.state_fork.scenario_generator import ScenarioGenerator


def test_standard_scenarios_are_bounded_and_typed():
    generator = ScenarioGenerator("0x" + "11" * 20, "0x" + "22" * 20, amount=7)
    scenarios = generator.standard_scenarios()
    ids = {item.scenario_id for item in scenarios}
    assert len(scenarios) == 12
    assert "standard:transfer" in ids
    assert "standard:upgradeTo" in ids
    assert all(item.data.startswith("0x") for item in scenarios)

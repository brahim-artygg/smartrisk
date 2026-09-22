from smartrisk.state_fork.scenario_generator import ScenarioGenerator


def test_scenario_generator_classifies_high_value_functions():
    generator = ScenarioGenerator("0x" + "1" * 40, "0x" + "2" * 40)
    scenarios = generator.from_abi([
        {"type": "function", "name": "setSellTax", "inputs": [{"type": "uint256"}]},
        {"type": "function", "name": "upgradeTo", "inputs": [{"type": "address"}]},
        {"type": "function", "name": "blacklist", "inputs": [{"type": "address"}]},
    ])
    by_id = {item.scenario_id: item for item in scenarios}
    assert by_id["abi:setSellTax"].category == "fee"
    assert by_id["abi:setSellTax"].data.startswith("0x8cd09d50")
    assert "upgrade" in by_id["abi:upgradeTo"].risk_tags
    assert by_id["abi:blacklist"].category == "restriction"

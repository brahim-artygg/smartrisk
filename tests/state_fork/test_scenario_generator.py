from smartrisk.state_fork.scenario_generator import ScenarioGenerator


def test_abi_generator_creates_transfer_mint_pause_upgrade_role_scenarios():
    generator = ScenarioGenerator("0x" + "1" * 40, "0x" + "2" * 40)
    scenarios = generator.from_abi([
        {"type": "function", "name": "transfer", "inputs": [{"type": "address"}, {"type": "uint256"}]},
        {"type": "function", "name": "mint", "inputs": [{"type": "address"}, {"type": "uint256"}]},
        {"type": "function", "name": "pause", "inputs": []},
        {"type": "function", "name": "upgradeTo", "inputs": [{"type": "address"}]},
        {"type": "function", "name": "grantRole", "inputs": [{"type": "bytes32"}, {"type": "address"}]},
    ])
    assert {item.scenario_id for item in scenarios} == {"abi:transfer", "abi:mint", "abi:pause", "abi:upgradeTo", "abi:grantRole"}
    assert next(item for item in scenarios if item.scenario_id == "abi:transfer").data.startswith("0xa9059cbb")


def test_source_generator_extracts_known_and_custom_function_selectors():
    scenarios = ScenarioGenerator("0x" + "1" * 40, "0x" + "2" * 40).from_source("function pause() external {} function transfer(address to, uint256 amount) external {}")
    assert [item.scenario_id for item in scenarios] == ["source:pause", "source:transfer"]

from smartrisk.heuristics.contract_intelligence import (
    EIP1967_IMPLEMENTATION_SLOT,
    BytecodeAnalyzer,
    ContractIntelligence,
    word_to_address,
)


def test_bytecode_profile_extracts_high_signal_opcodes_and_selectors():
    code = "0x63a9059cbb6000525055"
    profile = BytecodeAnalyzer().analyze(code)
    assert profile.byte_length == 10
    assert "0xa9059cbb" in profile.push4_selectors
    assert profile.flags["has_delegatecall"] is False
    assert profile.flags["has_timestamp"] is False


def test_word_to_address_ignores_zero_address():
    assert word_to_address("0x" + "00" * 32) is None
    address = "0x" + "11" * 20
    assert word_to_address("0x" + "00" * 12 + "11" * 20) == address


def test_contract_intelligence_reads_eip1967_implementation():
    address = "0x" + "22" * 20
    profile = ContractIntelligence().build_profile(
        "0x5af43d", storage={EIP1967_IMPLEMENTATION_SLOT: "0x" + "00" * 12 + "22" * 20}
    )
    assert profile["privileges"]["implementation"] == address
    assert profile["privileges"]["upgradeable"] is True

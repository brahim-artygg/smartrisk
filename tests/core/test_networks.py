from smartrisk.core.networks import canonical_chain_id, dexscreener_chain, get_network, supported_networks


def test_v09_has_exactly_ten_supported_networks():
    profiles = supported_networks()
    assert len(profiles) == 10
    assert [profile.chain_id for profile in profiles] == ["1", "56", "8453", "42161", "137", "10", "43114", "100", "42220", "130"]


def test_network_aliases_normalize_to_canonical_chain_ids():
    assert canonical_chain_id("eth-mainnet") == "1"
    assert canonical_chain_id("bsc-mainnet") == "56"
    assert canonical_chain_id("0x2105") == "8453"
    assert canonical_chain_id("arbitrum") == "42161"
    assert canonical_chain_id("matic") == "137"
    assert canonical_chain_id("xdai") == "100"
    assert canonical_chain_id("celo") == "42220"
    assert canonical_chain_id("unichain") == "130"


def test_dexscreener_chain_ids_are_stable():
    assert dexscreener_chain("1") == "ethereum"
    assert dexscreener_chain("56") == "bsc"
    assert dexscreener_chain("8453") == "base"
    assert dexscreener_chain("42161") == "arbitrum"
    assert dexscreener_chain("137") == "polygon"
    assert dexscreener_chain("10") == "optimism"
    assert dexscreener_chain("43114") == "avalanche"
    assert dexscreener_chain("100") == "gnosis"
    assert dexscreener_chain("42220") == "celo"
    assert dexscreener_chain("130") == "unichain"


def test_known_profile_payload():
    profile = get_network("bsc")
    assert profile.chain_id == "56"
    assert profile.wrapped_native.lower() == "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"

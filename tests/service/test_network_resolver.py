from dataclasses import dataclass

import pytest

from smartrisk.service import network_resolver


@dataclass(frozen=True)
class FakeProfile:
    key: str
    name: str
    chain_id: str
    rpc_chain: str


PROFILES = (
    FakeProfile("ethereum", "Ethereum", "1", "eth-mainnet"),
    FakeProfile("base", "Base", "8453", "base-mainnet"),
    FakeProfile("arbitrum", "Arbitrum One", "42161", "arb-mainnet"),
)


class FakeRpc:
    deployed = {"eth-mainnet", "base-mainnet"}

    def __init__(self, *, chain, **kwargs):
        self.chain = chain

    def get_code(self, address, block):
        return "0x6000" if self.chain in self.deployed else "0x"


def test_detect_networks_finds_contract_across_supported_networks(monkeypatch):
    monkeypatch.setattr(network_resolver, "supported_networks", lambda: PROFILES)
    monkeypatch.setattr(network_resolver, "AlchemyRpcClient", FakeRpc)

    matches = network_resolver.detect_networks("0x" + "1" * 40)

    assert [item.chain_id for item in matches] == ["1", "8453"]


def test_resolve_network_requires_unique_match(monkeypatch):
    monkeypatch.setattr(network_resolver, "detect_networks", lambda address: [PROFILES[1]])

    assert network_resolver.resolve_network("0x" + "2" * 40).chain_id == "8453"


def test_resolve_network_rejects_ambiguous_contract(monkeypatch):
    monkeypatch.setattr(network_resolver, "detect_networks", lambda address: list(PROFILES[:2]))

    with pytest.raises(network_resolver.NetworkResolutionError, match="multiple supported networks"):
        network_resolver.resolve_network("0x" + "3" * 40)


def test_detect_networks_rejects_invalid_address():
    with pytest.raises(network_resolver.NetworkResolutionError, match="valid EVM contract address"):
        network_resolver.detect_networks("not-an-address")

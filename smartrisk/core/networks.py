from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NetworkProfile:
    key: str
    name: str
    chain_id: str
    rpc_chain: str
    dexscreener_id: str
    wrapped_native: str
    native_symbol: str
    aliases: tuple[str, ...] = ()

    def matches(self, value: str | int) -> bool:
        candidate = str(value).strip().lower()
        normalized = {self.key, self.name.lower(), self.chain_id.lower(), self.rpc_chain.lower(), self.dexscreener_id.lower(), *(alias.lower() for alias in self.aliases)}
        if candidate in normalized:
            return True
        try:
            return int(candidate, 16) == int(self.chain_id) if candidate.startswith("0x") else int(candidate) == int(self.chain_id)
        except ValueError:
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "chain_id": self.chain_id,
            "chain_id_hex": hex(int(self.chain_id)),
            "rpc_chain": self.rpc_chain,
            "dexscreener_id": self.dexscreener_id,
            "wrapped_native": self.wrapped_native,
            "native_symbol": self.native_symbol,
            "aliases": list(self.aliases),
        }


NETWORKS: tuple[NetworkProfile, ...] = (
    NetworkProfile(
        "ethereum", "Ethereum", "1", "eth-mainnet", "ethereum",
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "ETH",
        ("eth", "mainnet", "ethereum-mainnet", "1"),
    ),
    NetworkProfile(
        "bsc", "BNB Smart Chain", "56", "bnb-mainnet", "bsc",
        "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", "BNB",
        ("bnb", "binance", "binance-smart-chain", "bsc-mainnet", "56"),
    ),
    NetworkProfile(
        "base", "Base", "8453", "base-mainnet", "base",
        "0x4200000000000000000000000000000000000006", "ETH",
        ("base-mainnet", "8453"),
    ),
    NetworkProfile(
        "arbitrum", "Arbitrum One", "42161", "arb-mainnet", "arbitrum",
        "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", "ETH",
        ("arb", "arbitrum-one", "arbitrum-mainnet", "42161"),
    ),
    NetworkProfile(
        "polygon", "Polygon", "137", "polygon-mainnet", "polygon",
        "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270", "POL",
        ("matic", "polygon-mainnet", "137"),
    ),
    NetworkProfile(
        "optimism", "Optimism", "10", "opt-mainnet", "optimism",
        "0x4200000000000000000000000000000000000006", "ETH",
        ("op", "optimism-mainnet", "10"),
    ),
    NetworkProfile(
        "avalanche", "Avalanche C-Chain", "43114", "avax-mainnet", "avalanche",
        "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7", "AVAX",
        ("avax", "avalanche-c", "avalanche-mainnet", "43114"),
    ),
    NetworkProfile(
        "gnosis", "Gnosis", "100", "gnosis-mainnet", "gnosis",
        "0x6A023CCD1ff6F2045C3309768eAd9E68F978f6e1", "xDAI",
        ("xdai", "gnosis-chain", "gnosis-mainnet", "100"),
    ),
    NetworkProfile(
        "celo", "Celo", "42220", "celo-mainnet", "celo",
        "0x471EcE3750Da237f93B8E339c536989b8978a438", "CELO",
        ("42220",),
    ),
    NetworkProfile(
        "unichain", "Unichain", "130", "unichain-mainnet", "unichain",
        "0x4200000000000000000000000000000000000006", "ETH",
        ("uni", "130"),
    ),
)

_NETWORK_BY_KEY = {item.key: item for item in NETWORKS}


def get_network(value: str | int) -> NetworkProfile:
    candidate = str(value).strip().lower()
    for profile in NETWORKS:
        if profile.matches(candidate):
            return profile
    raise KeyError(f"unsupported SmartRisk network: {value}")


def try_get_network(value: str | int) -> NetworkProfile | None:
    try:
        return get_network(value)
    except KeyError:
        return None


def supported_networks() -> tuple[NetworkProfile, ...]:
    return NETWORKS


def canonical_chain_id(value: str | int) -> str:
    return get_network(value).chain_id


def dexscreener_chain(value: str | int) -> str:
    return get_network(value).dexscreener_id


def rpc_chain(value: str | int) -> str:
    return get_network(value).rpc_chain

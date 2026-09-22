from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from typing import Any

from ..core.networks import NetworkProfile, supported_networks
from ..state_fork.alchemy_rpc import AlchemyRpcClient, AlchemyRpcError


_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


class NetworkResolutionError(ValueError):
    pass


def _has_code(client: AlchemyRpcClient, address: str) -> bool:
    code = client.get_code(address, "latest")
    return isinstance(code, str) and code.lower() not in {"0x", "0x0", "0x00"}


def detect_networks(address: str, timeout_seconds: float = 8.0) -> list[NetworkProfile]:
    """Return supported networks where the address currently has contract code.

    Probes all supported networks in parallel so the public scanner never needs a
    network selector. Individual provider failures are ignored; a network is
    considered a match only when eth_getCode confirms deployed bytecode.
    """
    token_address = address.strip() if isinstance(address, str) else ""
    if not _ADDRESS_RE.fullmatch(token_address):
        raise NetworkResolutionError("Enter a valid EVM contract address.")

    profiles = supported_networks()

    def probe(profile: NetworkProfile) -> tuple[NetworkProfile, bool]:
        try:
            client = AlchemyRpcClient(chain=profile.rpc_chain, timeout_seconds=timeout_seconds, retries=0)
            return profile, _has_code(client, token_address)
        except (AlchemyRpcError, KeyError, OSError, TimeoutError):
            return profile, False
        except Exception:
            return profile, False

    matches: list[NetworkProfile] = []
    with ThreadPoolExecutor(max_workers=min(len(profiles), 10), thread_name_prefix="smartrisk-network-detect") as executor:
        futures = [executor.submit(probe, profile) for profile in profiles]
        for future in as_completed(futures):
            profile, found = future.result()
            if found:
                matches.append(profile)

    order = {profile.chain_id: index for index, profile in enumerate(profiles)}
    return sorted(matches, key=lambda profile: order[profile.chain_id])


def resolve_network(address: str) -> NetworkProfile:
    matches = detect_networks(address)
    if not matches:
        raise NetworkResolutionError("SmartRisk could not determine a supported network for this contract.")
    if len(matches) > 1:
        names = ", ".join(profile.name for profile in matches)
        raise NetworkResolutionError(
            f"This contract is deployed on multiple supported networks: {names}."
        )
    return matches[0]

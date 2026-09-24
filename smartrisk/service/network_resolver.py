from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import os
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


def detect_networks(address: str, timeout_seconds: float = 8.0, stop_on_first: bool = False) -> list[NetworkProfile]:
    """Return supported networks where the address currently has contract code.

    Probes all supported networks in parallel so the public scanner never needs a
    network selector. Individual provider failures are ignored; a network is
    considered a match only when eth_getCode confirms deployed bytecode.
    """
    token_address = address.strip() if isinstance(address, str) else ""
    if not _ADDRESS_RE.fullmatch(token_address):
        raise NetworkResolutionError("Enter a valid EVM contract address.")

    profiles = list(supported_networks())

    def probe(profile: NetworkProfile) -> tuple[NetworkProfile, bool]:
        try:
            client = AlchemyRpcClient(chain=profile.rpc_chain, timeout_seconds=timeout_seconds, retries=0)
            return profile, _has_code(client, token_address)
        except (AlchemyRpcError, KeyError, OSError, TimeoutError):
            return profile, False
        except Exception:
            return profile, False

    matches: list[NetworkProfile] = []
    # A single Alchemy key is shared by all network endpoints. Do not launch
    # ten eth_getCode requests at once: that burst is enough to trigger 429s
    # before the actual scan begins. Probe the configured/default network first;
    # only fan out to alternatives when the priority network has no code.
    preferred_key = os.getenv("SMARTRISK_DEFAULT_SCAN_NETWORK", "ethereum")
    preferred = next((item for item in profiles if item.key == preferred_key or item.matches(preferred_key)), profiles[0])
    ordered = [preferred] + [item for item in profiles if item != preferred]
    first_profile, first_found = probe(ordered[0])
    if first_found and stop_on_first:
        return [first_profile]
    if first_found:
        matches.append(first_profile)
    fallback_profiles = ordered[1:]
    with ThreadPoolExecutor(max_workers=min(len(fallback_profiles), 3), thread_name_prefix="smartrisk-network-detect") as executor:
        futures = [executor.submit(probe, profile) for profile in fallback_profiles]
        for future in as_completed(futures):
            profile, found = future.result()
            if found:
                matches.append(profile)

    order = {profile.chain_id: index for index, profile in enumerate(ordered)}
    return sorted(matches, key=lambda profile: order[profile.chain_id])


def resolve_network(address: str) -> NetworkProfile:
    # Public scans need one canonical chain and should not fan out to every
    # Alchemy network after the priority chain already proved the address.
    try:
        matches = detect_networks(address, stop_on_first=True)
    except TypeError:
        # Backwards compatibility for integrations/tests injecting the former
        # one-argument detector.
        matches = detect_networks(address)
    if not matches:
        raise NetworkResolutionError("SmartRisk could not determine a supported network for this contract.")
    if len(matches) > 1:
        names = ", ".join(profile.name for profile in matches)
        raise NetworkResolutionError(
            f"This contract is deployed on multiple supported networks: {names}."
        )
    return matches[0]

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    name: str
    window_blocks: int
    max_pairs: int
    max_holder_contract_probes: int
    rpc_log_concurrency: int
    rpc_timeout_seconds: float
    rpc_retries: int
    stage_timeout_seconds: int


FREE_PROFILE = ScanProfile(
    name="free",
    window_blocks=2_000,
    max_pairs=2,
    max_holder_contract_probes=4,
    rpc_log_concurrency=1,
    rpc_timeout_seconds=8.0,
    rpc_retries=1,
    stage_timeout_seconds=75,
)

PAID_PROFILE = ScanProfile(
    name="paid",
    window_blocks=10_000,
    max_pairs=5,
    max_holder_contract_probes=12,
    rpc_log_concurrency=2,
    rpc_timeout_seconds=12.0,
    rpc_retries=1,
    stage_timeout_seconds=150,
)


def get_scan_profile(name: str | None) -> ScanProfile:
    return FREE_PROFILE if str(name or "paid").lower() == "free" else PAID_PROFILE


def clamp_window(requested: int | None, profile: ScanProfile) -> int:
    try:
        value = int(requested if requested is not None else profile.window_blocks)
    except (TypeError, ValueError):
        value = profile.window_blocks
    return max(1, min(value, profile.window_blocks))

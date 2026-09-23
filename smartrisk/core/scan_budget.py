from __future__ import annotations

import os
import time
from dataclasses import dataclass


def _env_int(name: str, default: int) -> int:
    try:
        return max(0, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


@dataclass
class ScanBudget:
    """Wall-clock budget shared by all engines of one scan.

    The budget guarantees a scan always terminates with a report (possibly
    partial) instead of hanging until the job watchdog marks it failed. Once
    the deadline is exhausted, expensive RPC-backed lookups are skipped and
    recorded as unknowns, which matches the project's conservative principle:
    missing evidence is never treated as safe.
    """

    deadline: float | None = None
    seconds: float = 180.0
    expired_reason: str | None = None
    skipped: list[str] | None = None

    @classmethod
    def from_seconds(cls, seconds: float | None) -> "ScanBudget":
        if not seconds or seconds <= 0:
            return cls(deadline=None, seconds=0.0)
        return cls(deadline=time.monotonic() + float(seconds), seconds=float(seconds))

    @classmethod
    def unlimited(cls) -> "ScanBudget":
        return cls(deadline=None, seconds=0.0)

    @property
    def enabled(self) -> bool:
        return self.deadline is not None

    def remaining_seconds(self) -> float | None:
        if self.deadline is None:
            return None
        return max(0.0, self.deadline - time.monotonic())

    def expired(self) -> bool:
        if self.deadline is None:
            return False
        if time.monotonic() >= self.deadline:
            if self.expired_reason is None:
                self.expired_reason = f"the {self.seconds:.0f}s scan time budget was exhausted"
            return True
        return False

    def note_skipped(self, item: str, reason: str | None = None) -> None:
        if self.skipped is None:
            self.skipped = []
        detail = f"{item}: {reason}" if reason else item
        if detail not in self.skipped:
            self.skipped.append(detail)


def default_scan_timeout_seconds() -> float:
    return float(_env_int("SMARTRISK_SCAN_TIMEOUT_SECONDS", 180))

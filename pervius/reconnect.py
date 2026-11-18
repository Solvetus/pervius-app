"""Retry policy for unexpected VPN disconnects.

The policy is deliberately conservative and deterministic: it is used only
after a tunnel was established and then dropped unexpectedly.  Manual
disconnects and failed first attempts never enter this policy.
"""

from __future__ import annotations

from dataclasses import dataclass

# Waits before retry 1, 2, ...  After the last wait the policy gives up.
DEFAULT_DELAYS = (2, 5, 10, 20, 30, 60)


@dataclass(frozen=True)
class ReconnectPolicy:
    delays: tuple[int, ...] = DEFAULT_DELAYS

    def __post_init__(self):
        if not self.delays:
            raise ValueError("reconnect policy needs at least one delay")
        if any(delay < 1 for delay in self.delays):
            raise ValueError("reconnect delays must be positive")

    @property
    def max_attempts(self) -> int:
        return len(self.delays)

    def delay(self, attempt: int) -> int | None:
        """Wait before one-based *attempt*, or None when attempts are exhausted."""
        if attempt < 1 or attempt > len(self.delays):
            return None
        return self.delays[attempt - 1]

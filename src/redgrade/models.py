"""Data model: attacks, trials and results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class Attack:
    """One attack from a pack.

    ``prompt`` and ``document`` are templates. ``{CANARY}`` is replaced by a random token per
    trial; ``{b64:TEXT}`` and ``{rot13:TEXT}`` encode TEXT (after canary substitution).

    ``delivery`` is ``direct`` (the prompt is sent as the user message) or ``document`` (the
    prompt is a harmless user question and ``document`` is a poisoned document the app reads,
    i.e. indirect prompt injection).
    """

    id: str
    family: str
    title: str
    owasp: str
    severity: str
    prompt: str
    detector: str
    delivery: str = "direct"
    document: str | None = None
    detector_args: dict[str, Any] = field(default_factory=dict)
    requires_secrets: bool = False
    description: str = ""


@dataclass
class Trial:
    """One execution of one attack against the target."""

    succeeded: bool  # True = the attack worked (bad)
    output: str = ""
    error: str | None = None
    latency_s: float = 0.0
    canary: str = ""


@dataclass
class AttackResult:
    attack: Attack
    trials: list[Trial] = field(default_factory=list)
    skipped_reason: str | None = None

    @property
    def valid_trials(self) -> list[Trial]:
        return [t for t in self.trials if t.error is None]

    @property
    def successes(self) -> int:
        return sum(1 for t in self.valid_trials if t.succeeded)

    @property
    def errors(self) -> int:
        return sum(1 for t in self.trials if t.error is not None)

    @property
    def asr(self) -> float | None:
        """Attack success rate over trials that ran without error (None if none did)."""
        valid = self.valid_trials
        if not valid:
            return None
        return self.successes / len(valid)

    @property
    def flaky(self) -> bool:
        asr = self.asr
        return asr is not None and 0.0 < asr < 1.0


@dataclass
class RunResult:
    results: list[AttackResult]
    trials_per_attack: int

    @property
    def executed(self) -> list[AttackResult]:
        return [r for r in self.results if r.skipped_reason is None]

    @property
    def skipped(self) -> list[AttackResult]:
        return [r for r in self.results if r.skipped_reason is not None]

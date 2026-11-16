"""Data model: attacks, trials and results."""

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator

from redgrade.constants import (
    DELIVERY_DIRECT,
    DETECT_ON_LAST,
    SEVERITIES,
    Delivery,
    DetectOn,
    Severity,
)
from redgrade.types import DetectorArgs

__all__ = [
    "SEVERITIES",
    "Attack",
    "AttackResult",
    "AttackTurn",
    "RunResult",
    "Trial",
]


class AttackTurn(BaseModel):
    """One turn in a multi-turn attack."""

    model_config = ConfigDict(frozen=True)

    prompt: str
    documents: tuple[str, ...] = ()


class Attack(BaseModel):
    """One attack from a pack.

    ``prompt`` and ``document`` are templates. ``{CANARY}`` is replaced by a random token per
    trial; ``{b64:TEXT}`` and ``{rot13:TEXT}`` encode TEXT (after canary substitution).

    ``delivery`` is ``direct`` (the prompt is sent as the user message) or ``document`` (the
    prompt is a harmless user question and ``document`` is a poisoned document the app reads,
    i.e. indirect prompt injection).
    """

    model_config = ConfigDict(frozen=True)

    id: str
    family: str
    title: str
    owasp: str
    severity: Severity
    prompt: str = ""
    detector: str
    delivery: Delivery = DELIVERY_DIRECT
    document: str | None = None
    turns: tuple[AttackTurn, ...] = ()
    detect_on: DetectOn = DETECT_ON_LAST
    detector_args: DetectorArgs = Field(default_factory=dict)
    requires_secrets: bool = False
    description: str = ""

    @model_validator(mode="after")
    def _prompt_xor_turns(self) -> Self:
        has_turns = len(self.turns) > 0
        has_prompt = bool(self.prompt)
        if has_turns and has_prompt:
            raise ValueError("attack cannot set both prompt and turns")
        if has_turns and len(self.turns) < 2:
            raise ValueError("turns must contain at least 2 items")
        if not has_turns and not has_prompt:
            raise ValueError("attack requires prompt or turns")
        return self


class Trial(BaseModel):
    """One execution of one attack against the target."""

    succeeded: bool  # True = the attack worked (bad)
    output: str = ""
    turn_outputs: list[str] = Field(default_factory=list)
    error: str | None = None
    latency_s: float = 0.0
    canary: str = ""


class AttackResult(BaseModel):
    attack: Attack
    trials: list[Trial] = Field(default_factory=list)
    skipped_reason: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def valid_trials(self) -> list[Trial]:
        return [t for t in self.trials if t.error is None]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def successes(self) -> int:
        return sum(1 for t in self.valid_trials if t.succeeded)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def errors(self) -> int:
        return sum(1 for t in self.trials if t.error is not None)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def asr(self) -> float | None:
        """Attack success rate over trials that ran without error (None if none did)."""
        valid = self.valid_trials
        if not valid:
            return None
        return self.successes / len(valid)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def flaky(self) -> bool:
        asr = self.asr
        return asr is not None and 0.0 < asr < 1.0


class RunResult(BaseModel):
    results: list[AttackResult]
    trials_per_attack: int

    @computed_field  # type: ignore[prop-decorator]
    @property
    def executed(self) -> list[AttackResult]:
        return [r for r in self.results if r.skipped_reason is None]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def skipped(self) -> list[AttackResult]:
        return [r for r in self.results if r.skipped_reason is not None]

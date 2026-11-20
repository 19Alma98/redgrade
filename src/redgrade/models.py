"""Data model: attacks, trials and results."""

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

from redgrade.attachments import AttachmentSpec
from redgrade.constants import (
    DELIVERY_DIRECT,
    DETECT_ON_LAST,
    MUTATE_SCOPE_ALL,
    SEVERITIES,
    Delivery,
    DetectOn,
    MutateScope,
    Severity,
)
from redgrade.oob import Fixture, OobHit
from redgrade.types import DetectorArgs, HistoryRole, JsonValue

__all__ = [
    "SEVERITIES",
    "Attack",
    "AttackResult",
    "AttackTurn",
    "HistoryTurn",
    "RunResult",
    "TargetObservation",
    "ToolCall",
    "Trial",
]


class ToolCall(BaseModel):
    """One tool invocation observed from the app under test."""

    model_config = ConfigDict(frozen=True)

    name: str
    arguments: dict[str, JsonValue] = Field(default_factory=dict)
    id: str = ""


class TargetObservation(BaseModel):
    """Normalized target result: text reply plus optional tool trajectory."""

    model_config = ConfigDict(frozen=True)

    output: str
    tools_called: tuple[ToolCall, ...] = ()


class AttackTurn(BaseModel):
    """One turn in a multi-turn attack."""

    model_config = ConfigDict(frozen=True)

    prompt: str
    documents: tuple[str, ...] = ()
    attachments: tuple[AttachmentSpec, ...] = ()
    # Start a new conversation before this turn: no history is sent and ``{{session_id}}`` changes.
    new_session: bool = False


class HistoryTurn(BaseModel):
    """One forged message of the conversation history sent *before* the attack prompt.

    The attacker controls the history an app receives from its client (chat UIs, mobile apps and
    agent frameworks usually send the whole conversation). Forged turns can pose as the system or
    operator (``system``), as the assistant agreeing to something earlier (``assistant``, optionally
    with ``tool_calls``), or as a tool result carrying an injection (``tool``). ``content`` and tool
    call arguments use the same ``{CANARY}`` / ``{b64:...}`` templates as prompts.
    """

    model_config = ConfigDict(frozen=True)

    role: HistoryRole
    content: str = ""
    name: str | None = None
    tool_call_id: str | None = None
    tool_calls: tuple[ToolCall, ...] = ()

    @model_validator(mode="after")
    def _check_role_fields(self) -> Self:
        if self.tool_calls and self.role != "assistant":
            raise ValueError("tool_calls are only allowed on assistant history turns")
        if self.tool_call_id and self.role != "tool":
            raise ValueError("tool_call_id is only allowed on tool history turns")
        if not self.content and not self.tool_calls:
            raise ValueError(f"{self.role} history turn needs content")
        return self


class Attack(BaseModel):
    """One attack from a pack.

    Single-shot attacks use ``prompt`` (and optional ``document``). Multi-turn attacks use
    ``turns`` (≥2 ``AttackTurn`` items); set ``prompt`` to empty. ``detect_on`` chooses whether
    detectors run on the last turn output only or on any turn.

    ``prompt``, ``document``, and each turn's templates use ``{CANARY}`` (per-trial token) and
    ``{b64:TEXT}`` / ``{rot13:TEXT}`` encodings after canary substitution.

    ``attachments`` are real files (PDF, DOCX, HTML, ...) built per trial; see ``redgrade.attachments``.

    ``delivery`` is ``direct`` (the prompt is sent as the user message) or ``document`` (the
    prompt is a harmless user question and ``document`` is a poisoned document the app reads,
    i.e. indirect prompt injection).

    ``history`` is a forged conversation (``HistoryTurn`` items) sent before ``prompt`` / the first
    turn. With ``requires_history`` the attack is skipped (and reported) when the target cannot
    receive history natively, because flattening forged roles into the prompt tests something else.

    ``fixtures`` are attacker pages served by the out-of-band collector at ``{OOB_URL}/f/<path>``
    (see ``redgrade.oob``). ``requires_oob`` skips the attack when no collector runs;
    ``requires_fetch`` turns a trial where the target never fetched any fixture into an error
    (inconclusive), because the injection never reached it.
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
    documents: tuple[str, ...] = ()
    attachments: tuple[AttachmentSpec, ...] = ()
    turns: tuple[AttackTurn, ...] = ()
    history: tuple[HistoryTurn, ...] = ()
    requires_history: bool = False
    fixtures: tuple[Fixture, ...] = ()
    requires_oob: bool = False
    requires_fetch: bool = False
    detect_on: DetectOn = DETECT_ON_LAST
    detector_args: DetectorArgs = Field(default_factory=dict)
    requires_secrets: bool = False
    requires_tools: bool = False
    tools: tuple[JsonValue, ...] = ()
    level: int | None = None
    technique: str = ""
    mutations: tuple[str, ...] = ()
    # Set on derived (L4) attacks: the mutation kind that produced this variant from its seed.
    mutation: str = ""
    mutate_scope: MutateScope = MUTATE_SCOPE_ALL
    description: str = ""

    @property
    def has_attachments(self) -> bool:
        return bool(self.attachments) or any(t.attachments for t in self.turns)

    @field_validator("level")
    @classmethod
    def _level_in_range(cls, v: int | None) -> int | None:
        if v is not None and not (1 <= v <= 5):
            raise ValueError("level must be between 1 and 5")
        return v

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
    tools_called: list[ToolCall] = Field(default_factory=list)
    turn_outputs: list[str] = Field(default_factory=list)
    error: str | None = None
    latency_s: float = 0.0
    canary: str = ""
    oob_hits: list[OobHit] = Field(default_factory=list)


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

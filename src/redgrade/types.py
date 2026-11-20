"""Shared typing aliases — prefer these over ``Any``."""

from collections.abc import Mapping
from typing import Literal, NotRequired, Protocol, TypedDict

type JsonPrimitive = None | bool | int | float | str
type JsonValue = JsonPrimitive | list[JsonValue] | dict[str, JsonValue]

# Free-form YAML / detector kwargs (scalars and nested JSON).
type DetectorArgs = dict[str, JsonValue]

# Untyped YAML mapping after ``isinstance(..., dict)`` checks.
type YamlMapping = Mapping[str, object]


type HistoryRole = Literal["system", "user", "assistant", "tool"]


class HistoryToolCall(TypedDict):
    """A tool call requested by an assistant turn of the conversation history."""

    id: str
    name: str
    arguments: dict[str, JsonValue]


class HistoryMessage(TypedDict):
    """One message of the conversation sent to the target.

    Real multi-turn runs only produce ``user`` / ``assistant`` turns. Attacks can also *forge*
    history (``Attack.history``) with ``system`` and ``tool`` turns, assistant tool calls and a
    ``name`` (speaker) field, because many apps accept the whole conversation from the client.
    """

    role: HistoryRole
    content: str
    name: NotRequired[str]
    tool_call_id: NotRequired[str]
    tool_calls: NotRequired[list[HistoryToolCall]]


class LevelStat(TypedDict):
    valid: int
    wins: int
    asr: float | None


class FamilyStat(TypedDict):
    attacks: int
    valid: int
    wins: int
    asr: float | None


class AttackSummary(TypedDict):
    id: str
    family: str
    title: str
    owasp: str
    severity: str
    skipped: str | None
    trials: int
    errors: int
    asr: float | None
    level: int | None
    valid: int
    successes: int
    flaky: bool
    mutation: str | None
    detector: str
    advisory: bool


class CheckDict(TypedDict):
    name: str
    value: float
    limit: float
    passed: bool


class PiPostureDict(TypedDict):
    score: int | None
    highest_resisted_level: int | None
    asr_by_level: dict[str, float | None]
    unleveled: int
    failing_techniques: list[str]


class ReportDictRequired(TypedDict):
    schema_version: int
    passed: bool
    trials_per_attack: int
    checks: list[CheckDict]
    families: dict[str, FamilyStat]
    attacks: list[AttackSummary]
    pi_posture: PiPostureDict
    utility_overall: float | None


class ReportDict(ReportDictRequired, total=False):
    security_level: dict[str, JsonValue]
    evasion: dict[str, dict[str, float | int | None]]
    deep_meta: dict[str, JsonValue]
    baseline: dict[str, JsonValue]
    scorecard: dict[str, JsonValue]
    compliance: dict[str, JsonValue]
    mode: str
    readiness: dict[str, JsonValue]
    findings: list[dict[str, JsonValue]]
    notes: list[str]


class OpenGradeRow(Protocol):
    """Duck type for an exported dataset row (task input)."""

    input: object
    metadata: Mapping[str, object] | None


class OpenGradeSample(Protocol):
    """Duck type for an OpenGrade scored sample."""

    input: object
    output: object
    metadata: Mapping[str, object] | None

"""Shared typing aliases — prefer these over ``Any``."""

from collections.abc import Mapping
from typing import Literal, Protocol, TypedDict

type JsonPrimitive = None | bool | int | float | str
type JsonValue = JsonPrimitive | list[JsonValue] | dict[str, JsonValue]

# Free-form YAML / detector kwargs (scalars and nested JSON).
type DetectorArgs = dict[str, JsonValue]

# Untyped YAML mapping after ``isinstance(..., dict)`` checks.
type YamlMapping = Mapping[str, object]


class HistoryMessage(TypedDict):
    role: Literal["user", "assistant"]
    content: str


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
    passed: bool
    trials_per_attack: int
    checks: list[CheckDict]
    families: dict[str, FamilyStat]
    attacks: list[AttackSummary]
    pi_posture: PiPostureDict
    utility_overall: float | None


class ReportDict(ReportDictRequired, total=False):
    deep_meta: dict[str, JsonValue]


class OpenGradeRow(Protocol):
    """Duck type for an exported dataset row (task input)."""

    input: object
    metadata: Mapping[str, object] | None


class OpenGradeSample(Protocol):
    """Duck type for an OpenGrade scored sample."""

    input: object
    output: object
    metadata: Mapping[str, object] | None

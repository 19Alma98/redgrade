"""Redgrade: red-team your LLM app in CI."""

from collections.abc import Callable

from redgrade.attachments import Attachment, AttachmentSpec
from redgrade.baseline import Baseline, BaselinePolicy, Waiver
from redgrade.loader import load_attacks
from redgrade.models import (
    Attack,
    AttackResult,
    HistoryTurn,
    RunResult,
    TargetObservation,
    ToolCall,
    Trial,
)
from redgrade.policy import Policy, evaluate_policy
from redgrade.runner import RunConfig, run_attacks
from redgrade.sdk import AttackError, AttackReport, attack, check
from redgrade.targets import ChatTarget, HttpTarget

__version__ = "0.4.0"

__all__ = [
    "Attachment",
    "AttachmentSpec",
    "Attack",
    "AttackError",
    "AttackReport",
    "AttackResult",
    "Baseline",
    "BaselinePolicy",
    "ChatTarget",
    "HistoryTurn",
    "HttpTarget",
    "Policy",
    "RunConfig",
    "RunResult",
    "TargetObservation",
    "ToolCall",
    "Trial",
    "Waiver",
    "attack",
    "check",
    "check_deep",
    "evaluate_policy",
    "load_attacks",
    "run_attacks",
]


def __getattr__(name: str) -> Callable[..., AttackReport]:
    if name == "check_deep":
        from redgrade.deep.sdk import check_deep

        return check_deep
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

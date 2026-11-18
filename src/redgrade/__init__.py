"""Redgrade: red-team your LLM app in CI."""

from redgrade.attachments import Attachment, AttachmentSpec
from redgrade.loader import load_attacks
from redgrade.models import Attack, AttackResult, RunResult, TargetObservation, ToolCall, Trial
from redgrade.policy import Policy, evaluate_policy
from redgrade.runner import RunConfig, run_attacks
from redgrade.sdk import AttackError, AttackReport, attack, check
from redgrade.targets import HttpTarget

__version__ = "0.4.0"

__all__ = [
    "Attachment",
    "AttachmentSpec",
    "Attack",
    "AttackError",
    "AttackReport",
    "AttackResult",
    "HttpTarget",
    "Policy",
    "RunConfig",
    "RunResult",
    "TargetObservation",
    "ToolCall",
    "Trial",
    "attack",
    "check",
    "check_deep",
    "evaluate_policy",
    "load_attacks",
    "run_attacks",
]


def __getattr__(name: str):
    if name == "check_deep":
        from redgrade.deep.sdk import check_deep

        return check_deep
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

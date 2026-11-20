"""Redgrade: red-team your LLM app in CI."""

from collections.abc import Callable

from redgrade.attachments import Attachment, AttachmentSpec
from redgrade.baseline import Baseline, BaselinePolicy, Waiver
from redgrade.classifiers import hf_text_classifier, register_classifier
from redgrade.defense import GuardedTarget, compare_defense
from redgrade.detectors import DetectorContext, register_detector, unregister_detector
from redgrade.judge import Judge, JudgeCache
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
from redgrade.oob import Fixture, OobServer
from redgrade.plugins import load_plugins
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
    "DetectorContext",
    "GuardedTarget",
    "Judge",
    "JudgeCache",
    "BaselinePolicy",
    "ChatTarget",
    "Fixture",
    "HistoryTurn",
    "HttpTarget",
    "OobServer",
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
    "compare_defense",
    "evaluate_policy",
    "hf_text_classifier",
    "load_plugins",
    "register_classifier",
    "register_detector",
    "unregister_detector",
    "load_attacks",
    "run_attacks",
]


def __getattr__(name: str) -> Callable[..., AttackReport]:
    if name == "check_deep":
        from redgrade.deep.sdk import check_deep

        return check_deep
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

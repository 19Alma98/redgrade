"""Redgrade: attack your AI agent before you release it.

``scan()`` attacks the agent's chat API (built-in, generated and adaptive attacks) and returns the
findings and a release verdict; ``check()`` replays the deterministic subset in CI.
"""

from collections.abc import Callable

from redgrade.attachments import Attachment, AttachmentSpec
from redgrade.baseline import Baseline, BaselinePolicy, Waiver
from redgrade.classifiers import hf_text_classifier, register_classifier
from redgrade.defense import GuardedTarget, compare_defense
from redgrade.detectors import DetectorContext, register_detector, unregister_detector
from redgrade.findings import Finding, Readiness
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
from redgrade.replay import ReplayReport, promote, replay
from redgrade.runner import RunConfig, run_attacks
from redgrade.scan import scan
from redgrade.sdk import AttackError, AttackReport, attack, check
from redgrade.targets import ChatTarget, HttpTarget
from redgrade.tool_server import ToolOutput, ToolServer, ToolServerConfig, ToolSpec

__version__ = "0.5.0"

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
    "Finding",
    "Fixture",
    "HistoryTurn",
    "HttpTarget",
    "OobServer",
    "Policy",
    "Readiness",
    "ReplayReport",
    "RunConfig",
    "RunResult",
    "TargetObservation",
    "ToolCall",
    "ToolOutput",
    "ToolServer",
    "ToolServerConfig",
    "ToolSpec",
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
    "promote",
    "replay",
    "run_attacks",
    "scan",
]


def __getattr__(name: str) -> Callable[..., AttackReport]:
    if name == "check_deep":
        from redgrade.deep.sdk import check_deep

        return check_deep
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

"""Redgrade: red-team your LLM app in CI."""

from redgrade.loader import load_attacks
from redgrade.models import Attack, AttackResult, RunResult, Trial
from redgrade.policy import Policy, evaluate_policy
from redgrade.runner import RunConfig, run_attacks

__version__ = "0.2.0"

__all__ = [
    "Attack",
    "AttackResult",
    "Policy",
    "RunConfig",
    "RunResult",
    "Trial",
    "evaluate_policy",
    "load_attacks",
    "run_attacks",
]

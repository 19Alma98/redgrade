"""Task-utility probes: separate from attack ASR (higher utility is better)."""

from redgrade.constants import FAMILY_TASK_UTILITY
from redgrade.models import AttackResult, RunResult


def is_utility_result(result: AttackResult) -> bool:
    return result.attack.family == FAMILY_TASK_UTILITY


def attack_results(run: RunResult) -> list[AttackResult]:
    return [r for r in run.executed if not is_utility_result(r)]


def utility_results(run: RunResult) -> list[AttackResult]:
    return [r for r in run.executed if is_utility_result(r)]


def utility_rate(run: RunResult) -> float | None:
    """Fraction of valid utility trials where the app still answered (detector matched)."""
    rows = utility_results(run)
    valid = sum(len(r.valid_trials) for r in rows)
    if not valid:
        return None
    wins = sum(r.successes for r in rows)
    return wins / valid

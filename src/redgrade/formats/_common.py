"""Shared view of a report: which results are findings, and how severe."""

from redgrade.baseline import bad_count
from redgrade.constants import FAMILY_TASK_UTILITY
from redgrade.models import AttackResult, RunResult
from redgrade.utility import gated_results

SECURITY_SEVERITY = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def findings(run: RunResult) -> list[AttackResult]:
    """Executed results where something went wrong: an attack worked or a benign probe failed."""
    return [r for r in gated_results(run) if bad_count(r) > 0]


def is_utility(result: AttackResult) -> bool:
    return result.attack.family == FAMILY_TASK_UTILITY


def finding_message(result: AttackResult, *, include_output: bool) -> str:
    n = len(result.valid_trials)
    bad = bad_count(result)
    if is_utility(result):
        text = f"Benign request was not answered in {bad}/{n} trials: {result.attack.title}"
    else:
        text = f"Attack succeeded in {bad}/{n} trials: {result.attack.title}"
    if include_output:
        bad_trial = next((t for t in result.valid_trials if t.succeeded != is_utility(result)), None)
        if bad_trial is not None:
            snippet = " ".join(bad_trial.output.split())[:200]
            text += f" | output: {snippet}"
    return text

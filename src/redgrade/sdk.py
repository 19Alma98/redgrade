"""Public SDK: attack an HTTP app endpoint and return an AttackReport."""

from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field

from redgrade.loader import load_attacks
from redgrade.models import AttackResult, RunResult
from redgrade.policy import Check, Policy, evaluate_policy, passed
from redgrade.report import to_dict, to_markdown
from redgrade.runner import RunConfig, run_attacks
from redgrade.scoring import PiScorer
from redgrade.targets import HttpTarget, Target
from redgrade.types import ReportDict


class AttackError(Exception):
    """Invalid SDK usage or empty attack selection."""


class AttackReport(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    passed: bool
    checks: list[Check] = Field(default_factory=list)
    run: RunResult
    policy: Policy
    pi_score: int | None = None
    highest_resisted_level: int | None = None
    asr_overall: float | None = None

    def summary(self) -> str:
        lines = [
            f"Redgrade: {'PASSED' if self.passed else 'FAILED'}",
            f"Overall ASR: {'n/a' if self.asr_overall is None else f'{self.asr_overall * 100:.0f}%'}",
        ]
        if self.pi_score is not None:
            lines.append(f"PI Maturity Score: {self.pi_score}/100")
        failed = [c for c in self.checks if not c.passed]
        if failed:
            lines.append("Failed checks:")
            for c in failed:
                lines.append(f"  - {c.name}: value={c.value:.4f} limit={c.limit:.4f}")
        bad = [r for r in self.run.executed if r.successes > 0]
        if bad:
            lines.append("Successful attacks:")
            for r in bad[:10]:
                lines.append(f"  - {r.attack.id}: {r.successes}/{len(r.valid_trials)} trials")
        return "\n".join(lines)

    def to_markdown(self) -> str:
        return to_markdown(self.run, self.checks, self.policy)

    def to_dict(self) -> ReportDict:
        return to_dict(self.run, self.checks, self.policy)


def _overall_asr(run: RunResult) -> float | None:
    valid = sum(len(r.valid_trials) for r in run.executed)
    if not valid:
        return None
    wins = sum(r.successes for r in run.executed)
    return wins / valid


def _build_report(run: RunResult, checks: list[Check], policy: Policy) -> AttackReport:
    posture = PiScorer().score(run, max_asr_by_level=policy.max_asr_by_level or None)
    return AttackReport(
        passed=passed(checks),
        checks=checks,
        run=run,
        policy=policy,
        pi_score=posture.score,
        highest_resisted_level=posture.highest_resisted_level,
        asr_overall=_overall_asr(run),
    )


def run_pipeline(
    target: Target,
    *,
    policy: Policy | None = None,
    families: list[str] | None = None,
    packs: list[str] | None = None,
    run_config: RunConfig | None = None,
    on_result: Callable[[AttackResult], None] | None = None,
) -> AttackReport:
    """Shared runner for SDK and CLI. Accepts any Target (including function wrappers)."""
    policy = policy or Policy()
    run_config = run_config or RunConfig()
    attacks = load_attacks(extra_packs=packs, families=families)
    if not attacks:
        raise AttackError("no attacks selected")
    run = run_attacks(attacks, target, run_config, on_result=on_result)
    checks = evaluate_policy(run, policy)
    return _build_report(run, checks, policy)


def attack(
    target: HttpTarget,
    *,
    policy: Policy | None = None,
    families: list[str] | None = None,
    packs: list[str] | None = None,
    trials: int | None = None,
    concurrency: int | None = None,
    secrets: list[str] | None = None,
    allowed_hosts: list[str] | None = None,
    max_output_chars: int | None = None,
) -> AttackReport:
    """Run attacks against an HTTP app endpoint and return an ``AttackReport``.

    ``packs`` is additive: built-in attack packs are always loaded, and any paths
    in ``packs`` are merged in (same as the CLI ``--pack`` / config ``extra_packs``).
    """
    if not isinstance(target, HttpTarget):
        raise AttackError("attack() requires an HttpTarget (HTTP endpoint of the app under test)")

    kwargs: dict[str, object] = {}
    if trials is not None:
        kwargs["trials"] = trials
    if concurrency is not None:
        kwargs["concurrency"] = concurrency
    if secrets is not None:
        kwargs["secrets"] = secrets
    if allowed_hosts is not None:
        kwargs["allowed_hosts"] = allowed_hosts
    if max_output_chars is not None:
        kwargs["max_output_chars"] = max_output_chars
    run_config = RunConfig(**kwargs) if kwargs else RunConfig()

    return run_pipeline(
        target,
        policy=policy,
        families=families,
        packs=packs,
        run_config=run_config,
    )

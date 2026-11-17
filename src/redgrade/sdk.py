"""Public SDK: attack an HTTP app endpoint and return an AttackReport."""

from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from redgrade.deep.meta import DeepMeta
from redgrade.loader import load_attacks
from redgrade.models import AttackResult, RunResult
from redgrade.pipelines import families_for_pipelines, resolve_pipelines
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
    deep_meta: DeepMeta | None = None
    mode: Literal["ci", "deep"] | None = None
    pipelines_run: list[str] = Field(default_factory=list)

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
        if self.deep_meta is not None:
            lines.extend(_deep_posture_lines(self.deep_meta))
        return "\n".join(lines)

    def to_markdown(self) -> str:
        md = to_markdown(self.run, self.checks, self.policy)
        if self.deep_meta is not None:
            md = md + "\n\n" + "\n".join(_deep_posture_lines(self.deep_meta))
        return md

    def to_dict(self) -> ReportDict:
        data = to_dict(self.run, self.checks, self.policy)
        if self.deep_meta is not None:
            data["deep_meta"] = self.deep_meta.model_dump()
        return data

    def export_winning_seeds(self, path: str | Path) -> int:
        """Write ``deep_meta.winning_seeds`` to an attack pack YAML; 0 if none."""
        if self.deep_meta is None or not self.deep_meta.winning_seeds:
            return 0
        from redgrade.deep.export import export_winning_seeds as write_winning_seeds

        return write_winning_seeds(self.deep_meta.winning_seeds, path)


def _deep_posture_lines(meta: DeepMeta) -> list[str]:
    lines = [
        "Deep posture:",
        f"  Attacker model: {meta.attacker_model}",
    ]
    if meta.attacker_api_base is not None:
        lines.append(f"  API base: {meta.attacker_api_base}")
    lines.append(f"  Max rounds: {meta.max_rounds}")
    lines.append(f"  Goals succeeded: {meta.goals_succeeded}/{meta.goals_total}")
    lines.append(f"  Target kind: {meta.target_kind}")
    if meta.rounds_used_by_goal:
        lines.append("  Rounds used by goal:")
        for goal_id, rounds in sorted(meta.rounds_used_by_goal.items()):
            lines.append(f"    - {goal_id}: {rounds}")
    return lines


def _overall_asr(run: RunResult) -> float | None:
    valid = sum(len(r.valid_trials) for r in run.executed)
    if not valid:
        return None
    wins = sum(r.successes for r in run.executed)
    return wins / valid


def _build_report(
    run: RunResult,
    checks: list[Check],
    policy: Policy,
    *,
    deep_meta: DeepMeta | None = None,
) -> AttackReport:
    posture = PiScorer().score(run, max_asr_by_level=policy.max_asr_by_level or None)
    return AttackReport(
        passed=passed(checks),
        checks=checks,
        run=run,
        policy=policy,
        pi_score=posture.score,
        highest_resisted_level=posture.highest_resisted_level,
        asr_overall=_overall_asr(run),
        deep_meta=deep_meta,
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


def check(
    target: HttpTarget,
    *,
    policy: Policy | None = None,
    pipelines: list[str] | None = None,
    disable: list[str] | None = None,
    extra_packs: list[str] | None = None,
    trials: int | None = None,
    concurrency: int | None = None,
    secrets: list[str] | None = None,
    allowed_hosts: list[str] | None = None,
    max_output_chars: int | None = None,
) -> AttackReport:
    """Run CI pipeline checks against an HTTP app endpoint."""
    if not isinstance(target, HttpTarget):
        raise AttackError("check() requires an HttpTarget (HTTP endpoint of the app under test)")

    specs = resolve_pipelines(pipelines, disable)
    ci_specs = [s for s in specs if not s.lab]
    if not ci_specs:
        raise AttackError("no CI pipelines selected (lab.adaptive_pi is deep-only)")

    families = families_for_pipelines(ci_specs)

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

    policy = policy or Policy()
    report = run_pipeline(
        target,
        policy=policy,
        families=families,
        packs=extra_packs,
        run_config=run_config,
    )
    return report.model_copy(
        update={"mode": "ci", "pipelines_run": [s.id for s in ci_specs]},
    )

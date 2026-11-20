"""Public SDK: attack an HTTP app endpoint and return an AttackReport."""

import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from redgrade.baseline import (
    DEFAULT_BASELINE_PATH,
    Baseline,
    BaselineComparison,
    BaselineError,
    BaselinePolicy,
    baseline_markdown,
    compare,
)
from redgrade.compliance import ComplianceReport, build_compliance
from redgrade.constants import (
    DEFAULT_CHECK_PIPELINES,
    PIPELINE_CI_AGENT,
    PIPELINE_CI_ATTACHMENTS,
    PIPELINE_CI_OOB,
    PIPELINE_CI_UTILITY,
)
from redgrade.deep.meta import DeepMeta
from redgrade.extensions import as_judge
from redgrade.findings import (
    DEFAULT_REQUIRED_LEVEL,
    Finding,
    Readiness,
    Source,
    assess_readiness,
    build_findings,
    findings_markdown,
)
from redgrade.identity import Identity
from redgrade.judge import Chat, Judge, JudgeCache
from redgrade.levels import LevelPosture, LevelScorer
from redgrade.loader import load_attacks
from redgrade.models import AttackResult, RunResult
from redgrade.oob import OobServer
from redgrade.pipelines import families_for_pipelines, resolve_pipelines
from redgrade.policy import Check, Policy, evaluate_policy, passed
from redgrade.report import to_dict, to_markdown
from redgrade.runner import RunConfig, run_attacks
from redgrade.scorecard import Scorecard, build_scorecard, scorecard_markdown
from redgrade.scoring import PiScorer
from redgrade.targets import HttpTarget, Target, target_observes_tools
from redgrade.types import ReportDict
from redgrade.utility import attack_results, utility_rate


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
    security_level: int | None = None  # holds every tested level up to this one (all families)
    first_broken_level: int | None = None
    asr_overall: float | None = None
    utility_overall: float | None = None
    deep_meta: DeepMeta | None = None
    mode: Literal["ci", "deep", "scan"] | None = None
    pipelines_run: list[str] = Field(default_factory=list)
    baseline: BaselineComparison | None = None
    grade: str | None = None
    security_score: int | None = None
    # Scan: the level the agent must hold to be released, where each attack came from, and notes
    # on what the scan could not do (no attacker, skipped surfaces...).
    required_level: int | None = None
    attack_sources: dict[str, Source] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)

    def findings(self) -> list[Finding]:
        """Attacks that got through at least once, with reproduction and a suggested fix."""
        return build_findings(self.run, deep_meta=self.deep_meta, sources=self.attack_sources)

    def readiness(self, required_level: int | None = None) -> Readiness:
        """Release verdict: does the agent hold every level up to ``required_level``?

        Defaults to the level the scan was run with, then ``policy.min_security_level``, then L3.
        """
        level = (
            required_level or self.required_level or self.policy.min_security_level or DEFAULT_REQUIRED_LEVEL
        )
        return assess_readiness(
            self.run,
            self.findings(),
            self.levels(),
            required_level=level,
            max_error_rate=self.policy.max_error_rate,
            notes=self.notes,
        )

    def compliance(self, frameworks: list[str] | None = None) -> ComplianceReport:
        """Per-control status for OWASP LLM / Agentic, MITRE ATLAS, NIST AI RMF, EU AI Act."""
        return build_compliance(self.run, frameworks)

    def scorecard(self) -> Scorecard:
        """Per-family and overall score with 95% ranges and a letter grade."""
        return build_scorecard(self.run)

    def levels(self) -> LevelPosture:
        """The level ladder: per-level ASR, how far the app holds, per-family ladders."""
        return LevelScorer().score(self.run, max_asr_by_level=self.policy.max_asr_by_level or None)

    def summary(self) -> str:
        if self.mode == "scan":
            return self._scan_summary()
        lines = [
            f"Redgrade: {'PASSED' if self.passed else 'FAILED'}",
            f"Overall ASR: {'n/a' if self.asr_overall is None else f'{self.asr_overall * 100:.0f}%'}",
        ]
        if self.utility_overall is not None:
            lines.append(f"Utility: {self.utility_overall * 100:.0f}%")
        lines.append(f"Security level: {self.levels().verdict}")
        if self.pi_score is not None:
            lines.append(f"PI Maturity Score: {self.pi_score}/100")
        if self.security_score is not None:
            lines.append(f"Security grade: {self.grade} ({self.security_score}/100)")
        failed = [c for c in self.checks if not c.passed]
        if failed:
            lines.append("Failed checks:")
            for c in failed:
                if c.name.startswith("utility.") or c.name == "coverage.task_utility":
                    lines.append(f"  - {c.name}: value={c.value:.4f} min={c.limit:.4f}")
                else:
                    lines.append(f"  - {c.name}: value={c.value:.4f} limit={c.limit:.4f}")
        if self.baseline is not None:
            reg = self.baseline.regressions
            lines.append(f"Baseline: {len(reg)} regression(s), {len(self.baseline.improved)} improved")
            for d in reg[:10]:
                lines.append(
                    f"  - regression {d.id}: {d.base_bad}/{d.base_valid} -> {d.now_bad}/{d.now_valid}"
                )
        bad = [r for r in attack_results(self.run) if r.successes > 0]
        if bad:
            lines.append("Successful attacks:")
            for r in bad[:10]:
                lines.append(f"  - {r.attack.id}: {r.successes}/{len(r.valid_trials)} trials")
        if self.deep_meta is not None:
            lines.extend(_deep_posture_lines(self.deep_meta))
        return "\n".join(lines)

    def _scan_summary(self) -> str:
        ready = self.readiness()
        lines = [ready.verdict]
        lines.append(f"Security level: {self.levels().verdict}")
        if self.security_score is not None:
            lines.append(f"Security grade: {self.grade} ({self.security_score}/100)")
        if self.utility_overall is not None:
            lines.append(f"Utility: {self.utility_overall * 100:.0f}%")
        findings = self.findings()
        blocking = set(ready.blocking)
        if findings:
            lines.append(f"Findings ({len(findings)}, {len(blocking)} blocking):")
            for f in findings[:15]:
                mark = "BLOCKING " if f.id in blocking else ""
                level = f"L{f.level}" if f.level else "L?"
                lines.append(
                    f"  - {mark}{f.id} [{f.severity}, {level}, {f.surface}]: {f.title} "
                    f"({f.successes}/{f.valid})"
                )
            if len(findings) > 15:
                lines.append(f"  ... and {len(findings) - 15} more (report.findings())")
        for w in ready.warnings:
            lines.append(f"Note: {w}")
        return "\n".join(lines)

    def to_markdown(self, *, include_output: bool = True) -> str:
        md = to_markdown(self.run, self.checks, self.policy)
        if self.mode == "scan":
            body = md.split("\n", 1)[1] if "\n" in md else ""
            body = body.replace("## Gate", "## Policy checks", 1)
            head = ["# Redgrade scan", ""]
            head += findings_markdown(self.readiness(), self.findings(), include_output=include_output)
            md = "\n".join(head) + "\n\n# Details\n" + body
        md = md.rstrip("\n") + "\n" + "\n".join(scorecard_markdown(self.scorecard())) + "\n"
        if self.baseline is not None:
            md = md.rstrip("\n") + "\n" + "\n".join(baseline_markdown(self.baseline)) + "\n"
        if self.deep_meta is not None:
            md = md + "\n\n" + "\n".join(_deep_posture_lines(self.deep_meta))
        return md

    def to_dict(self) -> ReportDict:
        data = to_dict(self.run, self.checks, self.policy)
        if self.mode is not None:
            data["mode"] = self.mode
        if self.mode == "scan":
            ready = self.readiness()
            data["readiness"] = ready.model_dump(mode="json") | {"verdict": ready.verdict}
            data["findings"] = [f.model_dump(mode="json") for f in self.findings()]
            data["notes"] = list(self.notes)
        if self.deep_meta is not None:
            data["deep_meta"] = self.deep_meta.model_dump()
        data["scorecard"] = self.scorecard().model_dump(mode="json")
        if self.baseline is not None:
            data["baseline"] = self.baseline.model_dump(mode="json")
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    def to_sarif(self, *, location_uri: str = "redgrade.yaml", include_output: bool = False) -> str:
        """SARIF 2.1.0 for GitHub code scanning (model output omitted unless requested)."""
        from redgrade import __version__
        from redgrade.formats.sarif import to_sarif

        return to_sarif(
            self.run,
            version=__version__,
            comparison=self.baseline,
            location_uri=location_uri,
            include_output=include_output,
        )

    def to_junit(self, *, include_output: bool = False) -> str:
        """JUnit XML: one testsuite per family plus the gate checks."""
        from redgrade.formats.junit import to_junit

        return to_junit(self.run, self.checks, include_output=include_output)

    def to_html(self, *, include_output: bool = False) -> str:
        """Self-contained HTML report (no scripts or external requests)."""
        from redgrade import __version__
        from redgrade.formats.html import to_html

        return to_html(
            self.run,
            self.checks,
            version=__version__,
            comparison=self.baseline,
            include_output=include_output,
            max_asr_by_level=self.policy.max_asr_by_level or None,
        )

    def to_baseline(self) -> Baseline:
        """Snapshot of this run, to commit as the reference for later comparisons."""
        return Baseline.from_run(self.run)

    def save_baseline(self, path: str | Path | None = None) -> Path:
        out = Path(path or (self.policy.baseline.path if self.policy.baseline else DEFAULT_BASELINE_PATH))
        self.to_baseline().save(out)
        return out

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
    attacks = attack_results(run)
    valid = sum(len(r.valid_trials) for r in attacks)
    if not valid:
        return None
    wins = sum(r.successes for r in attacks)
    return wins / valid


def _build_report(
    run: RunResult,
    checks: list[Check],
    policy: Policy,
    *,
    deep_meta: DeepMeta | None = None,
) -> AttackReport:
    posture = PiScorer().score(run, max_asr_by_level=policy.max_asr_by_level or None)
    ladder = LevelScorer().score(run, max_asr_by_level=policy.max_asr_by_level or None)
    card = build_scorecard(run)
    return AttackReport(
        passed=passed(checks),
        checks=checks,
        run=run,
        policy=policy,
        pi_score=posture.score,
        highest_resisted_level=posture.highest_resisted_level,
        security_level=ladder.resisted_up_to,
        first_broken_level=ladder.first_broken,
        grade=card.grade,
        security_score=card.score,
        asr_overall=_overall_asr(run),
        utility_overall=utility_rate(run),
        deep_meta=deep_meta,
    )


@contextmanager
def oob_collector(oob: OobServer | bool | None) -> Iterator[OobServer | None]:
    """Resolve the SDK ``oob`` argument: ``True`` starts (and stops) a local collector, a stopped
    ``OobServer`` is started for the run and stopped after, a running one is used as is."""
    if not oob:
        yield None
        return
    server = OobServer() if oob is True else oob
    if not isinstance(server, OobServer):
        raise AttackError("oob must be True, False/None or an OobServer")
    if server.running:
        yield server
        return
    with server:
        yield server


def run_pipeline(
    target: Target,
    *,
    policy: Policy | None = None,
    families: list[str] | None = None,
    packs: list[str] | None = None,
    run_config: RunConfig | None = None,
    on_result: Callable[[AttackResult], None] | None = None,
    baseline: Baseline | str | Path | None = None,
    oob: OobServer | bool | None = None,
    judge: Judge | Chat | None = None,
    judge_cache: str | Path | JudgeCache | None = None,
) -> AttackReport:
    """Shared runner for SDK and CLI. Accepts any Target (including function wrappers).

    ``baseline`` (a ``Baseline`` or a path) enables the per-attack regression gate; without it,
    ``policy.baseline.path`` is used when the policy configures one. ``oob`` enables the
    out-of-band collector (see ``redgrade.oob``) for attacks that need it.
    """
    policy = policy or Policy()
    if baseline is not None and policy.baseline is None:
        path = baseline if isinstance(baseline, (str, Path)) else DEFAULT_BASELINE_PATH
        policy = policy.model_copy(update={"baseline": BaselinePolicy(path=str(path))})
    elif isinstance(baseline, (str, Path)) and policy.baseline is not None:
        policy = policy.model_copy(
            update={"baseline": policy.baseline.model_copy(update={"path": str(baseline)})}
        )
    loaded: Baseline | None = None
    if policy.baseline is not None:
        try:
            loaded = baseline if isinstance(baseline, Baseline) else Baseline.load(policy.baseline.path)
        except BaselineError as exc:
            raise AttackError(str(exc)) from exc
    run_config = run_config or RunConfig()
    attacks = load_attacks(extra_packs=packs, families=families)
    if not attacks:
        raise AttackError("no attacks selected")
    scorer = as_judge(judge, judge_cache)
    with oob_collector(oob) as server:
        run = run_attacks(attacks, target, run_config, on_result=on_result, oob=server, judge=scorer)
    if scorer is not None and scorer.cache is not None:
        scorer.cache.save()
    comparison = compare(run, loaded, policy.baseline) if loaded and policy.baseline else None
    checks = evaluate_policy(run, policy, comparison)
    report = _build_report(run, checks, policy)
    return report.model_copy(update={"baseline": comparison}) if comparison else report


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
    baseline: Baseline | str | Path | None = None,
    oob: OobServer | bool | None = None,
    identity: Identity | dict[str, object] | None = None,
    judge: Judge | Chat | None = None,
    judge_cache: str | Path | JudgeCache | None = None,
) -> AttackReport:
    """Run attacks against an HTTP app endpoint and return an ``AttackReport``.

    ``packs`` is additive: built-in attack packs are always loaded, and any paths
    in ``packs`` are merged in (same as the CLI ``--pack`` / config ``extra_packs``).
    ``oob=True`` (or an ``OobServer``) runs the out-of-band collector for agents that fetch URLs.
    ``judge`` (a chat callable ``messages -> str``) scores ``llm_judge`` attacks; ``judge_cache``
    (a path) reuses verdicts for identical outputs. Without a judge those attacks are skipped.
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
    if identity is not None:
        kwargs["identity"] = identity if isinstance(identity, Identity) else Identity.model_validate(identity)
    run_config = RunConfig(**kwargs) if kwargs else RunConfig()

    return run_pipeline(
        target,
        policy=policy,
        families=families,
        packs=packs,
        run_config=run_config,
        baseline=baseline,
        oob=oob,
        judge=judge,
        judge_cache=judge_cache,
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
    baseline: Baseline | str | Path | None = None,
    oob: OobServer | bool | None = None,
    identity: Identity | dict[str, object] | None = None,
    judge: Judge | Chat | None = None,
    judge_cache: str | Path | JudgeCache | None = None,
) -> AttackReport:
    """Run CI pipeline checks against an HTTP app endpoint.

    When ``pipelines`` is omitted and the target can receive files (``upload_field`` or an
    ``{{attachments}}`` body template), ``ci.attachments`` runs as well; with ``oob`` (``True`` or
    an ``OobServer``), ``ci.oob`` runs the attacker-web / out-of-band exfiltration attacks.
    """
    if not isinstance(target, HttpTarget):
        raise AttackError("check() requires an HttpTarget (HTTP endpoint of the app under test)")

    if pipelines is None:
        # Default pipelines plus the surfaces the target has (opt-out via ``disable``).
        pipelines = list(DEFAULT_CHECK_PIPELINES)
        if target.accepts_attachments:
            pipelines.append(PIPELINE_CI_ATTACHMENTS)
        if oob:
            pipelines.append(PIPELINE_CI_OOB)
        if target_observes_tools(target):
            pipelines.append(PIPELINE_CI_AGENT)
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
    if identity is not None:
        kwargs["identity"] = identity if isinstance(identity, Identity) else Identity.model_validate(identity)
    run_config = RunConfig(**kwargs) if kwargs else RunConfig()

    policy = policy or Policy()
    utility_on = any(s.id == PIPELINE_CI_UTILITY for s in ci_specs)
    if utility_on and "require_utility" not in policy.model_fields_set:
        policy = policy.model_copy(update={"require_utility": True})
    report = run_pipeline(
        target,
        policy=policy,
        families=families,
        packs=extra_packs,
        run_config=run_config,
        baseline=baseline,
        oob=oob,
        judge=judge,
        judge_cache=judge_cache,
    )
    return report.model_copy(
        update={"mode": "ci", "pipelines_run": [s.id for s in ci_specs]},
    )

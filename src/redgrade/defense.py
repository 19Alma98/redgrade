"""Measure a defense: the same attacks against the app without and with it (A/B).

A guardrail is worth what it blocks *minus* what it breaks. ``compare_defense`` runs one attack
set against a baseline target and a defended target and reports, side by side:

- attack success rate overall, per family and per level, with 95% Wilson intervals and whether
  the change is significant (non-overlapping intervals);
- utility on the benign probes (over-refusal is the usual price of a guard);
- latency added per call (mean and p95);
- attacks the defense **blocked** (worked before, not after), attacks **still working**, and
  attacks that **started working** with the defense (it happens: a guard that rewrites input).

The defended side can be a different endpoint (``redgrade compare -c base.yaml -d guarded.yaml``)
or the same app wrapped in ``GuardedTarget`` with your input/output classifiers, to test a
guard before wiring it in::

    guarded = GuardedTarget(app, input_guard=lambda req: prompt_guard(req.text) > 0.5)
    result = compare_defense(app, guarded, families=["prompt_injection_direct"])
    print(result.to_markdown())
"""

import json
import statistics
import threading
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field

from pydantic import BaseModel, Field

from redgrade.attachments import Attachment
from redgrade.constants import FAMILY_TASK_UTILITY
from redgrade.judge import Judge
from redgrade.loader import load_attacks
from redgrade.models import AttackResult, RunResult, TargetObservation
from redgrade.oob import OobServer
from redgrade.runner import RunConfig, run_attacks
from redgrade.stats import wilson_interval
from redgrade.targets import (
    Target,
    invoke_target,
    normalize_observation,
    target_accepts_attachments,
    target_accepts_history,
    target_observes_tools,
)
from redgrade.types import HistoryMessage, JsonValue
from redgrade.utility import attack_results, utility_results

__all__ = ["DefenseReport", "GuardRequest", "GuardedTarget", "compare_defense"]

DEFAULT_BLOCKED_MESSAGE = "I can't help with that request."


@dataclass(frozen=True)
class GuardRequest:
    """What an input guard sees: the prompt and everything that came with it."""

    prompt: str
    documents: list[str] = field(default_factory=list)
    history: list[HistoryMessage] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)

    @property
    def text(self) -> str:
        """All text in one string (history, documents, attachment text, prompt)."""
        parts = [str(m.get("content", "")) for m in self.history]
        parts += self.documents
        parts += [a.text for a in self.attachments if a.text]
        parts.append(self.prompt)
        return "\n\n".join(p for p in parts if p)


InputGuard = Callable[[GuardRequest], object]
OutputGuard = Callable[[str], object]


class GuardedTarget:
    """Wrap a target with input / output guards. A truthy guard result blocks the call and the
    target answers ``blocked_message`` instead (input guard: the app is not called at all).
    The wrapper keeps the inner target's surfaces (history, tools, attachments)."""

    def __init__(
        self,
        target: Target,
        *,
        input_guard: InputGuard | None = None,
        output_guard: OutputGuard | None = None,
        blocked_message: str = DEFAULT_BLOCKED_MESSAGE,
    ) -> None:
        self.inner = target
        self.input_guard = input_guard
        self.output_guard = output_guard
        self.blocked_message = blocked_message
        self.calls = 0
        self.blocked_input = 0
        self.blocked_output = 0
        self._lock = threading.Lock()
        self._redgrade_observes_tools = target_observes_tools(target)
        self._redgrade_accepts_history = target_accepts_history(target)
        self._redgrade_accepts_attachments = target_accepts_attachments(target)

    def __call__(
        self,
        prompt: str,
        documents: list[str],
        history: list[HistoryMessage] | None = None,
        tools: list[JsonValue] | None = None,
        attachments: list[Attachment] | None = None,
    ) -> TargetObservation:
        with self._lock:
            self.calls += 1
        request = GuardRequest(prompt, list(documents), list(history or []), list(attachments or []))
        if self.input_guard is not None and self.input_guard(request):
            with self._lock:
                self.blocked_input += 1
            return TargetObservation(output=self.blocked_message)
        obs = normalize_observation(invoke_target(self.inner, prompt, documents, history, tools, attachments))
        if self.output_guard is not None and self.output_guard(obs.output):
            with self._lock:
                self.blocked_output += 1
            return TargetObservation(output=self.blocked_message)
        return obs


class RateDelta(BaseModel):
    """One rate, before and after, with 95% intervals."""

    name: str
    attacks: int
    before: float | None
    after: float | None
    before_ci: tuple[float, float]
    after_ci: tuple[float, float]

    @property
    def delta(self) -> float | None:
        if self.before is None or self.after is None:
            return None
        return self.after - self.before

    @property
    def significant(self) -> bool:
        """The 95% intervals do not overlap."""
        return self.after_ci[1] < self.before_ci[0] or self.after_ci[0] > self.before_ci[1]


class DefenseReport(BaseModel):
    baseline_label: str = "baseline"
    defended_label: str = "defended"
    trials: int
    asr: RateDelta
    utility: RateDelta | None = None
    families: list[RateDelta] = Field(default_factory=list)
    levels: list[RateDelta] = Field(default_factory=list)
    blocked: list[str] = Field(default_factory=list)
    still_working: list[str] = Field(default_factory=list)
    newly_working: list[str] = Field(default_factory=list)
    broken_probes: list[str] = Field(default_factory=list)
    latency_before: tuple[float, float] | None = None  # mean, p95 seconds
    latency_after: tuple[float, float] | None = None
    guard_stats: dict[str, int] | None = None
    baseline_run: RunResult
    defended_run: RunResult

    @property
    def utility_drop(self) -> float:
        if self.utility is None or self.utility.delta is None:
            return 0.0
        return max(0.0, -self.utility.delta)

    def effective(self, *, max_utility_drop: float = 0.0) -> bool:
        """ASR went down (or stayed at 0), nothing started working, utility held within budget."""
        asr_ok = self.asr.delta is not None and (self.asr.delta < 0 or (self.asr.after or 0.0) == 0.0)
        return asr_ok and not self.newly_working and self.utility_drop <= max_utility_drop

    @property
    def verdict(self) -> str:
        if self.newly_working:
            return f"regression: {len(self.newly_working)} attack(s) work only with the defense"
        if self.asr.delta is None:
            return "inconclusive: no valid attack trials"
        if self.asr.delta >= 0 and (self.asr.after or 0) > 0:
            return "no improvement in attack success rate"
        sig = "significant" if self.asr.significant else "not significant with these trials"
        drop = f", utility -{self.utility_drop * 100:.0f} pts" if self.utility_drop else ""
        return f"ASR {_pct(self.asr.before)} -> {_pct(self.asr.after)} ({sig}){drop}"

    def to_dict(self) -> dict[str, object]:
        data = self.model_dump(exclude={"baseline_run", "defended_run"})
        data["verdict"] = self.verdict
        data["utility_drop"] = self.utility_drop
        for key in ("asr", "utility"):
            if data.get(key) is not None:
                rd = getattr(self, key)
                data[key].update(delta=rd.delta, significant=rd.significant)
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    def to_markdown(self) -> str:
        b, d = self.baseline_label, self.defended_label
        lines = [
            f"# Defense comparison: {b} vs {d}",
            "",
            f"**{self.verdict}**",
            "",
            f"Same attacks, {self.trials} trial(s) each. ASR lower is better; utility higher is better. "
            "Ranges are 95% Wilson intervals; *significant* = the ranges do not overlap.",
            "",
            f"| metric | {b} | {d} | change | |",
            "|---|---|---|---|---|",
        ]
        for rd, label in ((self.asr, "ASR (attacks)"), (self.utility, "utility (benign probes)")):
            if rd is not None:
                lines.append(_row(label, rd))
        if self.latency_before and self.latency_after:
            (mb, pb), (ma, pa) = self.latency_before, self.latency_after
            lines.append(
                f"| latency mean / p95 | {mb * 1000:.0f} / {pb * 1000:.0f} ms | "
                f"{ma * 1000:.0f} / {pa * 1000:.0f} ms | {(ma - mb) * 1000:+.0f} ms | |"
            )
        if self.guard_stats:
            gs = self.guard_stats
            lines.append(
                f"| guard blocks (input / output) | | {gs['blocked_input']} / {gs['blocked_output']} "
                f"of {gs['calls']} calls | | |"
            )
        if self.families:
            lines += [
                "",
                "## By family",
                "",
                f"| family | attacks | {b} | {d} | change | |",
                "|---|---|---|---|---|---|",
            ]
            lines += [_row(rd.name, rd, attacks=True) for rd in self.families]
        if self.levels:
            lines += [
                "",
                "## By level",
                "",
                f"| level | attacks | {b} | {d} | change | |",
                "|---|---|---|---|---|---|",
            ]
            lines += [_row(rd.name, rd, attacks=True) for rd in self.levels]
        for title, ids in (
            ("Blocked by the defense", self.blocked),
            ("Still working", self.still_working),
            ("Working only with the defense (regressions)", self.newly_working),
            ("Benign probes broken by the defense (over-refusal)", self.broken_probes),
        ):
            if ids:
                lines += ["", f"## {title} ({len(ids)})", "", ", ".join(ids)]
        lines += ["", "> Same attacks, few trials: treat small changes as noise unless marked significant."]
        return "\n".join(lines) + "\n"


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.0f}%"


def _row(label: str, rd: RateDelta, *, attacks: bool = False) -> str:
    delta = "n/a" if rd.delta is None else f"{rd.delta * 100:+.0f} pts"
    sig = "significant" if rd.significant else ""
    before = f"{_pct(rd.before)} [{_pct(rd.before_ci[0])}-{_pct(rd.before_ci[1])}]"
    after = f"{_pct(rd.after)} [{_pct(rd.after_ci[0])}-{_pct(rd.after_ci[1])}]"
    if attacks:
        return f"| {label} | {rd.attacks} | {before} | {after} | {delta} | {sig} |"
    return f"| {label} | {before} | {after} | {delta} | {sig} |"


def _tally(rows: list[AttackResult]) -> tuple[int, int]:
    valid = sum(len(r.valid_trials) for r in rows)
    good = sum(r.successes for r in rows)
    return good, valid


def _delta(name: str, before: list[AttackResult], after: list[AttackResult]) -> RateDelta:
    sb, nb = _tally(before)
    sa, na = _tally(after)
    return RateDelta(
        name=name,
        attacks=len({r.attack.id for r in before} | {r.attack.id for r in after}),
        before=sb / nb if nb else None,
        after=sa / na if na else None,
        before_ci=wilson_interval(sb, nb),
        after_ci=wilson_interval(sa, na),
    )


def _latency(run: RunResult) -> tuple[float, float] | None:
    values = sorted(t.latency_s for r in run.executed for t in r.valid_trials)
    if not values:
        return None
    p95 = values[min(len(values) - 1, int(round(0.95 * (len(values) - 1))))]
    return statistics.fmean(values), p95


def compare_runs(
    before: RunResult,
    after: RunResult,
    *,
    baseline_label: str = "baseline",
    defended_label: str = "defended",
    guard_stats: dict[str, int] | None = None,
) -> DefenseReport:
    """Compare two runs of the same attacks (only ids executed in both are compared)."""
    b_attacks = {r.attack.id: r for r in attack_results(before)}
    a_attacks = {r.attack.id: r for r in attack_results(after)}
    common = sorted(set(b_attacks) & set(a_attacks))
    b_rows = [b_attacks[i] for i in common]
    a_rows = [a_attacks[i] for i in common]

    by_family: dict[str, tuple[list[AttackResult], list[AttackResult]]] = defaultdict(lambda: ([], []))
    by_level: dict[str, tuple[list[AttackResult], list[AttackResult]]] = defaultdict(lambda: ([], []))
    for i in common:
        fam = b_attacks[i].attack.family
        by_family[fam][0].append(b_attacks[i])
        by_family[fam][1].append(a_attacks[i])
        level = b_attacks[i].attack.level
        if level is not None:
            by_level[f"L{level}"][0].append(b_attacks[i])
            by_level[f"L{level}"][1].append(a_attacks[i])

    b_util = {r.attack.id: r for r in utility_results(before)}
    a_util = {r.attack.id: r for r in utility_results(after)}
    util_common = sorted(set(b_util) & set(a_util))
    utility = (
        _delta(FAMILY_TASK_UTILITY, [b_util[i] for i in util_common], [a_util[i] for i in util_common])
        if util_common
        else None
    )
    broken = [
        i
        for i in util_common
        if b_util[i].valid_trials
        and b_util[i].successes == len(b_util[i].valid_trials)
        and a_util[i].successes < len(a_util[i].valid_trials)
    ]
    return DefenseReport(
        baseline_label=baseline_label,
        defended_label=defended_label,
        trials=before.trials_per_attack,
        asr=_delta("overall", b_rows, a_rows),
        utility=utility,
        families=[_delta(f, *rows) for f, rows in sorted(by_family.items())],
        levels=[_delta(lv, *rows) for lv, rows in sorted(by_level.items())],
        blocked=[i for i in common if b_attacks[i].successes and not a_attacks[i].successes],
        still_working=[i for i in common if b_attacks[i].successes and a_attacks[i].successes],
        newly_working=[
            i
            for i in common
            if not b_attacks[i].successes and a_attacks[i].successes and b_attacks[i].valid_trials
        ],
        broken_probes=broken,
        latency_before=_latency(before),
        latency_after=_latency(after),
        guard_stats=guard_stats,
        baseline_run=before,
        defended_run=after,
    )


def compare_defense(
    baseline: Target,
    defended: Target,
    *,
    families: list[str] | None = None,
    packs: list[str] | None = None,
    include_opt_in: bool = False,
    run_config: RunConfig | None = None,
    oob: OobServer | None = None,
    judge: Judge | None = None,
    baseline_label: str = "baseline",
    defended_label: str = "defended",
) -> DefenseReport:
    """Run the same attacks against ``baseline`` and ``defended`` and compare them."""
    attacks = load_attacks(extra_packs=packs, families=families, include_opt_in=include_opt_in)
    config = run_config or RunConfig()
    before = run_attacks(attacks, baseline, config, oob=oob, judge=judge)
    after = run_attacks(attacks, defended, config, oob=oob, judge=judge)
    stats = None
    if isinstance(defended, GuardedTarget):
        stats = {
            "calls": defended.calls,
            "blocked_input": defended.blocked_input,
            "blocked_output": defended.blocked_output,
        }
    return compare_runs(
        before, after, baseline_label=baseline_label, defended_label=defended_label, guard_stats=stats
    )

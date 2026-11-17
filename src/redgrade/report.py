"""Reports: Markdown for humans, JSON for machines."""

import json
from collections import defaultdict

from redgrade.constants import (
    FAMILY_STATUS_AVAILABLE,
    FAMILY_TASK_UTILITY,
    PI_LEVEL_WEIGHTS,
    REPORT_SNIPPET_CHARS,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)
from redgrade.families import FAMILIES
from redgrade.models import AttackResult, RunResult
from redgrade.policy import Check, Policy, passed
from redgrade.scoring import PiPosture, PiScorer
from redgrade.types import AttackSummary, CheckDict, FamilyStat, PiPostureDict, ReportDict
from redgrade.utility import attack_results, utility_rate

_SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 0,
    SEVERITY_HIGH: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 3,
}


class ReportBuilder:
    """Build machine and human-readable reports from a run and its gate checks."""

    def family_stats(self, run: RunResult) -> dict[str, FamilyStat]:
        counts: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
        for r in run.executed:
            bucket = counts[r.attack.family]
            bucket[0] += 1
            bucket[1] += len(r.valid_trials)
            bucket[2] += r.successes
        stats: dict[str, FamilyStat] = {}
        for family, (attacks, valid, wins) in counts.items():
            rate = wins / valid if valid else None
            stats[family] = {
                "attacks": attacks,
                "valid": valid,
                "wins": wins,
                # task_utility: wins = probes that still answered (utility rate, higher better)
                "asr": rate,
            }
        return stats

    def _score_posture(self, run: RunResult, policy: Policy | None) -> PiPosture:
        if policy is None:
            return PiScorer().score(run, max_asr_by_level={})
        return PiScorer().score(run, max_asr_by_level=policy.max_asr_by_level or None)

    def _posture_dict(self, posture: PiPosture) -> PiPostureDict:
        return {
            "score": posture.score,
            "highest_resisted_level": posture.highest_resisted_level,
            "asr_by_level": {str(level): rate for level, rate in posture.asr_by_level.items()},
            "unleveled": posture.unleveled,
            "failing_techniques": posture.failing_techniques,
        }

    def _pi_posture_markdown(self, posture: PiPosture) -> list[str]:
        if posture.score is None:
            score_line = "PI Maturity Score: n/a (no leveled PI attacks ran)"
        else:
            score_line = f"PI Maturity Score: {posture.score}/100"
        resisted = (
            f"L{posture.highest_resisted_level}" if posture.highest_resisted_level is not None else "n/a"
        )
        lines = [
            "",
            "## Prompt injection posture",
            "",
            f"- {score_line}",
            f"- Highest resisted level: {resisted}",
            f"- Unleveled attacks (excluded from score): {posture.unleveled}",
            "",
            "| level | ASR |",
            "|---|---|",
        ]
        for level in PI_LEVEL_WEIGHTS:
            lines.append(f"| L{level} | {_pct(posture.asr_by_level.get(level))} |")
        return lines

    def to_dict(self, run: RunResult, checks: list[Check], policy: Policy | None = None) -> ReportDict:
        check_rows: list[CheckDict] = [
            {"name": c.name, "value": c.value, "limit": c.limit, "passed": c.passed} for c in checks
        ]
        attack_rows: list[AttackSummary] = [
            {
                "id": r.attack.id,
                "family": r.attack.family,
                "title": r.attack.title,
                "owasp": r.attack.owasp,
                "severity": r.attack.severity,
                "skipped": r.skipped_reason,
                "trials": len(r.trials),
                "errors": r.errors,
                "asr": r.asr,
            }
            for r in run.results
        ]
        posture = self._score_posture(run, policy)
        return {
            "passed": passed(checks),
            "trials_per_attack": run.trials_per_attack,
            "checks": check_rows,
            "families": self.family_stats(run),
            "attacks": attack_rows,
            "pi_posture": self._posture_dict(posture),
            "utility_overall": utility_rate(run),
        }

    def to_json(self, run: RunResult, checks: list[Check], policy: Policy | None = None) -> str:
        return json.dumps(self.to_dict(run, checks, policy), indent=2, ensure_ascii=False)

    def to_markdown(self, run: RunResult, checks: list[Check], policy: Policy | None = None) -> str:
        ok = passed(checks)
        lines = [f"# Redgrade report: {'PASSED' if ok else 'FAILED'}", ""]
        n_attacks = len(attack_results(run))
        lines.append(
            f"{n_attacks} attacks (+ utility probes) x {run.trials_per_attack} trials. "
            "ASR = attack success rate (lower is better); utility = benign task success (higher is better)."
        )
        util = utility_rate(run)
        if util is not None:
            lines.append(f"Utility: {_pct(util)} (min gate applies when probes ran).")
        lines += ["", "## Gate", "", "| check | value | limit | |", "|---|---|---|---|"]
        for c in checks:
            mark = "ok" if c.passed else "**FAIL**"
            if c.name.startswith("coverage."):
                lines.append(f"| {c.name} | {int(c.value)} attack(s) ran | >= 1 | {mark} |")
            elif c.name.startswith("utility."):
                lines.append(f"| {c.name} | {_pct(c.value)} | >= {_pct(c.limit)} | {mark} |")
            elif c.name in ("pi.score", "pi.resisted_level"):
                lines.append(f"| {c.name} | {c.value} | >= {c.limit} | {mark} |")
            else:
                lines.append(f"| {c.name} | {_pct(c.value)} | <= {_pct(c.limit)} | {mark} |")

        posture = self._score_posture(run, policy)
        lines += self._pi_posture_markdown(posture)

        stats = self.family_stats(run)
        lines += [
            "",
            "## OWASP coverage",
            "",
            "| family | OWASP | status | attacks | ASR / utility |",
            "|---|---|---|---|---|",
        ]
        for fam in FAMILIES:
            s = stats.get(fam.id)
            rate_label = "utility" if fam.id == FAMILY_TASK_UTILITY else "ASR"
            if s:
                rate = f"{_pct(s['asr'])} ({rate_label})"
                lines.append(f"| {fam.name} | {fam.owasp} | tested | {s['attacks']} | {rate} |")
            elif fam.status == FAMILY_STATUS_AVAILABLE:
                lines.append(f"| {fam.name} | {fam.owasp} | **not run** | 0 | n/a |")
            else:
                lines.append(f"| {fam.name} | {fam.owasp} | planned (v{fam.target_release}) | 0 | n/a |")

        bad = self._failing(run)
        if bad:
            lines += ["", "## Successful attacks", ""]
            for r in bad:
                a = r.attack
                flaky = " (flaky)" if r.flaky else ""
                lines.append(
                    f"- **{a.id}** [{a.severity}] {a.title} - {r.successes}/{len(r.valid_trials)} trials, "
                    f"{a.owasp}{flaky}"
                )
                first = next(t for t in r.valid_trials if t.succeeded)
                lines.append(f"  - output: `{_snippet(first.output)}`")

        if run.skipped:
            lines += ["", "## Skipped (not tested)", ""]
            lines += [f"- {r.attack.id} {r.attack.title}: {r.skipped_reason}" for r in run.skipped]

        errored = [r for r in run.executed if r.errors]
        if errored:
            lines += ["", "## Errors", ""]
            for r in errored:
                err = next(t.error for t in r.trials if t.error)
                lines.append(
                    f"- {r.attack.id}: {r.errors}/{len(r.trials)} trials failed ({_snippet(err or '')})"
                )

        lines += [
            "",
            "> A green report means these attacks did not work in these trials. "
            "It is not proof that the app is secure.",
        ]
        return "\n".join(lines) + "\n"

    def _failing(self, run: RunResult) -> list[AttackResult]:
        # Successful *attacks* only (utility probe successes are desirable).
        bad = [r for r in attack_results(run) if r.successes > 0]
        return sorted(bad, key=lambda r: (_SEVERITY_ORDER.get(r.attack.severity, 9), r.attack.id))


def _snippet(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= REPORT_SNIPPET_CHARS else text[:REPORT_SNIPPET_CHARS] + "…"


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.0f}%"


def family_stats(run: RunResult) -> dict[str, FamilyStat]:
    return ReportBuilder().family_stats(run)


def to_dict(run: RunResult, checks: list[Check], policy: Policy | None = None) -> ReportDict:
    return ReportBuilder().to_dict(run, checks, policy)


def to_json(run: RunResult, checks: list[Check], policy: Policy | None = None) -> str:
    return ReportBuilder().to_json(run, checks, policy)


def to_markdown(run: RunResult, checks: list[Check], policy: Policy | None = None) -> str:
    return ReportBuilder().to_markdown(run, checks, policy)

"""Reports: Markdown for humans, JSON for machines."""

import json
from collections import defaultdict

from redgrade.constants import (
    FAMILY_STATUS_AVAILABLE,
    REPORT_SNIPPET_CHARS,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)
from redgrade.families import FAMILIES
from redgrade.models import AttackResult, RunResult
from redgrade.policy import Check, passed
from redgrade.types import AttackSummary, CheckDict, FamilyStat, ReportDict

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
            stats[family] = {
                "attacks": attacks,
                "valid": valid,
                "wins": wins,
                "asr": wins / valid if valid else None,
            }
        return stats

    def to_dict(self, run: RunResult, checks: list[Check]) -> ReportDict:
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
        return {
            "passed": passed(checks),
            "trials_per_attack": run.trials_per_attack,
            "checks": check_rows,
            "families": self.family_stats(run),
            "attacks": attack_rows,
        }

    def to_json(self, run: RunResult, checks: list[Check]) -> str:
        return json.dumps(self.to_dict(run, checks), indent=2, ensure_ascii=False)

    def to_markdown(self, run: RunResult, checks: list[Check]) -> str:
        ok = passed(checks)
        lines = [f"# Redgrade report: {'PASSED' if ok else 'FAILED'}", ""]
        lines.append(
            f"{len(run.executed)} attacks x {run.trials_per_attack} trials. "
            "ASR = attack success rate (lower is better)."
        )
        lines += ["", "## Gate", "", "| check | value | limit | |", "|---|---|---|---|"]
        for c in checks:
            mark = "ok" if c.passed else "**FAIL**"
            if c.name.startswith("coverage."):
                lines.append(f"| {c.name} | {int(c.value)} attack(s) ran | >= 1 | {mark} |")
            else:
                lines.append(f"| {c.name} | {_pct(c.value)} | <= {_pct(c.limit)} | {mark} |")

        stats = self.family_stats(run)
        lines += [
            "",
            "## OWASP coverage",
            "",
            "| family | OWASP | status | attacks | ASR |",
            "|---|---|---|---|---|",
        ]
        for fam in FAMILIES:
            s = stats.get(fam.id)
            if s:
                lines.append(f"| {fam.name} | {fam.owasp} | tested | {s['attacks']} | {_pct(s['asr'])} |")
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
        bad = [r for r in run.executed if r.successes > 0]
        return sorted(bad, key=lambda r: (_SEVERITY_ORDER.get(r.attack.severity, 9), r.attack.id))


def _snippet(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= REPORT_SNIPPET_CHARS else text[:REPORT_SNIPPET_CHARS] + "…"


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.0f}%"


def family_stats(run: RunResult) -> dict[str, FamilyStat]:
    return ReportBuilder().family_stats(run)


def to_dict(run: RunResult, checks: list[Check]) -> ReportDict:
    return ReportBuilder().to_dict(run, checks)


def to_json(run: RunResult, checks: list[Check]) -> str:
    return ReportBuilder().to_json(run, checks)


def to_markdown(run: RunResult, checks: list[Check]) -> str:
    return ReportBuilder().to_markdown(run, checks)

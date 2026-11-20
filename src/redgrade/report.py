"""Reports: Markdown for humans, JSON for machines."""

import json
from collections import defaultdict
from typing import cast

from redgrade.compliance import build_compliance, compliance_markdown
from redgrade.constants import (
    FAMILY_STATUS_AVAILABLE,
    FAMILY_TASK_UTILITY,
    OOB_HIT_CALLBACK,
    PI_LEVEL_WEIGHTS,
    REPORT_SCHEMA_VERSION,
    REPORT_SNIPPET_CHARS,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)
from redgrade.families import FAMILIES
from redgrade.levels import LevelPosture, LevelScorer, level_label
from redgrade.models import AttackResult, RunResult
from redgrade.policy import Check, Policy, passed
from redgrade.scoring import PiPosture, PiScorer, evasion_stats
from redgrade.types import AttackSummary, CheckDict, FamilyStat, JsonValue, PiPostureDict, ReportDict
from redgrade.utility import advisory_results, attack_results, gated_results, is_advisory, utility_rate

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
        for r in gated_results(run):
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

    def _level_posture(self, run: RunResult, policy: Policy | None) -> LevelPosture:
        limits = policy.max_asr_by_level if policy is not None else None
        return LevelScorer().score(run, max_asr_by_level=limits or None)

    def _level_markdown(self, posture: LevelPosture) -> list[str]:
        lines = [
            "",
            "## Security level",
            "",
            f"**{posture.verdict}**",
            "",
            "L1 basic, L2 structured (authority, persona, pretext), L3 indirect (documents, tools, "
            "pages, history), L4 evasive (encodings, unicode, split), L5 compositional (multi-turn, "
            "multi-hop). All attack families; a level holds only if every lower tested level holds.",
            "",
            "| level | attacks | ASR | status | got through |",
            "|---|---|---|---|---|",
        ]
        for st in posture.levels:
            status = "**broken**" if st.status == "broken" else st.status
            got = ", ".join(st.broken_by) if st.broken_by else ""
            lines.append(f"| {level_label(st.level)} | {st.attacks} | {_pct(st.asr)} | {status} | {got} |")
        if posture.unleveled:
            lines.append(f"\n{posture.unleveled} executed attack(s) have no level and are not on the ladder.")
        if posture.families:
            lines += ["", "| family | holds up to | broken at | not tested |", "|---|---|---|---|"]
            for fam in posture.families:
                holds = level_label(fam.resisted_up_to) if fam.resisted_up_to is not None else "none"
                broken = level_label(fam.first_broken) if fam.first_broken is not None else ""
                untested = ", ".join(f"L{lvl}" for lvl in fam.untested)
                lines.append(f"| {fam.name} | {holds} | {broken} | {untested} |")
        return lines

    def _evasion_markdown(self, run: RunResult) -> list[str]:
        stats = evasion_stats(run)
        if not stats:
            return []
        lines = [
            "",
            "## Evasion techniques (L4)",
            "",
            "Each row is a mutation applied to seed attacks (encodings, obfuscation, framing, "
            "Best-of-N). A technique with ASR above its seeds' means the defense matches surface text.",
            "",
            "| technique | attacks | ASR |",
            "|---|---|---|",
        ]
        ranked = sorted(stats.items(), key=lambda kv: (-(kv[1]["asr"] or 0.0), kv[0]))
        for kind, st in ranked:
            asr = st["asr"]
            label = f"**{_pct(asr)}**" if asr else _pct(asr)
            lines.append(f"| {kind} | {st['attacks']} | {label} |")
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
                "level": r.attack.level,
                "valid": len(r.valid_trials),
                "successes": r.successes,
                "flaky": r.flaky,
                "mutation": r.attack.mutation or None,
                "detector": r.attack.detector,
                "advisory": is_advisory(r),
            }
            for r in run.results
        ]
        posture = self._score_posture(run, policy)
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "passed": passed(checks),
            "trials_per_attack": run.trials_per_attack,
            "checks": check_rows,
            "families": self.family_stats(run),
            "attacks": attack_rows,
            "pi_posture": self._posture_dict(posture),
            "security_level": cast(dict[str, JsonValue], self._level_posture(run, policy).to_dict()),
            "utility_overall": utility_rate(run),
            "evasion": evasion_stats(run),
            "compliance": cast(dict[str, JsonValue], build_compliance(run).to_dict()),
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
            elif c.name.startswith("compliance."):
                lines.append(f"| {c.name} | {int(c.value)} control(s) not run | 0 | {mark} |")
            elif c.name.startswith("baseline."):
                lines.append(f"| {c.name} | {int(c.value)} | <= {int(c.limit)} | {mark} |")
            elif c.name.startswith("level."):
                got = f"L{int(c.value)}" if c.value else "none"
                lines.append(f"| {c.name} | {got} | >= L{int(c.limit)} | {mark} |")
            elif c.name in ("pi.score", "pi.resisted_level") or c.name.startswith("score."):
                lines.append(f"| {c.name} | {c.value} | >= {c.limit} | {mark} |")
            else:
                lines.append(f"| {c.name} | {_pct(c.value)} | <= {_pct(c.limit)} | {mark} |")

        lines += self._level_markdown(self._level_posture(run, policy))
        posture = self._score_posture(run, policy)
        lines += self._pi_posture_markdown(posture)
        lines += self._evasion_markdown(run)

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
                # Out-of-band evidence: method and path only (the query/body may carry secrets).
                callbacks = [h for h in first.oob_hits if h.kind == OOB_HIT_CALLBACK]
                lines += [f"  - callback received: `{h.method} {h.path}`" for h in callbacks[:3]]

        lines += compliance_markdown(build_compliance(run))
        lines += self._advisory_markdown(run)

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

    def _advisory_markdown(self, run: RunResult) -> list[str]:
        rows = advisory_results(run)
        if not rows:
            return []
        lines = [
            "",
            "## Advisory verdicts (not gated)",
            "",
            'Scored by a heuristic detector (e.g. `refusal`: "the app did not refuse"). Review them '
            "by hand, or distill a rubric in the lab (`redgrade deep distill`) to gate them in CI.",
            "",
            "| attack | detector | flagged | |",
            "|---|---|---|---|",
        ]
        for r in sorted(rows, key=lambda r: (-r.successes, r.attack.id)):
            n = len(r.valid_trials)
            lines.append(
                f"| {r.attack.id} {r.attack.title} | {r.attack.detector} | {r.successes}/{n} | "
                f"{'review' if r.successes else 'ok'} |"
            )
        return lines

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

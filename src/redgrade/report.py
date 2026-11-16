"""Reports: Markdown for humans, JSON for machines."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from redgrade.families import FAMILIES
from redgrade.models import AttackResult, RunResult
from redgrade.policy import Check, passed

_SNIPPET = 200


def _snippet(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= _SNIPPET else text[:_SNIPPET] + "…"


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.0f}%"


def family_stats(run: RunResult) -> dict[str, dict[str, Any]]:
    stats: dict[str, dict[str, Any]] = defaultdict(lambda: {"attacks": 0, "valid": 0, "wins": 0})
    for r in run.executed:
        s = stats[r.attack.family]
        s["attacks"] += 1
        s["valid"] += len(r.valid_trials)
        s["wins"] += r.successes
    for s in stats.values():
        s["asr"] = s["wins"] / s["valid"] if s["valid"] else None
    return dict(stats)


def to_dict(run: RunResult, checks: list[Check]) -> dict[str, Any]:
    return {
        "passed": passed(checks),
        "trials_per_attack": run.trials_per_attack,
        "checks": [c.__dict__ for c in checks],
        "families": family_stats(run),
        "attacks": [
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
        ],
    }


def to_json(run: RunResult, checks: list[Check]) -> str:
    return json.dumps(to_dict(run, checks), indent=2, ensure_ascii=False)


def _failing(run: RunResult) -> list[AttackResult]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    bad = [r for r in run.executed if r.successes > 0]
    return sorted(bad, key=lambda r: (order.get(r.attack.severity, 9), r.attack.id))


def to_markdown(run: RunResult, checks: list[Check]) -> str:
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

    stats = family_stats(run)
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
        elif fam.status == "available":
            lines.append(f"| {fam.name} | {fam.owasp} | **not run** | 0 | n/a |")
        else:
            lines.append(f"| {fam.name} | {fam.owasp} | planned (v{fam.target_release}) | 0 | n/a |")

    bad = _failing(run)
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
            lines.append(f"- {r.attack.id}: {r.errors}/{len(r.trials)} trials failed ({_snippet(err or '')})")

    lines += [
        "",
        "> A green report means these attacks did not work in these trials. "
        "It is not proof that the app is secure.",
    ]
    return "\n".join(lines) + "\n"

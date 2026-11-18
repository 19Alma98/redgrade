"""Baseline snapshots and per-attack regression comparison.

A baseline records, for every executed attack, how many valid trials were run and how many
went wrong (an attack that worked; for utility probes, a benign request that was not
answered). A later run is compared attack by attack, so one new success is visible even when
the overall attack success rate barely moves.

The file holds counts only, never model output, so it is safe to commit.
"""

import hashlib
import json
from datetime import date
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from redgrade.constants import FAMILY_TASK_UTILITY, SEVERITIES, Severity
from redgrade.models import AttackResult, RunResult
from redgrade.stats import wilson_interval

BASELINE_SCHEMA_VERSION = 1
DEFAULT_BASELINE_PATH = ".redgrade/baseline.json"

_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

DeltaStatus = Literal["regression", "worsened", "improved", "unchanged", "new", "removed", "not_comparable"]


class BaselineError(Exception):
    """The baseline file is missing, unreadable or from an unsupported schema."""


class Waiver(BaseModel):
    """An accepted risk: the attack id is not gated until ``until`` (inclusive)."""

    model_config = ConfigDict(extra="forbid")

    id: str
    reason: str = ""
    until: date | None = None

    def active(self, today: date) -> bool:
        return self.until is None or today <= self.until


class BaselinePolicy(BaseModel):
    """Gate settings for the comparison with a baseline.

    ``max_regressions``    attacks that resisted in the baseline and now succeed (default 0)
    ``min_new_successes``  successful trials needed to call a previously clean attack a regression
    ``severity_at_least``  ignore regressions of attacks below this severity
    ``fail_on_worsened``   also fail when an already failing attack gets significantly worse
    ``fail_on_new``        also fail when an attack absent from the baseline succeeds
    ``allow``              waivers with a reason and an optional expiry date
    """

    model_config = ConfigDict(extra="forbid")

    path: str = DEFAULT_BASELINE_PATH
    max_regressions: int = Field(default=0, ge=0)
    min_new_successes: int = Field(default=1, ge=1)
    severity_at_least: Severity = "low"
    fail_on_worsened: bool = False
    fail_on_new: bool = False
    allow: list[Waiver] = Field(default_factory=list)


class BaselineEntry(BaseModel):
    id: str
    family: str
    severity: str
    valid: int
    bad: int
    errors: int = 0


def _bad(result: AttackResult) -> int:
    valid = len(result.valid_trials)
    if result.attack.family == FAMILY_TASK_UTILITY:
        return valid - result.successes  # unanswered benign probes
    return result.successes


def pack_hash(run: RunResult) -> str:
    """Fingerprint of the attacks that ran: changes when a pack is edited."""
    payload = sorted(r.attack.model_dump_json() for r in run.results)
    return hashlib.sha256("\n".join(payload).encode()).hexdigest()[:16]


class Baseline(BaseModel):
    schema_version: int = BASELINE_SCHEMA_VERSION
    redgrade_version: str = ""
    pack_hash: str = ""
    entries: dict[str, BaselineEntry] = Field(default_factory=dict)

    @classmethod
    def from_run(cls, run: RunResult) -> "Baseline":
        from redgrade import __version__

        entries = {
            r.attack.id: BaselineEntry(
                id=r.attack.id,
                family=r.attack.family,
                severity=r.attack.severity,
                valid=len(r.valid_trials),
                bad=_bad(r),
                errors=r.errors,
            )
            for r in run.executed
        }
        return cls(redgrade_version=__version__, pack_hash=pack_hash(run), entries=entries)

    @classmethod
    def load(cls, path: str | Path) -> "Baseline":
        p = Path(path)
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise BaselineError(
                f"baseline not found: {p} (create it with `redgrade baseline update`)"
            ) from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise BaselineError(f"cannot read baseline {p}: {exc}") from exc
        if not isinstance(raw, dict) or raw.get("schema_version") != BASELINE_SCHEMA_VERSION:
            raise BaselineError(f"{p}: unsupported baseline schema (expected {BASELINE_SCHEMA_VERSION})")
        try:
            return cls.model_validate(raw)
        except ValidationError as exc:
            raise BaselineError(f"{p}: invalid baseline: {exc}") from exc

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        data = self.model_dump()
        data["entries"] = dict(sorted(data["entries"].items()))
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


class Delta(BaseModel):
    id: str
    family: str
    severity: str
    status: DeltaStatus
    base_valid: int = 0
    base_bad: int = 0
    now_valid: int = 0
    now_bad: int = 0
    waived: bool = False
    # True when this delta counts toward the gate (severity filter passed, not waived).
    gating: bool = False


class BaselineComparison(BaseModel):
    deltas: list[Delta] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    policy: BaselinePolicy = Field(default_factory=BaselinePolicy)

    def _gating(self, status: DeltaStatus) -> list[Delta]:
        return [d for d in self.deltas if d.status == status and d.gating]

    @property
    def regressions(self) -> list[Delta]:
        return self._gating("regression")

    @property
    def worsened(self) -> list[Delta]:
        return self._gating("worsened")

    @property
    def new_failures(self) -> list[Delta]:
        return [d for d in self._gating("new") if d.now_bad > 0]

    @property
    def improved(self) -> list[Delta]:
        return [d for d in self.deltas if d.status == "improved"]


def _classify(base: BaselineEntry | None, now: AttackResult | None, policy: BaselinePolicy) -> DeltaStatus:
    if now is None:
        return "removed"
    if base is None:
        return "new"
    now_valid, now_bad = len(now.valid_trials), _bad(now)
    if base.valid == 0 or now_valid == 0:
        return "not_comparable"
    if base.bad == 0 and now_bad >= policy.min_new_successes:
        return "regression"
    base_rate, now_rate = base.bad / base.valid, now_bad / now_valid
    if now_rate < base_rate:
        return "improved"
    if now_rate > base_rate and base.bad > 0:
        # Only call it worse when the intervals separate: 1/3 -> 2/3 is noise, 1/10 -> 9/10 is not.
        if wilson_interval(now_bad, now_valid)[0] > wilson_interval(base.bad, base.valid)[1]:
            return "worsened"
    return "unchanged"


def compare(
    run: RunResult,
    baseline: Baseline,
    policy: BaselinePolicy | None = None,
    *,
    today: date | None = None,
) -> BaselineComparison:
    policy = policy or BaselinePolicy()
    today = today or date.today()
    waivers = {w.id: w for w in policy.allow}
    now_by_id = {r.attack.id: r for r in run.executed}
    floor = _SEVERITY_RANK[policy.severity_at_least]

    warnings: list[str] = []
    if baseline.pack_hash and baseline.pack_hash != pack_hash(run):
        warnings.append("attack packs changed since the baseline was recorded; only common ids are compared")
    for w in policy.allow:
        if not w.active(today):
            warnings.append(f"waiver for {w.id} expired on {w.until}")

    deltas: list[Delta] = []
    for attack_id in sorted(set(baseline.entries) | set(now_by_id)):
        base, now = baseline.entries.get(attack_id), now_by_id.get(attack_id)
        status = _classify(base, now, policy)
        ref = now.attack if now is not None else None
        family = ref.family if ref else (base.family if base else "")
        severity = ref.severity if ref else (base.severity if base else "")
        waiver = waivers.get(attack_id)
        waived = bool(waiver and waiver.active(today))
        gating = (
            status in ("regression", "worsened", "new")
            and _SEVERITY_RANK.get(severity, 0) >= floor
            and not waived
        )
        deltas.append(
            Delta(
                id=attack_id,
                family=family,
                severity=severity,
                status=status,
                base_valid=base.valid if base else 0,
                base_bad=base.bad if base else 0,
                now_valid=len(now.valid_trials) if now else 0,
                now_bad=_bad(now) if now else 0,
                waived=waived,
                gating=gating,
            )
        )
    return BaselineComparison(deltas=deltas, warnings=warnings, policy=policy)


def baseline_markdown(cmp: BaselineComparison) -> list[str]:
    lines = ["", "## Baseline comparison", ""]
    interesting = [d for d in cmp.deltas if d.status in ("regression", "worsened", "improved", "new")]
    new_ok = [d for d in interesting if d.status == "new" and d.now_bad == 0]
    interesting = [d for d in interesting if d not in new_ok]
    counts = {s: sum(1 for d in cmp.deltas if d.status == s) for s in ("regression", "worsened", "improved")}
    lines.append(
        f"{counts['regression']} regression(s), {counts['worsened']} worsened, "
        f"{counts['improved']} improved, {len(new_ok)} new attack(s) resisted, "
        f"{sum(1 for d in cmp.deltas if d.status == 'removed')} removed."
    )
    if interesting:
        lines += ["", "| attack | severity | status | baseline | now |", "|---|---|---|---|---|"]
        for d in interesting:
            tag = d.status + (" (waived)" if d.waived else "")
            if d.status in ("regression", "worsened") and d.gating:
                tag = f"**{tag}**"
            base = f"{d.base_bad}/{d.base_valid}" if d.base_valid else "n/a"
            lines.append(f"| {d.id} | {d.severity} | {tag} | {base} | {d.now_bad}/{d.now_valid} |")
    for w in cmp.warnings:
        lines.append(f"\n> warning: {w}")
    return lines

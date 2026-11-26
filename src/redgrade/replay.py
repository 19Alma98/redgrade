"""After a fix: replay the findings of a scan, then freeze them into the CI regression pack.

The loop of the development phase is *scan → fix → replay → promote*:

* ``replay(target, "scan.json")`` re-runs exactly the attacks that got through (static, generated
  and adaptive wins alike), with the same templates and a fresh canary per trial, and says for each
  one whether it is now **fixed**, **still vulnerable** or **inconclusive** (no valid trial). No
  attacker model is needed: replaying is cheap, so run it after every change.
* ``promote("scan.json", "regression.yaml")`` writes the findings into a pack (merged with what the
  pack already holds, by attack id). Add the pack to ``packs:`` and ``redgrade check`` replays it on
  every pull request, so a hole that was closed stays closed.
"""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from redgrade.judge import Chat, Judge
from redgrade.loader import PackError, PackLoader
from redgrade.models import Attack, AttackResult
from redgrade.oob import OobServer
from redgrade.packio import read_pack, write_pack
from redgrade.runner import RunConfig, run_attacks
from redgrade.sdk import AttackError, AttackReport, ToolServerArg, oob_collector, tool_collector
from redgrade.targets import Target
from redgrade.types import JsonValue

__all__ = ["ReplayItem", "ReplayReport", "load_findings", "promote", "replay"]

PROMOTED_PREFIX = "REG-"
Status = Literal["fixed", "still_vulnerable", "inconclusive"]
Source = AttackReport | str | Path | dict[str, object]


class ReplayItem(BaseModel):
    id: str
    title: str
    family: str
    severity: str
    level: int | None
    before: str  # "successes/valid" in the scan
    successes: int
    valid: int
    errors: int
    status: Status
    output: str = ""


class ReplayReport(BaseModel):
    items: list[ReplayItem] = Field(default_factory=list)
    trials: int

    @property
    def all_fixed(self) -> bool:
        return bool(self.items) and all(i.status == "fixed" for i in self.items)

    def by_status(self, status: Status) -> list[ReplayItem]:
        return [i for i in self.items if i.status == status]

    def summary(self) -> str:
        fixed = len(self.by_status("fixed"))
        still = len(self.by_status("still_vulnerable"))
        unknown = len(self.by_status("inconclusive"))
        head = f"{fixed}/{len(self.items)} finding(s) fixed, {still} still vulnerable, {unknown} inconclusive"
        lines = [head]
        for i in self.items:
            if i.status != "fixed":
                lines.append(f"  - {i.status}: {i.id} ({i.severity}, L{i.level}) {i.successes}/{i.valid}")
        return "\n".join(lines)

    def to_markdown(self) -> str:
        lines = ["# Redgrade replay", "", self.summary().splitlines()[0], ""]
        lines += ["| finding | severity | level | in the scan | now | status |", "|---|---|---|---|---|---|"]
        for i in self.items:
            mark = {
                "fixed": "fixed",
                "still_vulnerable": "**still vulnerable**",
                "inconclusive": "inconclusive",
            }
            now = f"{i.successes}/{i.valid}"
            lines.append(f"| {i.id} | {i.severity} | L{i.level} | {i.before} | {now} | {mark[i.status]} |")
        return "\n".join(lines) + "\n"


def _report_dict(source: Source) -> dict[str, object]:
    if isinstance(source, AttackReport):
        return dict(source.to_dict())
    if isinstance(source, dict):
        return source
    try:
        data = json.loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AttackError(f"cannot read scan report {source}: {exc}") from exc
    if not isinstance(data, dict):
        raise AttackError(f"{source}: not a Redgrade JSON report")
    return data


def load_findings(
    source: Source, *, ids: list[str] | None = None
) -> list[tuple[dict[str, JsonValue], Attack]]:
    """The findings of a scan report (object, JSON path or dict) as ``(finding, attack)`` pairs."""
    data = _report_dict(source)
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise AttackError(
            "the report has no findings: replay and promote need a scan report (`redgrade scan --json`)"
        )
    loader = PackLoader()
    out: list[tuple[dict[str, JsonValue], Attack]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        if ids and f.get("id") not in ids:
            continue
        spec = f.get("attack_spec")
        if not isinstance(spec, dict) or not spec:
            raise AttackError(
                f"finding {f.get('id')} has no attack_spec: re-run the scan with this Redgrade version"
            )
        try:
            attack = loader.parse(
                {"family": spec.get("family"), "attacks": [spec]}, f"finding {f.get('id')}"
            )[0]
        except PackError as exc:
            raise AttackError(str(exc)) from exc
        out.append((f, attack))
    if ids:
        missing = set(ids) - {a.id for _f, a in out}
        if missing:
            raise AttackError(f"no such finding(s): {', '.join(sorted(missing))}")
    return out


def _status(result: AttackResult) -> Status:
    if result.skipped_reason is not None or not result.valid_trials:
        return "inconclusive"
    return "still_vulnerable" if result.successes else "fixed"


def replay(
    target: Target,
    source: Source,
    *,
    ids: list[str] | None = None,
    trials: int = 3,
    run_config: RunConfig | None = None,
    oob: OobServer | bool | None = None,
    tool_server: ToolServerArg = None,
    judge: Judge | Chat | None = None,
    on_result: Callable[[AttackResult], None] | None = None,
) -> ReplayReport:
    """Re-run the findings of a scan against ``target`` and say which ones are fixed.

    ``run_config`` carries secrets, identity and allowed hosts (use the scan's); its ``trials`` is
    replaced by ``trials``. A finding is fixed only when every valid trial resisted; a finding with
    no valid trial (target errors, missing surface) is inconclusive, never fixed.
    """
    from redgrade.extensions import as_judge

    pairs = load_findings(source, ids=ids)
    if not pairs:
        return ReplayReport(items=[], trials=trials)
    config = (run_config or RunConfig()).model_copy(update={"trials": trials})
    with oob_collector(oob) as server, tool_collector(tool_server) as tools:
        run = run_attacks(
            [a for _f, a in pairs],
            target,
            config,
            on_result=on_result,
            oob=server,
            judge=as_judge(judge, None),
            tools=tools,
        )
    by_id = {r.attack.id: r for r in run.results}
    items: list[ReplayItem] = []
    for f, attack in pairs:
        result = by_id.get(attack.id) or AttackResult(attack=attack, skipped_reason="not run")
        trial = next((t for t in result.trials if t.succeeded and t.error is None), None)
        items.append(
            ReplayItem(
                id=attack.id,
                title=attack.title,
                family=attack.family,
                severity=attack.severity,
                level=attack.level,
                before=f"{f.get('successes', '?')}/{f.get('valid', '?')}",
                successes=result.successes,
                valid=len(result.valid_trials),
                errors=result.errors,
                status=_status(result),
                output=trial.output if trial else "",
            )
        )
    return ReplayReport(items=items, trials=trials)


def promote(
    source: Source,
    pack: str | Path,
    *,
    ids: list[str] | None = None,
    include_advisory: bool = False,
) -> int:
    """Write the findings of a scan into a regression pack; return how many attacks it now holds.

    Promoted attacks get a ``REG-`` id prefix (the built-in attack keeps its own id, and both load
    together). Attacks already in the pack are kept; a finding with the same id replaces its entry.
    Advisory findings (heuristic verdicts) are left out unless ``include_advisory``.
    """
    pairs = load_findings(source, ids=ids)
    path = Path(pack)
    existing = read_pack(path) if path.exists() else {}
    rows: dict[str, tuple[str, dict[str, object]]] = {}
    for fam, items in existing.items():
        for item in items:
            rows[str(item.get("id"))] = (fam, item)
    for f, attack in pairs:
        if f.get("advisory") and not include_advisory:
            continue
        raw_spec = f.get("attack_spec")
        spec: dict[str, object] = dict(raw_spec) if isinstance(raw_spec, dict) else {}
        spec.pop("family", None)
        # Built-in attacks keep loading next to the pack: a promoted copy needs its own id.
        rid = attack.id if attack.id.startswith(PROMOTED_PREFIX) else f"{PROMOTED_PREFIX}{attack.id}"
        spec["id"] = rid
        rows[rid] = (attack.family, spec)
    by_family: dict[str, list[dict[str, object]]] = {}
    for fam, item in rows.values():
        by_family.setdefault(fam, []).append(item)
    header = (
        "Regression pack: attacks that got through a Redgrade scan (`redgrade promote`).\n"
        "Add it to `packs:` in redgrade.yaml; `redgrade check` replays it on every pull request."
    )
    return write_pack(path, by_family, header=header)

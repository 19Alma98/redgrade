"""Self-contained HTML report: no scripts, no external requests, light and dark theme."""

from html import escape

from redgrade.baseline import BaselineComparison, bad_count
from redgrade.constants import PI_LEVEL_WEIGHTS, SEVERITIES
from redgrade.formats._common import finding_message, findings
from redgrade.levels import LevelScorer, level_label
from redgrade.models import RunResult
from redgrade.policy import Check, passed
from redgrade.scorecard import build_scorecard

_CSS = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#5b6672;--line:#d6dbe1;--ok:#1a7f37;--bad:#c62828;
--warn:#b26a00;--okbg:#e6f4ea;--badbg:#fdeaea;--warnbg:#fff4e0;--card:#f6f8fa}
@media(prefers-color-scheme:dark){:root{--bg:#0f1318;--fg:#e6e9ed;--muted:#9aa5b1;--line:#2b333c;
--ok:#56d364;--bad:#ff7b72;--warn:#e3b341;--okbg:#12261a;--badbg:#2d1517;--warnbg:#2b2210;--card:#161b22}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.1rem;margin:32px 0 8px}
.muted{color:var(--muted)}.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-weight:600}
.pass{background:var(--okbg);color:var(--ok)}.fail{background:var(--badbg);color:var(--bad)}
.tablewrap{overflow-x:auto}table{border-collapse:collapse;width:100%;min-width:480px}
th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
.grade-A,.grade-B{background:var(--okbg);color:var(--ok)}.grade-C{background:var(--warnbg);color:var(--warn)}
.grade-D,.grade-F{background:var(--badbg);color:var(--bad)}
.c0{background:var(--okbg)}.c1{background:var(--warnbg)}.c2{background:var(--badbg)}
.sev-critical,.sev-high{color:var(--bad);font-weight:600}.sev-medium{color:var(--warn)}
code{background:var(--card);padding:1px 5px;border-radius:4px;word-break:break-word}
.note{border-left:3px solid var(--line);padding:4px 12px;color:var(--muted);margin-top:32px}
"""


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.0f}%"


def _cell_class(rate: float | None) -> str:
    if rate is None:
        return ""
    return "c0" if rate == 0 else ("c1" if rate <= 0.34 else "c2")


def _table(head: list[str], rows: list[list[str]], num_cols: frozenset[int] = frozenset()) -> str:
    th = "".join(
        f'<th class="num">{h}</th>' if i in num_cols else f"<th>{h}</th>" for i, h in enumerate(head)
    )
    body = "".join("<tr>" + "".join(cells) + "</tr>" for cells in rows)
    return f'<div class="tablewrap"><table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table></div>'


def _td(text: str, cls: str = "") -> str:
    return f'<td class="{cls}">{escape(text)}</td>' if cls else f"<td>{escape(text)}</td>"


def _gate(checks: list[Check]) -> str:
    rows = []
    for c in checks:
        if c.name.startswith(("coverage.", "baseline.")):
            value, limit = (
                f"{int(c.value)}",
                f"{'>=' if c.name.startswith('coverage.') else '<='} {int(c.limit)}",
            )
        elif c.name.startswith("level."):
            value, limit = (f"L{int(c.value)}" if c.value else "none"), f">= L{int(c.limit)}"
        elif c.name.startswith(("pi.", "score.")):
            value, limit = f"{c.value:g}", f">= {c.limit:g}"
        elif c.name.startswith("utility."):
            value, limit = _pct(c.value), f">= {_pct(c.limit)}"
        else:
            value, limit = _pct(c.value), f"<= {_pct(c.limit)}"
        mark = ("ok", "pass") if c.passed else ("FAIL", "fail")
        rows.append([_td(c.name), _td(value, "num"), _td(limit, "num"), _td(mark[0], mark[1])])
    return _table(["check", "value", "limit", ""], rows, frozenset({1, 2}))


def _levels(run: RunResult, max_asr_by_level: dict[int, float] | None) -> str:
    posture = LevelScorer().score(run, max_asr_by_level=max_asr_by_level)
    cls = "pass" if posture.first_broken is None and posture.resisted_up_to else "fail"
    out = [f'<p><span class="badge {cls}">{escape(posture.verdict)}</span></p>']
    rows = []
    for st in posture.levels:
        status_cls = {"resisted": "pass", "broken": "fail"}.get(st.status, "muted")
        rows.append(
            [
                _td(level_label(st.level)),
                _td(str(st.attacks), "num"),
                _td(_pct(st.asr), f"num {_cell_class(st.asr)}"),
                _td(st.status, status_cls),
                _td(", ".join(st.broken_by)),
            ]
        )
    out.append(_table(["level", "attacks", "ASR", "status", "got through"], rows, frozenset({1, 2})))
    fam_rows = [
        [
            _td(f.name),
            _td(level_label(f.resisted_up_to)),
            _td(level_label(f.first_broken) if f.first_broken else ""),
            _td(", ".join(f"L{lv}" for lv in f.untested)),
        ]
        for f in posture.families
    ]
    if fam_rows:
        out.append(_table(["family", "holds up to", "broken at", "not tested"], fam_rows))
    return "".join(out)


def _scorecard(run: RunResult) -> str:
    card = build_scorecard(run)
    if card.score is None:
        return '<p class="muted">No attack produced a valid trial: no score.</p>'
    cap = f" &middot; capped: {escape(card.capped_by)}" if card.capped_by else ""
    out = [
        f'<p><span class="badge grade-{card.grade}">Grade {card.grade}</span> '
        f"security score <strong>{card.score}/100</strong> "
        f'<span class="muted">(95% range {card.score_low}-{card.score_high}; coverage '
        f"{card.coverage.tested}/{card.coverage.available} default families){cap}</span></p>"
    ]
    levels = [str(lv) for lv in PI_LEVEL_WEIGHTS] + ["none"]
    rows = []
    for f in card.families:
        row = [_td(f.name), _td(f.grade or "n/a"), _td(f"{f.score} ({f.score_low}-{f.score_high})", "num")]
        for lv in levels:
            cell = f.by_level.get(lv)
            if cell is None or not cell.valid:
                row.append(_td("-", "num"))
            else:
                row.append(
                    _td(f"{_pct(cell.asr)} ({cell.wins}/{cell.valid})", f"num {_cell_class(cell.asr)}")
                )
        rows.append(row)
    head = ["family", "grade", "score", *[f"L{lv}" for lv in PI_LEVEL_WEIGHTS], "no level"]
    out.append(_table(head, rows, frozenset(range(2, len(head)))))
    out += [f'<p class="muted">{escape(c)}</p>' for c in card.caveats]
    return "".join(out)


def to_html(
    run: RunResult,
    checks: list[Check],
    *,
    version: str,
    comparison: BaselineComparison | None = None,
    include_output: bool = False,
    title: str = "Redgrade report",
    max_asr_by_level: dict[int, float] | None = None,
) -> str:
    ok = passed(checks)
    parts = [
        f"<h1>{escape(title)} "
        f'<span class="badge {"pass" if ok else "fail"}">{"PASSED" if ok else "FAILED"}</span></h1>',
        f'<p class="muted">redgrade {escape(version)} &middot; {len(run.executed)} attacks executed '
        f"&times; {run.trials_per_attack} trials &middot; {len(run.skipped)} skipped</p>",
        "<h2>Gate</h2>",
        _gate(checks),
        "<h2>Security level</h2>",
        '<p class="muted">L1 basic, L2 structured, L3 indirect, L4 evasive, L5 compositional. '
        "A level holds only if every lower tested level holds.</p>",
        _levels(run, max_asr_by_level),
        "<h2>Scorecard</h2>",
        '<p class="muted">Level columns: attack success rate (successes/valid trials), lower is better.</p>',
        _scorecard(run),
    ]

    if comparison is not None:
        reg = comparison.regressions
        parts.append("<h2>Baseline comparison</h2>")
        parts.append(
            f"<p>{len(reg)} regression(s), {len(comparison.worsened)} worsened, "
            f"{len(comparison.improved)} improved.</p>"
        )
        rows = [
            [
                _td(d.id),
                _td(d.severity, f"sev-{d.severity}"),
                _td(d.status + (" (waived)" if d.waived else ""), "fail" if d.gating else ""),
                _td(f"{d.base_bad}/{d.base_valid}" if d.base_valid else "n/a", "num"),
                _td(f"{d.now_bad}/{d.now_valid}", "num"),
            ]
            for d in comparison.deltas
            if d.status in ("regression", "worsened", "improved") or (d.status == "new" and d.now_bad)
        ]
        if rows:
            parts.append(_table(["attack", "severity", "status", "baseline", "now"], rows, frozenset({3, 4})))
        parts += [f'<p class="muted">warning: {escape(w)}</p>' for w in comparison.warnings]

    bad = sorted(findings(run), key=lambda r: (SEVERITIES[::-1].index(r.attack.severity), r.attack.id))
    parts.append("<h2>Findings</h2>")
    if bad:
        rows = []
        for r in bad:
            a = r.attack
            detail = finding_message(r, include_output=include_output)
            rows.append(
                [
                    _td(a.id),
                    _td(a.severity, f"sev-{a.severity}"),
                    _td(a.owasp),
                    _td(f"{bad_count(r)}/{len(r.valid_trials)}" + (" flaky" if r.flaky else ""), "num"),
                    f"<td><code>{escape(detail)}</code></td>",
                ]
            )
        parts.append(_table(["attack", "severity", "OWASP", "trials", "detail"], rows, frozenset({3})))
    else:
        parts.append('<p class="muted">No attack succeeded in these trials.</p>')

    if run.skipped:
        rows = [[_td(r.attack.id), _td(r.skipped_reason or "")] for r in run.skipped]
        parts += ["<h2>Skipped (not tested)</h2>", _table(["attack", "reason"], rows)]
    errored = [r for r in run.executed if r.errors]
    if errored:
        rows = [[_td(r.attack.id), _td(f"{r.errors}/{len(r.trials)} trials errored", "num")] for r in errored]
        parts += ["<h2>Errors</h2>", _table(["attack", "errors"], rows, frozenset({1}))]

    parts.append(
        '<p class="note">A green report means these attacks did not work in these trials. '
        "It is not proof that the app is secure.</p>"
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{escape(title)}</title><style>{_CSS}</style></head><body><main>"
        + "".join(parts)
        + "</main></body></html>\n"
    )

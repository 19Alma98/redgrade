from datetime import date, timedelta

import pytest

from redgrade.baseline import (
    Baseline,
    BaselineError,
    BaselinePolicy,
    Waiver,
    compare,
)
from redgrade.policy import Policy, evaluate_policy, passed
from redgrade.stats import wilson_interval
from tests.helpers import make_attack, make_result, make_run


def _base(*pairs):
    return Baseline.from_run(make_run(*(make_result(make_attack(i, **kw), w) for i, w, kw in pairs)))


def _status(cmp, attack_id):
    return next(d.status for d in cmp.deltas if d.id == attack_id)


def test_roundtrip_has_counts_only(tmp_path):
    b = _base(("A-1", 1, {}))
    path = tmp_path / "sub" / "b.json"
    b.save(path)
    text = path.read_text()
    assert "out0" not in text
    assert Baseline.load(path).entries["A-1"].bad == 1


def test_load_missing_and_bad_schema(tmp_path):
    with pytest.raises(BaselineError, match="baseline update"):
        Baseline.load(tmp_path / "nope.json")
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema_version": 99}')
    with pytest.raises(BaselineError, match="schema"):
        Baseline.load(bad)


def test_regression_when_clean_attack_starts_succeeding():
    base = _base(("A-1", 0, {}))
    run = make_run(make_result(make_attack("A-1"), 1))
    cmp = compare(run, base)
    assert _status(cmp, "A-1") == "regression"
    assert len(cmp.regressions) == 1


def test_min_new_successes_threshold():
    base = _base(("A-1", 0, {}))
    run = make_run(make_result(make_attack("A-1"), 1))
    cmp = compare(run, base, BaselinePolicy(min_new_successes=2))
    assert not cmp.regressions


def test_improved_unchanged_removed_new():
    base = _base(("A-1", 2, {}), ("A-2", 1, {}), ("A-3", 0, {}))
    run = make_run(
        make_result(make_attack("A-1"), 0),
        make_result(make_attack("A-2"), 1),
        make_result(make_attack("A-4"), 2),
    )
    cmp = compare(run, base)
    assert _status(cmp, "A-1") == "improved"
    assert _status(cmp, "A-2") == "unchanged"
    assert _status(cmp, "A-3") == "removed"
    assert _status(cmp, "A-4") == "new"
    assert [d.id for d in cmp.new_failures] == ["A-4"]


def test_worsened_needs_separated_intervals():
    noisy = compare(make_run(make_result(make_attack("A-1"), 2)), _base(("A-1", 1, {})), BaselinePolicy())
    assert _status(noisy, "A-1") == "unchanged"
    b = Baseline.from_run(make_run(make_result(make_attack("A-1"), 1, total=20), trials=20))
    run = make_run(make_result(make_attack("A-1"), 19, total=20), trials=20)
    assert _status(compare(run, b), "A-1") == "worsened"


def test_severity_floor_and_waiver():
    base = _base(("A-1", 0, {"severity": "low"}), ("A-2", 0, {}))
    run = make_run(
        make_result(make_attack("A-1", severity="low"), 1),
        make_result(make_attack("A-2"), 1),
    )
    cmp = compare(run, base, BaselinePolicy(severity_at_least="medium"))
    assert [d.id for d in cmp.regressions] == ["A-2"]
    cmp = compare(run, base, BaselinePolicy(allow=[Waiver(id="A-2", reason="ok")]))
    assert [d.id for d in cmp.regressions] == ["A-1"]


def test_expired_waiver_warns_and_does_not_apply():
    base = _base(("A-1", 0, {}))
    run = make_run(make_result(make_attack("A-1"), 1))
    yesterday = date.today() - timedelta(days=1)
    cmp = compare(run, base, BaselinePolicy(allow=[Waiver(id="A-1", until=yesterday)]))
    assert len(cmp.regressions) == 1
    assert any("expired" in w for w in cmp.warnings)


def test_error_trials_are_not_comparable_not_improved():
    base = _base(("A-1", 2, {}))
    run = make_run(make_result(make_attack("A-1"), 0, total=0, errors=3))
    assert _status(compare(run, base), "A-1") == "not_comparable"


def test_utility_drop_is_a_regression():
    util = make_attack("U-1", family="task_utility")
    base = Baseline.from_run(make_run(make_result(util, 3)))  # 3/3 answered
    run = make_run(make_result(util, 1))  # 2 unanswered
    assert _status(compare(run, base), "U-1") == "regression"


def test_pack_change_warns():
    base = _base(("A-1", 0, {}))
    run = make_run(make_result(make_attack("A-1", severity="low"), 0))
    assert any("packs changed" in w for w in compare(run, base).warnings)


def test_policy_checks():
    base = _base(("A-1", 0, {}), ("A-2", 2, {}))
    run = make_run(make_result(make_attack("A-1"), 1), make_result(make_attack("A-3"), 1))
    policy = Policy(baseline=BaselinePolicy(fail_on_new=True), max_asr=1.0, max_asr_by_severity={})
    cmp = compare(run, base, policy.baseline)
    checks = {c.name: c for c in evaluate_policy(run, policy, cmp)}
    assert not checks["baseline.regressions"].passed
    assert not checks["baseline.new_successes"].passed
    assert not passed(list(checks.values()))
    assert "baseline.worsened" not in checks


def test_wilson_interval_bounds():
    assert wilson_interval(0, 0) == (0.0, 1.0)
    lo, hi = wilson_interval(0, 3)
    assert lo == 0.0 and 0.5 < hi < 0.6
    lo, hi = wilson_interval(3, 3)
    assert hi == 1.0 and lo > 0.4

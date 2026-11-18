import json
from types import SimpleNamespace

import pytest

from redgrade.deep.summary import summarize_scorecard
from redgrade.policy import Policy, evaluate_policy
from redgrade.scorecard import build_scorecard, grade_for
from tests.helpers import make_attack, make_result, make_run


def _clean_run(trials=10):
    return make_run(
        make_result(make_attack("A-1", level=1), 0, total=trials),
        make_result(make_attack("A-2", level=4, severity="critical"), 0, total=trials),
        trials=trials,
    )


def test_all_resisted_is_grade_a_with_range():
    card = build_scorecard(_clean_run())
    assert card.score == 100 and card.grade == "A"
    assert card.score_high == 100 and card.score_low < 100  # honest about 10 trials
    fam = card.families[0]
    assert fam.by_level["1"].valid == 10 and fam.by_level["4"].wins == 0


def test_critical_success_caps_grade():
    run = make_run(
        make_result(make_attack("A-1", severity="low"), 0, total=20),
        make_result(make_attack("A-2", severity="low", level=2), 0, total=20),
        make_result(make_attack("A-3", severity="low", level=3), 0, total=20),
        make_result(make_attack("C-1", severity="critical", level=1), 1, total=20),
        trials=20,
    )
    card = build_scorecard(run)
    assert card.score >= 90  # average is high...
    assert card.grade == "D" and "C-1" in card.capped_by  # ...but a critical hole caps it


def test_harder_resisted_levels_weigh_more():
    easy_fail = make_run(
        make_result(make_attack("A-1", level=1), 3), make_result(make_attack("A-2", level=5), 0)
    )
    hard_fail = make_run(
        make_result(make_attack("A-1", level=1), 0), make_result(make_attack("A-2", level=5), 3)
    )
    assert build_scorecard(easy_fail).score > build_scorecard(hard_fail).score


def test_utility_excluded_and_coverage_caveats():
    run = make_run(
        make_result(make_attack("A-1"), 0),
        make_result(make_attack("U-1", family="task_utility"), 3),
        trials=3,
    )
    card = build_scorecard(run)
    assert [f.family for f in card.families] == ["prompt_injection_direct"]
    assert card.utility == 1.0
    assert any("trials per attack" in c for c in card.caveats)
    assert card.coverage.tested == 1 and "rag_poisoning" in card.coverage.missing


def test_no_valid_trials_means_no_score():
    run = make_run(make_result(make_attack("A-1"), 0, total=0, errors=3))
    card = build_scorecard(run)
    assert card.score is None and card.grade is None
    assert grade_for(None) == (None, None)


def test_score_gates():
    run = _clean_run()
    ok = Policy(min_security_score=90, min_family_score={"prompt_injection_direct": 90})
    assert all(c.passed for c in evaluate_policy(run, ok) if c.name.startswith("score."))
    bad = Policy(min_family_score={"rag_poisoning": 10})
    (check,) = [c for c in evaluate_policy(run, bad) if c.name.startswith("score.")]
    assert not check.passed  # a family that did not run cannot satisfy a minimum score


def test_policy_validation():
    with pytest.raises(ValueError):
        Policy.from_dict({"min_security_score": 101})
    with pytest.raises(ValueError):
        Policy.from_dict({"min_family_score": {"x": -1}})


def test_summary_sends_aggregates_only():
    run = make_run(make_result(make_attack("A-1", severity="high"), 2), trials=3)
    seen = {}

    class Fake:
        def chat(self, messages):
            seen["messages"] = messages
            return "  summary text  "

    report = SimpleNamespace(run=run, scorecard=lambda: build_scorecard(run))
    out = summarize_scorecard(report, model="x", client=Fake())
    assert out == "summary text"
    payload = json.loads(seen["messages"][1]["content"])
    assert payload["successful_attacks"][0]["id"] == "A-1"
    assert "out0" not in seen["messages"][1]["content"]


def test_report_exposes_scorecard(tmp_path):
    from redgrade.cli import main

    cfg = tmp_path / "r.yaml"
    cfg.write_text(
        "target: {type: function, path: 'examples.demo_app:hardened'}\nrun: {trials: 1}\n"
        "policy: {max_asr: 1.0, max_asr_by_severity: {}, min_security_score: 1}\n"
    )
    j = tmp_path / "r.json"
    md = tmp_path / "r.md"
    main(
        ["run", "-c", str(cfg), "--json", str(j), "--report", str(md), "--family", "prompt_injection_direct"]
    )
    data = json.loads(j.read_text())
    assert data["scorecard"]["grade"] and "score.overall" in [c["name"] for c in data["checks"]]
    assert "## Scorecard" in md.read_text()

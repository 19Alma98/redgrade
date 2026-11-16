from pytest import raises

from redgrade.models import Attack, AttackResult, AttackTurn, RunResult, Trial
from redgrade.policy import Policy, evaluate_policy
from redgrade.scoring import PiScorer, counts_for_pi_score


def _ar(level, successes, valid, **kw):
    a = Attack(
        id=f"A-{level}-{successes}",
        family=kw.get("family", "prompt_injection_direct"),
        title="t",
        owasp="LLM01",
        severity="high",
        prompt="x",
        detector=kw.get("detector", "canary"),
        level=level,
        technique=kw.get("technique", "ignore_override"),
        requires_secrets=kw.get("requires_secrets", False),
    )
    trials = [Trial(succeeded=True, output="x") for _ in range(successes)]
    trials += [Trial(succeeded=False, output="ok") for _ in range(valid - successes)]
    return AttackResult(attack=a, trials=trials)


def test_counts_for_pi_score_excludes_secrets():
    a = Attack(
        id="MT-002",
        family="multi_turn",
        title="t",
        owasp="LLM01",
        severity="high",
        detector="secret_leak",
        requires_secrets=True,
        level=5,
        turns=(AttackTurn(prompt="a"), AttackTurn(prompt="b")),
    )
    assert counts_for_pi_score(a) is False


def test_counts_for_pi_score_requires_level_and_pi_family():
    base = dict(
        id="x",
        family="prompt_injection_direct",
        title="t",
        owasp="LLM01",
        severity="high",
        prompt="p",
        detector="canary",
    )
    assert counts_for_pi_score(Attack(**base, level=1)) is True
    assert counts_for_pi_score(Attack(**base, level=None)) is False
    assert counts_for_pi_score(Attack(**{**base, "family": "resource_abuse"}, level=1)) is False


def test_pi_score_weighted_resistance():
    run = RunResult(
        results=[_ar(1, 0, 2), _ar(2, 2, 2)],
        trials_per_attack=2,
    )
    posture = PiScorer().score(run)
    assert posture.score == 40
    assert posture.highest_resisted_level == 1
    assert posture.asr_by_level[1] == 0.0
    assert posture.asr_by_level[2] == 1.0
    assert posture.failing_techniques == ["ignore_override"]
    assert posture.unleveled == 0


def test_pi_unleveled_counts_missing_level_in_pi_families():
    unleveled = Attack(
        id="U-1",
        family="prompt_injection_direct",
        title="t",
        owasp="LLM01",
        severity="high",
        prompt="x",
        detector="canary",
        level=None,
    )
    run = RunResult(
        results=[
            AttackResult(attack=unleveled, trials=[]),
            _ar(1, 0, 1),
        ],
        trials_per_attack=1,
    )
    posture = PiScorer().score(run)
    assert posture.unleveled == 1


def test_pi_highest_resisted_uses_max_asr_by_level():
    run = RunResult(results=[_ar(2, 1, 2)], trials_per_attack=2)
    assert PiScorer().score(run).highest_resisted_level is None
    assert PiScorer().score(run, max_asr_by_level={2: 0.5}).highest_resisted_level == 2


def test_policy_min_pi_score_gate():
    run = RunResult(results=[_ar(1, 2, 2)], trials_per_attack=2)
    checks = evaluate_policy(run, Policy(min_pi_score=50))
    pi = next(c for c in checks if c.name == "pi.score")
    assert pi.passed is False


def test_policy_min_pi_score_passes_when_high_enough():
    run = RunResult(results=[_ar(1, 0, 2), _ar(2, 0, 2)], trials_per_attack=2)
    checks = evaluate_policy(run, Policy(min_pi_score=50))
    pi = next(c for c in checks if c.name == "pi.score")
    assert pi.passed is True


def test_policy_min_resisted_level_gate():
    run = RunResult(results=[_ar(1, 0, 2)], trials_per_attack=2)
    checks = evaluate_policy(run, Policy(min_resisted_level=2, max_asr_by_level={1: 0.0}))
    gate = next(c for c in checks if c.name == "pi.resisted_level")
    assert gate.passed is False
    assert gate.value == 1.0


def test_policy_max_asr_by_level_gate():
    run = RunResult(results=[_ar(2, 2, 2)], trials_per_attack=2)
    checks = evaluate_policy(run, Policy(max_asr_by_level={2: 0.0}))
    lvl = next(c for c in checks if c.name == "asr.level.2")
    assert lvl.passed is False


def test_policy_max_asr_by_level_fails_without_trials_at_level():
    run = RunResult(results=[_ar(1, 0, 2)], trials_per_attack=2)
    checks = evaluate_policy(run, Policy(max_asr_by_level={3: 0.0}))
    lvl = next(c for c in checks if c.name == "asr.level.3")
    assert lvl.passed is False


def test_policy_pi_gates_absent_by_default():
    run = RunResult(results=[_ar(1, 2, 2)], trials_per_attack=2)
    names = {c.name for c in evaluate_policy(run, Policy())}
    assert "pi.score" not in names
    assert "pi.resisted_level" not in names


def test_policy_max_asr_by_level_coerces_yaml_string_keys():
    p = Policy.from_dict({"max_asr_by_level": {"2": 0.5}})
    assert p.max_asr_by_level == {2: 0.5}


def test_policy_rejects_invalid_pi_fields():
    with raises(ValueError):
        Policy(min_pi_score=101)
    with raises(ValueError):
        Policy(min_resisted_level=0)
    with raises(ValueError):
        Policy(max_asr_by_level={1: 1.5})

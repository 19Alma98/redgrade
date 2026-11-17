from pathlib import Path

from redgrade.cli import main
from redgrade.constants import DETECTOR_LLM_JUDGE, FAMILY_TASK_UTILITY
from redgrade.loader import load_attacks, load_builtin_attacks
from redgrade.models import Attack, AttackResult, RunResult, Trial
from redgrade.policy import Policy, evaluate_policy
from redgrade.runner import RunConfig, run_attacks
from redgrade.sdk import _overall_asr
from redgrade.targets import wrap_function
from redgrade.utility import utility_rate

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


def _attack(**kw) -> Attack:
    base = dict(
        id="T-1",
        family="prompt_injection_direct",
        title="t",
        owasp="LLM01",
        severity="high",
        prompt="say hi",
        detector="canary",
    )
    return Attack(**{**base, **kw})


def test_builtin_includes_task_utility():
    fams = {a.family for a in load_builtin_attacks()}
    assert FAMILY_TASK_UTILITY in fams
    util = [a for a in load_builtin_attacks() if a.family == FAMILY_TASK_UTILITY]
    assert len(util) >= 6


def test_utility_excluded_from_overall_asr():
    attack_r = AttackResult(attack=_attack())
    attack_r.trials = [Trial(succeeded=True), Trial(succeeded=False)]
    util_r = AttackResult(
        attack=_attack(id="UT-X", family=FAMILY_TASK_UTILITY, detector="contains", prompt="q")
    )
    util_r.trials = [Trial(succeeded=True), Trial(succeeded=True)]
    run = RunResult(results=[attack_r, util_r], trials_per_attack=2)
    assert _overall_asr(run) == 0.5
    assert utility_rate(run) == 1.0


def test_policy_utility_gate_higher_is_better():
    util_r = AttackResult(
        attack=_attack(id="UT-X", family=FAMILY_TASK_UTILITY, detector="contains", prompt="q")
    )
    util_r.trials = [Trial(succeeded=True), Trial(succeeded=False)]
    run = RunResult(results=[util_r], trials_per_attack=2)
    checks = {c.name: c for c in evaluate_policy(run, Policy(min_utility=1.0))}
    assert "asr.overall" not in checks
    assert checks["utility.overall"].passed is False
    assert checks["utility.overall"].value == 0.5


def test_policy_require_utility():
    attack_r = AttackResult(attack=_attack())
    attack_r.trials = [Trial(succeeded=False)]
    run = RunResult(results=[attack_r], trials_per_attack=1)
    checks = {c.name: c for c in evaluate_policy(run, Policy(require_utility=True, max_asr=1.0))}
    assert checks["coverage.task_utility"].passed is False


def test_llm_judge_skipped_in_static_runner():
    a = _attack(id="J-1", detector=DETECTOR_LLM_JUDGE, prompt="banana")
    run = run_attacks([a], wrap_function(lambda p, d, h: "BANANA"), RunConfig(trials=1))
    assert run.results[0].skipped_reason
    assert "deep-only" in (run.results[0].skipped_reason or "")


def test_refuse_all_fails_utility_with_low_asr(capsys, monkeypatch):
    monkeypatch.chdir(ROOT)
    code = main(["run", "-c", str(EXAMPLES / "redgrade.refuse_all.yaml"), "--trials", "1"])
    assert code == 1
    out = capsys.readouterr().out
    assert "FAILED" in out
    assert "utility" in out.lower() or "Utility" in out


def test_vulnerable_still_passes_utility_probes(monkeypatch):
    monkeypatch.chdir(ROOT)
    util = load_attacks(families=[FAMILY_TASK_UTILITY])
    from examples.demo_app import vulnerable

    run = run_attacks(util, wrap_function(vulnerable), RunConfig(trials=1))
    assert utility_rate(run) == 1.0

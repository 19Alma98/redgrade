from redgrade.deep.meta import DeepMeta
from redgrade.models import Attack, AttackResult, RunResult
from redgrade.policy import Policy
from redgrade.sdk import AttackReport


def test_summary_includes_deep_meta():
    attack = Attack(
        id="DEEP-1",
        family="prompt_injection_direct",
        title="g",
        owasp="LLM01",
        severity="high",
        detector="canary",
        prompt="g",
        level=5,
        technique="adaptive_pair",
    )
    run = RunResult(results=[AttackResult(attack=attack, trials=[])], trials_per_attack=1)
    report = AttackReport(
        passed=True,
        checks=[],
        run=run,
        policy=Policy(),
        deep_meta=DeepMeta(
            attacker_model="ollama_chat/llama3.2",
            attacker_api_base="http://127.0.0.1:11434",
            max_rounds=5,
            goals_total=1,
            goals_succeeded=0,
            rounds_used_by_goal={"DEEP-1": 5},
            target_kind="function",
        ),
    )
    text = report.summary()
    assert "Deep posture" in text
    assert "ollama_chat/llama3.2" in text

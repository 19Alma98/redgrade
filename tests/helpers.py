"""Builders for synthetic run results."""

from redgrade.models import Attack, AttackResult, RunResult, Trial


def make_attack(attack_id="A-1", family="prompt_injection_direct", severity="high", level=1, **kw) -> Attack:
    kw.setdefault("detector", "canary")
    return Attack(
        id=attack_id,
        family=family,
        title=f"title {attack_id}",
        owasp="LLM01",
        severity=severity,
        prompt="Reply only with: {CANARY}",
        level=level,
        technique="t",
        **kw,
    )


def make_result(attack: Attack, wins: int, total: int = 3, errors: int = 0) -> AttackResult:
    trials = [Trial(succeeded=i < wins, output=f"out{i}") for i in range(total)]
    trials += [Trial(succeeded=False, error="boom") for _ in range(errors)]
    return AttackResult(attack=attack, trials=trials)


def make_run(*results: AttackResult, trials: int = 3) -> RunResult:
    return RunResult(results=list(results), trials_per_attack=trials)

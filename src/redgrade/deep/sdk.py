from __future__ import annotations

from collections.abc import Callable
from typing import Literal

from redgrade.deep.attacker import GoalSpec, PairLiteAttacker
from redgrade.deep.client import LlmClient
from redgrade.deep.errors import DeepError
from redgrade.deep.llm_target import LlmTarget
from redgrade.deep.meta import DeepMeta
from redgrade.loader import load_attacks
from redgrade.models import Attack, AttackResult, RunResult
from redgrade.policy import Policy, evaluate_policy
from redgrade.sdk import AttackReport, _build_report
from redgrade.targets import HttpTarget, Target


def _seed_documents(attack: Attack) -> tuple[str, ...]:
    if attack.documents:
        return tuple(attack.documents)
    if attack.document:
        return (attack.document,)
    return ()


def _goal_succeeded(trials: list) -> bool:
    return any(t.succeeded for t in trials if t.error is None)


def _target_kind(target: Target) -> Literal["http", "llm", "function"]:
    if isinstance(target, HttpTarget):
        return "http"
    if isinstance(target, LlmTarget):
        return "llm"
    return "function"


def _build_goal_specs(
    *,
    goals: list[str] | None,
    seed_attack_ids: list[str] | None,
    packs: list[str] | None,
    detector: str,
) -> list[GoalSpec]:
    specs: list[GoalSpec] = []
    for i, text in enumerate(goals or [], start=1):
        specs.append(GoalSpec(id=f"DEEP-{i}", text=text, detector=detector))

    if seed_attack_ids:
        by_id = {a.id: a for a in load_attacks(extra_packs=packs)}
        for sid in seed_attack_ids:
            attack = by_id.get(sid)
            if attack is None:
                raise DeepError(f"unknown seed attack id: {sid!r}")
            if attack.turns:
                raise DeepError("multi-turn seeds not supported in M1")
            specs.append(
                GoalSpec(
                    id=f"DEEP-SEED-{attack.id}",
                    text=attack.title or attack.id,
                    seed_prompt=attack.prompt,
                    seed_documents=_seed_documents(attack),
                    detector=detector,
                )
            )
    return specs


def deep_attack(
    target: Target,
    *,
    attacker_model: str,
    attacker_api_base: str | None = None,
    goals: list[str] | None = None,
    seed_attack_ids: list[str] | None = None,
    max_rounds: int = 5,
    policy: Policy | None = None,
    secrets: list[str] | None = None,
    allowed_hosts: list[str] | None = None,
    detector: str = "canary",
    attacker_chat: Callable[[list[dict[str, str]]], str] | None = None,
    packs: list[str] | None = None,
) -> AttackReport:
    if not (goals or seed_attack_ids):
        raise DeepError("deep_attack requires at least one goal or seed_attack_id")

    policy = policy or Policy()
    goal_specs = _build_goal_specs(
        goals=goals,
        seed_attack_ids=seed_attack_ids,
        packs=packs,
        detector=detector,
    )
    chat_fn = attacker_chat
    if chat_fn is None:
        client = LlmClient(model=attacker_model, api_base=attacker_api_base)

        def chat_fn(messages: list[dict[str, str]]) -> str:
            return client.chat(messages, response_format_json=True)

    attacker = PairLiteAttacker(chat_fn, max_rounds=max_rounds)
    kind = _target_kind(target)
    goal_runs = [
        attacker.run_goal(spec, target, secrets=secrets, allowed_hosts=allowed_hosts) for spec in goal_specs
    ]
    run = RunResult(
        results=[AttackResult(attack=gr.attack, trials=gr.trials) for gr in goal_runs],
        trials_per_attack=max_rounds,
    )
    checks = evaluate_policy(run, policy)
    goals_succeeded = sum(1 for gr in goal_runs if _goal_succeeded(gr.trials))
    deep_meta = DeepMeta(
        attacker_model=attacker_model,
        attacker_api_base=attacker_api_base,
        max_rounds=max_rounds,
        goals_total=len(goal_specs),
        goals_succeeded=goals_succeeded,
        rounds_used_by_goal={gr.attack.id: gr.rounds_used for gr in goal_runs},
        target_kind=kind,
    )
    return _build_report(run, checks, policy, deep_meta=deep_meta)

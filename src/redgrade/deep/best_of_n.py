"""Best-of-N jailbreaking (Hughes et al., 2024), adaptive form.

Sample augmented variants of a seed (word scrambling, random capitalization, ASCII noise) and
stop at the first that works. No attacker model is needed: the variants come from a seeded
``random.Random``, so a run is reproducible and the winning variant can be frozen into a CI
pack as a ``bon`` mutation. Raise ``max_rounds`` to sample more (the paper's success rate grows
roughly as a power law in N).
"""

import zlib
from collections.abc import Callable

from redgrade.deep.attacker import GoalRun, GoalSpec, _synthetic_attack
from redgrade.deep.conversational import evaluate_turn
from redgrade.models import Trial
from redgrade.mutations import mutate_template
from redgrade.render import render
from redgrade.runner import new_canary
from redgrade.targets import Target

ChatFn = Callable[[list[dict[str, str]]], str]


def variant_seed(goal_id: str, index: int) -> int:
    return zlib.crc32(f"{goal_id}#bon{index}".encode())


class BestOfNAttacker:
    name = "best_of_n"

    def __init__(
        self,
        chat: ChatFn | None = None,
        *,
        max_rounds: int = 5,
        judge_chat: ChatFn | None = None,
    ) -> None:
        # ``chat`` is accepted for a uniform strategy signature; Best-of-N never calls it.
        self._max_rounds = max_rounds
        self._judge_chat = judge_chat

    def run_goal(
        self,
        goal: GoalSpec,
        target: Target,
        *,
        secrets: list[str] | None = None,
        allowed_hosts: list[str] | None = None,
    ) -> GoalRun:
        attack = _synthetic_attack(goal, technique="adaptive_best_of_n")
        base_prompt = goal.seed_prompt if goal.seed_prompt is not None else goal.text
        base_docs = list(goal.seed_documents)
        trials: list[Trial] = []
        rounds_used = 0
        winning_prompt: str | None = None
        winning_documents: tuple[str, ...] = ()

        for i in range(1, self._max_rounds + 1):
            rounds_used = i
            seed = variant_seed(goal.id, i)
            prompt_tpl = mutate_template("bon", base_prompt, seed=seed)
            doc_tpls = [mutate_template("bon", d, seed=seed) for d in base_docs]
            canary = new_canary()
            prompt = render(prompt_tpl, canary)
            documents = [render(d, canary) for d in doc_tpls]
            trial = evaluate_turn(
                goal,
                target,
                prompt,
                documents,
                [],
                canary,
                secrets=secrets,
                allowed_hosts=allowed_hosts,
                judge_chat=self._judge_chat,
            )
            trials.append(trial)
            if trial.succeeded:
                # Store the augmented text with the canary placeholder restored, so the winning
                # variant can be replayed as a static seed.
                winning_prompt = prompt.replace(canary, "{CANARY}")
                winning_documents = tuple(d.replace(canary, "{CANARY}") for d in documents)
                break

        return GoalRun(
            attack=attack,
            trials=trials,
            rounds_used=rounds_used,
            strategy=self.name,
            winning_prompt=winning_prompt,
            winning_documents=winning_documents,
        )

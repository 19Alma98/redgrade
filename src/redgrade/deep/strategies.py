from collections.abc import Callable
from typing import Protocol

from redgrade.deep.attacker import GoalRun, GoalSpec, PairLiteAttacker
from redgrade.deep.crescendo import CrescendoAttacker
from redgrade.deep.errors import DeepError
from redgrade.deep.tap import TapAttacker
from redgrade.targets import Target


class AdaptiveStrategy(Protocol):
    name: str

    def run_goal(
        self,
        goal: GoalSpec,
        target: Target,
        *,
        secrets: list[str] | None = None,
        allowed_hosts: list[str] | None = None,
    ) -> GoalRun: ...


class _PairStrategy(PairLiteAttacker):
    name = "pair"


def get_strategy(
    name: str, chat: Callable[[list[dict[str, str]]], str], *, max_rounds: int
) -> AdaptiveStrategy:
    if name == "pair":
        return _PairStrategy(chat, max_rounds=max_rounds)
    if name == "crescendo":
        return CrescendoAttacker(chat, max_rounds=max_rounds)
    if name == "tap":
        return TapAttacker(chat, max_rounds=max_rounds)
    raise DeepError(f"unknown strategy: {name!r}")
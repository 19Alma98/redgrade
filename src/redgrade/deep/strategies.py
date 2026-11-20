from collections.abc import Callable
from typing import Protocol

from redgrade.constants import (
    DEEP_STRATEGIES,
    STRATEGY_BEST_OF_N,
    STRATEGY_CRESCENDO,
    STRATEGY_ECHO_CHAMBER,
    STRATEGY_GOAT,
    STRATEGY_MISCHIEVOUS_USER,
    STRATEGY_PAIR,
    STRATEGY_TAP,
)
from redgrade.deep.attacker import GoalRun, GoalSpec, PairLiteAttacker
from redgrade.deep.best_of_n import BestOfNAttacker
from redgrade.deep.conversational import (
    CrescendoAttacker,
    EchoChamberAttacker,
    GoatAttacker,
    MischievousUserAttacker,
)
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
    name: str,
    chat: Callable[[list[dict[str, str]]], str],
    *,
    max_rounds: int,
    judge_chat: Callable[[list[dict[str, str]]], str] | None = None,
) -> AdaptiveStrategy:
    if name == STRATEGY_PAIR:
        return _PairStrategy(chat, max_rounds=max_rounds, judge_chat=judge_chat)
    if name == STRATEGY_CRESCENDO:
        return CrescendoAttacker(chat, max_rounds=max_rounds, judge_chat=judge_chat)
    if name == STRATEGY_TAP:
        return TapAttacker(chat, max_rounds=max_rounds, judge_chat=judge_chat)
    if name == STRATEGY_GOAT:
        return GoatAttacker(chat, max_rounds=max_rounds, judge_chat=judge_chat)
    if name == STRATEGY_ECHO_CHAMBER:
        return EchoChamberAttacker(chat, max_rounds=max_rounds, judge_chat=judge_chat)
    if name == STRATEGY_BEST_OF_N:
        return BestOfNAttacker(chat, max_rounds=max_rounds, judge_chat=judge_chat)
    if name == STRATEGY_MISCHIEVOUS_USER:
        return MischievousUserAttacker(chat, max_rounds=max_rounds, judge_chat=judge_chat)
    known = ", ".join(DEEP_STRATEGIES)
    raise DeepError(f"unknown strategy: {name!r} (known: {known})")

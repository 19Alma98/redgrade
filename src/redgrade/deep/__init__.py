from collections.abc import Callable
from typing import Any

from redgrade.deep.errors import DeepError
from redgrade.deep.llm_target import LlmTarget
from redgrade.deep.meta import DeepMeta

__all__ = ["DeepError", "DeepMeta", "LlmTarget", "check_deep", "deep_attack", "summarize_scorecard"]


def __getattr__(name: str) -> Callable[..., Any]:
    if name == "deep_attack":
        from redgrade.deep.sdk import deep_attack

        return deep_attack
    if name == "check_deep":
        from redgrade.deep.sdk import check_deep

        return check_deep
    if name == "summarize_scorecard":
        from redgrade.deep.summary import summarize_scorecard

        return summarize_scorecard
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

"""LLM-as-judge for deep mode only (semantic attack success)."""

from __future__ import annotations

import json
from collections.abc import Callable

from redgrade.constants import DETECTOR_LLM_JUDGE
from redgrade.deep.errors import DeepError
from redgrade.detectors import DetectorContext, get_detector
from redgrade.judge import JUDGE_SYSTEM, judge_messages, parse_judge_response

__all__ = ["JUDGE_SYSTEM", "parse_judge_response", "run_llm_judge", "score_output"]


def run_llm_judge(
    *,
    goal: str,
    output: str,
    documents: list[str] | None = None,
    chat: Callable[[list[dict[str, str]]], str],
) -> tuple[bool, str]:
    """Return (attack_succeeded, reason). Fail-closed on parse/provider errors."""
    messages = judge_messages(goal, output, documents)
    try:
        raw = chat(messages)
        return parse_judge_response(raw)
    except DeepError:
        return False, "judge provider error (fail-closed)"
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        return False, f"judge parse error (fail-closed): {exc}"
    except Exception as exc:
        return False, f"judge error (fail-closed): {exc}"


def score_output(
    detector: str,
    ctx: DetectorContext,
    *,
    goal_text: str,
    judge_chat: Callable[[list[dict[str, str]]], str] | None = None,
) -> tuple[bool, str]:
    """Score a trial: route ``llm_judge`` to the deep judge, else deterministic detectors."""
    if detector == DETECTOR_LLM_JUDGE:
        if judge_chat is None:
            raise DeepError("llm_judge requires a judge chat callable")
        docs = [line for line in ctx.inputs.split("\n") if line] if ctx.inputs else []
        return run_llm_judge(goal=goal_text, output=ctx.output, documents=docs, chat=judge_chat)
    return get_detector(detector)(ctx)

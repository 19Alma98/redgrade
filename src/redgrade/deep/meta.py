from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class DeepMeta(BaseModel):
    attacker_model: str
    attacker_api_base: str | None = None
    max_rounds: int
    goals_total: int
    goals_succeeded: int
    rounds_used_by_goal: dict[str, int] = Field(default_factory=dict)
    target_kind: Literal["http", "llm", "function"]
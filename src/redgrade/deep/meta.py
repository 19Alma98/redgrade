from typing import Literal

from pydantic import BaseModel, Field


class WinningSeed(BaseModel):
    goal_id: str
    strategy: str
    prompt: str
    documents: list[str] = Field(default_factory=list)
    detector: str = "canary"
    level: int = 4
    # Conversation before the winning turn (multi-turn strategies), replayed as forged history.
    history: list[dict[str, str]] = Field(default_factory=list)


class DeepMeta(BaseModel):
    attacker_model: str
    attacker_api_base: str | None = None
    max_rounds: int
    goals_total: int
    goals_succeeded: int
    rounds_used_by_goal: dict[str, int] = Field(default_factory=dict)
    target_kind: Literal["http", "llm", "function"]
    strategies: list[str] = Field(default_factory=list)
    winning_seeds: list[WinningSeed] = Field(default_factory=list)

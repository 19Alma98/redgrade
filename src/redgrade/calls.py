"""Tool calls observed from the app under test (shared by the data model and the tool server)."""

from pydantic import BaseModel, ConfigDict, Field

from redgrade.types import JsonValue

__all__ = ["ToolCall"]


class ToolCall(BaseModel):
    """One tool invocation observed from the app under test."""

    model_config = ConfigDict(frozen=True)

    name: str
    arguments: dict[str, JsonValue] = Field(default_factory=dict)
    id: str = ""

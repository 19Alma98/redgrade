from redgrade.deep.errors import DeepError
from redgrade.deep.llm_target import LlmTarget
from redgrade.deep.meta import DeepMeta

__all__ = ["DeepError", "DeepMeta", "LlmTarget", "deep_attack"]


def __getattr__(name: str):
    if name == "deep_attack":
        from redgrade.deep.sdk import deep_attack

        return deep_attack
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

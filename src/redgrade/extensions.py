"""Turn the extension blocks of ``redgrade.yaml`` (plugins, classifiers, judge) into live objects."""

import importlib
from pathlib import Path

from redgrade.classifiers import build_classifier, register_classifier
from redgrade.config import Config, JudgeConfig
from redgrade.judge import Chat, Judge, JudgeCache
from redgrade.plugins import load_plugins

__all__ = ["as_judge", "build_judge", "prepare_extensions"]


def as_judge(judge: Judge | Chat | None, cache: str | Path | JudgeCache | None = None) -> Judge | None:
    """SDK helper: a chat callable becomes a ``Judge``; ``cache`` (a path) adds a verdict cache."""
    if judge is None:
        return None
    store = cache if isinstance(cache, JudgeCache) or cache is None else JudgeCache(cache)
    if isinstance(judge, Judge):
        if store is not None and judge.cache is None:
            judge.cache = store
        return judge
    return Judge(judge, judge_id=getattr(judge, "__qualname__", "custom"), cache=store)


def build_judge(config: JudgeConfig | None) -> Judge | None:
    if config is None:
        return None
    cache = JudgeCache(config.cache) if config.cache else None
    if config.path:
        module_name, _, attr = config.path.partition(":")
        fn = getattr(importlib.import_module(module_name), attr, None) if attr else None
        if not callable(fn):
            raise ValueError(f"judge.path must be 'module:function' (a chat callable), got {config.path!r}")
        return Judge(fn, judge_id=config.path, cache=cache)
    if not config.model:
        raise ValueError("judge needs 'model' (LiteLLM) or 'path' (your chat callable)")
    from redgrade.deep.client import LlmClient

    client = LlmClient(model=config.model, api_base=config.api_base)

    def chat(messages: list[dict[str, str]]) -> str:
        return client.chat(messages, response_format_json=True)

    return Judge(chat, judge_id=config.model, cache=cache)


def prepare_extensions(config: Config, *, installed_plugins: bool = True) -> Judge | None:
    """Load plugins, register the configured classifiers and build the judge (if any)."""
    load_plugins(config.plugins, installed=installed_plugins)
    for name, spec in config.classifiers.items():
        register_classifier(name, build_classifier(spec), replace=True)
    return build_judge(config.judge)

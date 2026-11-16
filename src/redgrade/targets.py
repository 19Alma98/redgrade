"""Targets: the thing under attack.

A target is a callable ``(prompt, documents) -> str``. Two adapters ship with Redgrade:

* ``module:function`` -- a Python function. It may take ``(prompt)`` or ``(prompt, documents)``.
* ``http`` -- any endpoint that takes JSON and returns JSON.
"""

import importlib
import inspect
import os
import re
import sys
from collections.abc import Callable, Mapping
from typing import Annotated, Literal

import httpx2
from pydantic import BaseModel, Field

from redgrade.constants import (
    DEFAULT_HTTP_RESPONSE_PATH,
    DEFAULT_HTTP_TIMEOUT,
    TARGET_TYPE_FUNCTION,
    TARGET_TYPE_HTTP,
    TEMPLATE_DOCUMENTS,
    TEMPLATE_HISTORY,
    TEMPLATE_PROMPT,
)
from redgrade.render import format_history
from redgrade.types import HistoryMessage, JsonValue, YamlMapping

Target = Callable[[str, list[str], list[HistoryMessage]], str]


class TargetError(Exception):
    """The target could not be built or called."""


class FunctionTargetConfig(BaseModel):
    type: Literal["function"] = "function"
    path: str


class HttpTargetConfig(BaseModel):
    type: Literal["http"] = "http"
    url: str
    body: JsonValue = None
    response_path: str = DEFAULT_HTTP_RESPONSE_PATH
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: float = DEFAULT_HTTP_TIMEOUT


TargetConfig = Annotated[FunctionTargetConfig | HttpTargetConfig, Field(discriminator="type")]


def function_target(spec: str) -> Target:
    """Load ``package.module:function`` (the current directory is importable)."""
    module_name, sep, func_name = spec.partition(":")
    if not sep or not module_name or not func_name:
        raise TargetError(f"target must look like 'module:function', got {spec!r}")
    cwd = os.getcwd()
    if cwd not in sys.path:
        sys.path.insert(0, cwd)
    try:
        func = getattr(importlib.import_module(module_name), func_name)
    except (ImportError, AttributeError) as exc:
        raise TargetError(f"cannot load target {spec!r}: {exc}") from exc
    return wrap_function(func)


def wrap_function(func: Callable[..., object]) -> Target:
    params = list(inspect.signature(func).parameters.values())
    names = {p.name for p in params}
    accepts_docs = any(p.kind is p.VAR_POSITIONAL for p in params) or len(params) >= 2
    accepts_docs = accepts_docs or any(p.name == "documents" for p in params)
    accepts_history = "history" in names or len(params) >= 3

    def call(
        prompt: str,
        documents: list[str],
        history: list[HistoryMessage] | None = None,
    ) -> str:
        history = history or []
        if accepts_history:
            if accepts_docs:
                result = func(prompt, documents, history)
            else:
                result = func(prompt, history)
        else:
            if history:
                prompt = format_history(history) + "\n\n" + prompt
            result = func(prompt, documents) if accepts_docs else func(prompt)
        return result if isinstance(result, str) else str(result)

    return call


_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_env(value: str) -> str:
    return _ENV.sub(lambda m: os.environ.get(m.group(1), ""), value)


def _contains_template_history(node: JsonValue) -> bool:
    if isinstance(node, str):
        return TEMPLATE_HISTORY in node
    if isinstance(node, list):
        return any(_contains_template_history(x) for x in node)
    if isinstance(node, dict):
        return any(_contains_template_history(v) for v in node.values())
    return False


def _fill(
    node: JsonValue,
    prompt: str,
    documents: list[str],
    history: list[HistoryMessage],
) -> JsonValue:
    """Replace ``{{prompt}}``, ``{{documents}}``, and ``{{history}}`` in a JSON-like template."""
    if isinstance(node, str):
        if node == TEMPLATE_DOCUMENTS:
            return list(documents)
        if node == TEMPLATE_HISTORY:
            return list(history)
        return (
            node.replace(TEMPLATE_PROMPT, prompt)
            .replace(TEMPLATE_DOCUMENTS, "\n\n".join(documents))
            .replace(TEMPLATE_HISTORY, format_history(history))
        )
    if isinstance(node, list):
        return [_fill(x, prompt, documents, history) for x in node]
    if isinstance(node, dict):
        return {str(k): _fill(v, prompt, documents, history) for k, v in node.items()}
    return node


def _dig(data: object, path: str) -> object:
    """Follow a dotted path like ``choices.0.message.content``."""
    current = data
    for part in path.split("."):
        if isinstance(current, list):
            current = current[int(part)]
        elif isinstance(current, Mapping):
            current = current[part]
        else:
            raise TypeError(f"cannot dig into {type(current).__name__} at {part!r}")
    return current


class HttpTarget:
    def __init__(
        self,
        url: str,
        *,
        body: JsonValue = None,
        response_path: str = DEFAULT_HTTP_RESPONSE_PATH,
        headers: dict[str, str] | None = None,
        timeout: float = DEFAULT_HTTP_TIMEOUT,
        client: httpx2.Client | None = None,
    ) -> None:
        self.url = _expand_env(url)
        self.body: JsonValue = {"prompt": TEMPLATE_PROMPT} if body is None else body
        self.response_path = response_path
        self.headers = {k: _expand_env(v) for k, v in (headers or {}).items()}
        self._client = client or httpx2.Client(timeout=timeout)

    def __call__(
        self,
        prompt: str,
        documents: list[str],
        history: list[HistoryMessage] | None = None,
    ) -> str:
        history = history or []
        if history and not _contains_template_history(self.body):
            prompt = format_history(history) + "\n\n" + prompt
        payload = _fill(self.body, prompt, documents, history)
        try:
            response = self._client.post(self.url, json=payload, headers=self.headers)
            response.raise_for_status()
            return str(_dig(response.json(), self.response_path))
        except (httpx2.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
            raise TargetError(f"HTTP target failed: {exc}") from exc


class TargetFactory:
    """Build a callable target from a typed config block."""

    def build(self, config: TargetConfig | YamlMapping) -> Target:
        if isinstance(config, (FunctionTargetConfig, HttpTargetConfig)):
            parsed: FunctionTargetConfig | HttpTargetConfig = config
        else:
            raw = dict(config)
            kind = raw.get("type", TARGET_TYPE_FUNCTION)
            if kind == TARGET_TYPE_FUNCTION:
                parsed = FunctionTargetConfig.model_validate({**raw, "type": TARGET_TYPE_FUNCTION})
            elif kind == TARGET_TYPE_HTTP:
                parsed = HttpTargetConfig.model_validate({**raw, "type": TARGET_TYPE_HTTP})
            else:
                raise TargetError(f"unknown target type {kind!r} (use 'function' or 'http')")

        if isinstance(parsed, FunctionTargetConfig):
            return function_target(parsed.path)
        return HttpTarget(
            parsed.url,
            body=parsed.body,
            response_path=parsed.response_path,
            headers=parsed.headers,
            timeout=parsed.timeout,
        )


def build_target(config: TargetConfig | YamlMapping) -> Target:
    """Build a target from the ``target:`` block of the config."""
    return TargetFactory().build(config)

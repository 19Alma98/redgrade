"""Targets: the thing under attack.

A target is a callable ``(prompt, documents) -> str``. Two adapters ship with Redgrade:

* ``module:function`` -- a Python function. It may take ``(prompt)`` or ``(prompt, documents)``.
* ``http`` -- any endpoint that takes JSON and returns JSON.
"""

from __future__ import annotations

import importlib
import inspect
import os
import re
import sys
from collections.abc import Callable
from typing import Any

import httpx

Target = Callable[[str, list[str]], str]


class TargetError(Exception):
    """The target could not be built or called."""


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


def wrap_function(func: Callable[..., Any]) -> Target:
    params = list(inspect.signature(func).parameters.values())
    accepts_docs = any(p.kind is p.VAR_POSITIONAL for p in params) or len(params) >= 2
    accepts_docs = accepts_docs or any(p.name == "documents" for p in params)

    def call(prompt: str, documents: list[str]) -> str:
        result = func(prompt, documents) if accepts_docs else func(prompt)
        return result if isinstance(result, str) else str(result)

    return call


_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_env(value: str) -> str:
    return _ENV.sub(lambda m: os.environ.get(m.group(1), ""), value)


def _fill(node: Any, prompt: str, documents: list[str]) -> Any:
    """Replace ``{{prompt}}`` and ``{{documents}}`` in a JSON-like template."""
    if isinstance(node, str):
        if node == "{{documents}}":
            return documents
        return node.replace("{{prompt}}", prompt).replace("{{documents}}", "\n\n".join(documents))
    if isinstance(node, list):
        return [_fill(x, prompt, documents) for x in node]
    if isinstance(node, dict):
        return {k: _fill(v, prompt, documents) for k, v in node.items()}
    return node


def _dig(data: Any, path: str) -> Any:
    """Follow a dotted path like ``choices.0.message.content``."""
    for part in path.split("."):
        if isinstance(data, list):
            data = data[int(part)]
        else:
            data = data[part]
    return data


class HttpTarget:
    def __init__(
        self,
        url: str,
        *,
        body: Any = None,
        response_path: str = "output",
        headers: dict[str, str] | None = None,
        timeout: float = 60.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.url = _expand_env(url)
        self.body = body if body is not None else {"prompt": "{{prompt}}"}
        self.response_path = response_path
        self.headers = {k: _expand_env(v) for k, v in (headers or {}).items()}
        self._client = client or httpx.Client(timeout=timeout)

    def __call__(self, prompt: str, documents: list[str]) -> str:
        payload = _fill(self.body, prompt, documents)
        try:
            response = self._client.post(self.url, json=payload, headers=self.headers)
            response.raise_for_status()
            return str(_dig(response.json(), self.response_path))
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            raise TargetError(f"HTTP target failed: {exc}") from exc


def build_target(config: dict[str, Any]) -> Target:
    """Build a target from the ``target:`` block of the config."""
    kind = config.get("type", "function")
    if kind == "function":
        return function_target(str(config.get("path", "")))
    if kind == "http":
        if "url" not in config:
            raise TargetError("http target needs a 'url'")
        return HttpTarget(
            str(config["url"]),
            body=config.get("body"),
            response_path=str(config.get("response_path", "output")),
            headers=config.get("headers"),
            timeout=float(config.get("timeout", 60)),
        )
    raise TargetError(f"unknown target type {kind!r} (use 'function' or 'http')")

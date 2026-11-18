"""Targets: the thing under attack.

A target is a callable ``(prompt, documents, history, tools=?) -> str | TargetObservation``.
Two adapters ship with Redgrade:

* ``module:function`` -- a Python function. It may take ``(prompt)`` or ``(prompt, documents)``
  (and optional ``history`` / ``tools``).
* ``http`` -- any endpoint that takes JSON and returns JSON. Optional ``tools_path`` extracts
  tool calls from the response into a ``TargetObservation``. Files are sent either as multipart
  (``upload_field``) or as base64 JSON (``{{attachments}}`` in the body).
"""

import importlib
import inspect
import json
import os
import re
import sys
from collections.abc import Callable, Mapping
from typing import Annotated, Literal, cast

import httpx2
from pydantic import BaseModel, Field

from redgrade.attachments import Attachment
from redgrade.constants import (
    DEFAULT_HTTP_RESPONSE_PATH,
    DEFAULT_HTTP_TIMEOUT,
    TARGET_TYPE_FUNCTION,
    TARGET_TYPE_HTTP,
    TEMPLATE_ATTACHMENTS,
    TEMPLATE_DOCUMENTS,
    TEMPLATE_HISTORY,
    TEMPLATE_PROMPT,
    TEMPLATE_TOOLS,
)
from redgrade.models import TargetObservation, ToolCall
from redgrade.render import format_history
from redgrade.types import HistoryMessage, JsonValue, YamlMapping

TargetResult = str | TargetObservation
Target = Callable[..., TargetResult]


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
    tools_path: str | None = None
    upload_field: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: float = DEFAULT_HTTP_TIMEOUT


TargetConfig = Annotated[FunctionTargetConfig | HttpTargetConfig, Field(discriminator="type")]


def normalize_observation(result: TargetResult) -> TargetObservation:
    if isinstance(result, TargetObservation):
        return result
    return TargetObservation(output=result if isinstance(result, str) else str(result))


def _callable_accepts_tools(target: object) -> bool:
    flag = getattr(target, "_redgrade_observes_tools", None)
    if flag is not None:
        return bool(flag)
    try:
        return "tools" in inspect.signature(target).parameters  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False


def target_observes_tools(target: object) -> bool:
    """HTTP targets need ``tools_path``; function targets need a ``tools`` parameter."""
    if isinstance(target, HttpTarget):
        return bool(target.tools_path)
    return _callable_accepts_tools(target)


def target_accepts_attachments(target: object) -> bool:
    """HTTP targets need ``upload_field`` or ``{{attachments}}``; callables an ``attachments`` param."""
    if isinstance(target, HttpTarget):
        return target.accepts_attachments
    flag = getattr(target, "_redgrade_accepts_attachments", None)
    if flag is not None:
        return bool(flag)
    try:
        return "attachments" in inspect.signature(target).parameters  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False


def invoke_target(
    target: Target,
    prompt: str,
    documents: list[str],
    history: list[HistoryMessage] | None = None,
    tools: list[JsonValue] | None = None,
    attachments: list[Attachment] | None = None,
) -> TargetResult:
    """Call a target with optional ``tools`` / ``attachments``, keeping 3-arg lambdas working."""
    history = history or []
    tools = tools or []
    extra: dict[str, object] = {}
    if attachments:
        if not target_accepts_attachments(target):
            raise TargetError("target has no attachments surface")
        extra["attachments"] = attachments
    if isinstance(target, HttpTarget):
        return target(prompt, documents, history, tools, **extra)  # type: ignore[arg-type]
    if getattr(target, "_redgrade_observes_tools", None) is not None:
        return target(prompt, documents, history, tools, **extra)
    try:
        if "tools" in inspect.signature(target).parameters:
            return target(prompt, documents, history, tools, **extra)
    except (TypeError, ValueError):
        pass
    return target(prompt, documents, history, **extra)


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
    accepts_attachments = "attachments" in names
    core = [p for p in params if p.name != "attachments"]
    accepts_docs = any(p.kind is p.VAR_POSITIONAL for p in core) or len(core) >= 2
    accepts_docs = accepts_docs or any(p.name == "documents" for p in params)
    accepts_history = "history" in names or len(core) >= 3
    accepts_tools = "tools" in names

    def call(
        prompt: str,
        documents: list[str],
        history: list[HistoryMessage] | None = None,
        tools: list[JsonValue] | None = None,
        attachments: list[Attachment] | None = None,
    ) -> TargetResult:
        history = history or []
        tools = tools or []
        kwargs: dict[str, object] = {}
        if accepts_tools:
            kwargs["tools"] = tools
        if accepts_attachments:
            kwargs["attachments"] = attachments or []
        elif attachments:
            raise TargetError("target function has no `attachments` parameter")
        if accepts_history:
            if accepts_docs:
                result = func(prompt, documents, history, **kwargs)
            else:
                result = func(prompt, history, **kwargs)
        else:
            if history:
                prompt = format_history(history) + "\n\n" + prompt
            if accepts_docs:
                result = func(prompt, documents, **kwargs)
            else:
                result = func(prompt, **kwargs)
        if isinstance(result, TargetObservation):
            return result
        return result if isinstance(result, str) else str(result)

    call._redgrade_observes_tools = accepts_tools  # type: ignore[attr-defined]
    call._redgrade_accepts_attachments = accepts_attachments  # type: ignore[attr-defined]
    return call


_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_env(value: str) -> str:
    return _ENV.sub(lambda m: os.environ.get(m.group(1), ""), value)


def _contains_template(node: JsonValue, token: str) -> bool:
    if isinstance(node, str):
        return token in node
    if isinstance(node, list):
        return any(_contains_template(x, token) for x in node)
    if isinstance(node, dict):
        return any(_contains_template(v, token) for v in node.values())
    return False


def _fill(
    node: JsonValue,
    prompt: str,
    documents: list[str],
    history: list[HistoryMessage],
    tools: list[JsonValue],
    attachments: list[Attachment] | None = None,
) -> JsonValue:
    """Replace ``{{prompt}}``, ``{{documents}}``, ``{{history}}``, ``{{tools}}``, ``{{attachments}}``."""
    if isinstance(node, str):
        if node == TEMPLATE_ATTACHMENTS:
            return [cast(JsonValue, a.as_json()) for a in attachments or []]
        if node == TEMPLATE_DOCUMENTS:
            return list(documents)
        if node == TEMPLATE_HISTORY:
            return cast(JsonValue, list(history))
        if node == TEMPLATE_TOOLS:
            return list(tools)
        return (
            node.replace(TEMPLATE_PROMPT, prompt)
            .replace(TEMPLATE_DOCUMENTS, "\n\n".join(documents))
            .replace(TEMPLATE_HISTORY, format_history(history))
            .replace(TEMPLATE_TOOLS, json.dumps(tools, ensure_ascii=False))
        )
    if isinstance(node, list):
        return [_fill(x, prompt, documents, history, tools, attachments) for x in node]
    if isinstance(node, dict):
        return {str(k): _fill(v, prompt, documents, history, tools, attachments) for k, v in node.items()}
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


def parse_tool_calls(raw: object) -> list[ToolCall]:
    """Parse a JSON list of tool calls (flat or OpenAI-style ``function`` wrappers)."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise TargetError(f"tools_path must point to a list, got {type(raw).__name__}")
    calls: list[ToolCall] = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise TargetError("each tool call must be a mapping")
        name = item.get("name")
        arguments: object = item.get("arguments", {})
        call_id = str(item.get("id", "") or "")
        if name is None and isinstance(item.get("function"), Mapping):
            fn = item["function"]
            name = fn.get("name")
            arguments = fn.get("arguments", {})
            if not call_id:
                call_id = str(item.get("id", "") or "")
        if not isinstance(name, str) or not name:
            raise TargetError("tool call missing name")
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments) if arguments else {}
            except json.JSONDecodeError as exc:
                raise TargetError(f"tool arguments are not valid JSON: {exc}") from exc
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise TargetError("tool arguments must be a mapping or JSON object string")
        calls.append(
            ToolCall(
                name=name,
                arguments=cast(dict[str, JsonValue], arguments),
                id=call_id,
            )
        )
    return calls


class HttpTarget:
    def __init__(
        self,
        url: str,
        *,
        body: JsonValue = None,
        response_path: str = DEFAULT_HTTP_RESPONSE_PATH,
        tools_path: str | None = None,
        upload_field: str | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = DEFAULT_HTTP_TIMEOUT,
        client: httpx2.Client | None = None,
    ) -> None:
        self.url = _expand_env(url)
        self.body: JsonValue = {"prompt": TEMPLATE_PROMPT} if body is None else body
        self.response_path = response_path
        self.tools_path = tools_path
        self.upload_field = upload_field
        if upload_field and not isinstance(self.body, dict):
            raise TargetError("upload_field needs a body that is a mapping (it becomes the form fields)")
        self.headers = {k: _expand_env(v) for k, v in (headers or {}).items()}
        self._client = client or httpx2.Client(timeout=timeout)

    @property
    def accepts_attachments(self) -> bool:
        return bool(self.upload_field) or _contains_template(self.body, TEMPLATE_ATTACHMENTS)

    def _send(self, payload: JsonValue, attachments: list[Attachment]) -> httpx2.Response:
        if not self.upload_field:
            return self._client.post(self.url, json=payload, headers=self.headers)
        # Always multipart when ``upload_field`` is set, so an endpoint that only reads
        # multipart also works for attacks without files. ``(None, value)`` is a plain form field.
        parts: list[tuple[str, tuple[str | None, bytes | str, str] | tuple[None, str]]] = []
        for key, value in cast(dict[str, JsonValue], payload).items():
            text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
            parts.append((key, (None, text)))
        for att in attachments:
            parts.append((self.upload_field, (att.filename, att.data, att.content_type)))
        headers = {k: v for k, v in self.headers.items() if k.lower() != "content-type"}
        return self._client.post(self.url, files=parts, headers=headers)

    def __call__(
        self,
        prompt: str,
        documents: list[str],
        history: list[HistoryMessage] | None = None,
        tools: list[JsonValue] | None = None,
        attachments: list[Attachment] | None = None,
    ) -> TargetObservation:
        history = history or []
        tools = tools or []
        attachments = attachments or []
        if history and not _contains_template(self.body, TEMPLATE_HISTORY):
            prompt = format_history(history) + "\n\n" + prompt
        payload = _fill(self.body, prompt, documents, history, tools, attachments)
        try:
            response = self._send(payload, attachments)
            response.raise_for_status()
            data = response.json()
            output = str(_dig(data, self.response_path))
            tools_called: list[ToolCall] = []
            if self.tools_path:
                tools_called = parse_tool_calls(_dig(data, self.tools_path))
            return TargetObservation(output=output, tools_called=tuple(tools_called))
        except (httpx2.HTTPError, KeyError, IndexError, TypeError, ValueError, TargetError) as exc:
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
            tools_path=parsed.tools_path,
            upload_field=parsed.upload_field,
            headers=parsed.headers,
            timeout=parsed.timeout,
        )


def build_target(config: TargetConfig | YamlMapping) -> Target:
    """Build a target from the ``target:`` block of the config."""
    return TargetFactory().build(config)

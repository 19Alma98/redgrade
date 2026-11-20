"""Targets: the thing under attack.

A target is a callable ``(prompt, documents, history, tools=?) -> str | TargetObservation``.
Three adapters ship with Redgrade:

* ``module:function`` -- a Python function. It may take ``(prompt)`` or ``(prompt, documents)``
  (and optional ``history`` / ``tools``).
* ``http`` -- any endpoint that takes JSON and returns JSON. Optional ``tools_path`` extracts
  tool calls from the response into a ``TargetObservation``. Files are sent either as multipart
  (``upload_field``) or as base64 JSON (``{{attachments}}`` in the body). ``{{history}}`` sends
  prior turns, ``{{messages}}`` the whole conversation including the current prompt.
* ``chat`` -- an OpenAI- or Anthropic-compatible messages endpoint (``ChatTarget``): history with
  every role, tool catalogs and tool calls go through the API's native fields.
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
    CHAT_API_ANTHROPIC,
    CHAT_API_OPENAI,
    DEFAULT_ANTHROPIC_MAX_TOKENS,
    DEFAULT_ANTHROPIC_VERSION,
    DEFAULT_CHAT_DOCUMENTS_TEMPLATE,
    DEFAULT_HTTP_RESPONSE_PATH,
    DEFAULT_HTTP_TIMEOUT,
    TARGET_TYPE_CHAT,
    TARGET_TYPE_FUNCTION,
    TARGET_TYPE_HTTP,
    TEMPLATE_ATTACHMENTS,
    TEMPLATE_DOCUMENTS,
    TEMPLATE_HISTORY,
    TEMPLATE_MESSAGES,
    TEMPLATE_PROMPT,
    TEMPLATE_SESSION_ID,
    TEMPLATE_TOOLS,
    ChatApi,
)
from redgrade.history import (
    anthropic_messages,
    anthropic_tools,
    format_history,
    normalize_history,
    openai_messages,
    openai_tools,
)
from redgrade.models import TargetObservation, ToolCall
from redgrade.session import current_session_id
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


class ChatTargetConfig(BaseModel):
    type: Literal["chat"] = "chat"
    url: str
    api: ChatApi = CHAT_API_OPENAI
    model: str | None = None
    system_prompt: str | None = None
    system_role: str = "system"
    documents_template: str = DEFAULT_CHAT_DOCUMENTS_TEMPLATE
    extra_body: dict[str, JsonValue] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: float = DEFAULT_HTTP_TIMEOUT


TargetConfig = Annotated[
    FunctionTargetConfig | HttpTargetConfig | ChatTargetConfig, Field(discriminator="type")
]


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
        return target.observes_tools
    return _callable_accepts_tools(target)


def target_accepts_history(target: object) -> bool:
    """Can the target receive conversation history natively (not flattened into the prompt)?

    HTTP targets need ``{{history}}`` or ``{{messages}}`` in the body; chat targets always can;
    wrapped functions need a ``history`` parameter. Plain callables are always called with
    history as the third argument, so they can.
    """
    if isinstance(target, HttpTarget):
        return target.accepts_history
    flag = getattr(target, "_redgrade_accepts_history", None)
    return True if flag is None else bool(flag)


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
    if getattr(target, "_redgrade_accepts_history", None) is None and not isinstance(target, HttpTarget):
        try:
            if "session_id" in inspect.signature(target).parameters:
                extra["session_id"] = current_session_id()
        except (TypeError, ValueError):
            pass
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
    core = [p for p in params if p.name not in ("attachments", "session_id")]
    accepts_docs = any(p.kind is p.VAR_POSITIONAL for p in core) or len(core) >= 2
    accepts_docs = accepts_docs or any(p.name == "documents" for p in params)
    accepts_history = "history" in names or len(core) >= 3
    accepts_tools = "tools" in names
    accepts_session = "session_id" in names

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
        if accepts_session:
            kwargs["session_id"] = current_session_id()
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
    call._redgrade_accepts_history = accepts_history  # type: ignore[attr-defined]
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
    """Replace ``{{prompt}}``, ``{{documents}}``, ``{{history}}``, ``{{messages}}``, ``{{tools}}``,
    ``{{attachments}}``. ``{{messages}}`` is the history plus the current user prompt."""
    if isinstance(node, str):
        if node == TEMPLATE_ATTACHMENTS:
            return [cast(JsonValue, a.as_json()) for a in attachments or []]
        if node == TEMPLATE_DOCUMENTS:
            return list(documents)
        if node == TEMPLATE_HISTORY:
            return cast(JsonValue, normalize_history(history))
        if node == TEMPLATE_MESSAGES:
            current: HistoryMessage = {"role": "user", "content": prompt}
            return cast(JsonValue, [*normalize_history(history), current])
        if node == TEMPLATE_TOOLS:
            return list(tools)
        return (
            node.replace(TEMPLATE_PROMPT, prompt)
            .replace(TEMPLATE_DOCUMENTS, "\n\n".join(documents))
            .replace(TEMPLATE_HISTORY, format_history(history))
            .replace(TEMPLATE_MESSAGES, format_history([*history, {"role": "user", "content": prompt}]))
            .replace(TEMPLATE_TOOLS, json.dumps(tools, ensure_ascii=False))
            .replace(TEMPLATE_SESSION_ID, current_session_id())
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

    @property
    def accepts_history(self) -> bool:
        return _contains_template(self.body, TEMPLATE_HISTORY) or _contains_template(
            self.body, TEMPLATE_MESSAGES
        )

    @property
    def observes_tools(self) -> bool:
        return bool(self.tools_path)

    @property
    def has_sessions(self) -> bool:
        """``{{session_id}}`` appears in the URL, headers or body."""
        return (
            TEMPLATE_SESSION_ID in self.url
            or any(TEMPLATE_SESSION_ID in v for v in self.headers.values())
            or _contains_template(self.body, TEMPLATE_SESSION_ID)
        )

    def _send(self, payload: JsonValue, attachments: list[Attachment]) -> httpx2.Response:
        sid = current_session_id()
        url = self.url.replace(TEMPLATE_SESSION_ID, sid)
        headers = {k: v.replace(TEMPLATE_SESSION_ID, sid) for k, v in self.headers.items()}
        if not self.upload_field:
            return self._client.post(url, json=payload, headers=headers)
        # Always multipart when ``upload_field`` is set, so an endpoint that only reads
        # multipart also works for attacks without files. ``(None, value)`` is a plain form field.
        parts: list[tuple[str, tuple[str | None, bytes | str, str] | tuple[None, str]]] = []
        for key, value in cast(dict[str, JsonValue], payload).items():
            text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
            parts.append((key, (None, text)))
        for att in attachments:
            parts.append((self.upload_field, (att.filename, att.data, att.content_type)))
        headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
        return self._client.post(url, files=parts, headers=headers)

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
        if history and not self.accepts_history:
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


def _text_content(content: object) -> str:
    """Text of a message ``content`` that is a string or a list of content parts / blocks."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [
            str(p.get("text", ""))
            for p in content
            if isinstance(p, Mapping) and p.get("type", "text") in ("text", "output_text")
        ]
        return "".join(parts)
    return str(content)


class ChatTarget(HttpTarget):
    """An OpenAI- or Anthropic-compatible chat endpoint (``/v1/chat/completions``, ``/v1/messages``).

    Use it when the app under test is reachable as a messages API: a model behind your system
    prompt, an LLM gateway, or an agent framework served through an OpenAI-compatible endpoint.
    Redgrade sends the forged conversation through the API's native fields: ``system`` turns,
    assistant ``tool_calls``, ``tool`` results, the attack's tool catalog as ``tools``. It reads
    the reply text and the tool calls the model requested (they are observed, not executed).

    ``system_prompt`` is the app's own system prompt (put the real one here, and parts of it in
    ``secrets``). Documents are inlined in the user message with ``documents_template``
    (``{documents}`` and ``{prompt}`` placeholders). Chat targets have no file-upload surface.
    """

    def __init__(
        self,
        url: str,
        *,
        api: ChatApi = CHAT_API_OPENAI,
        model: str | None = None,
        system_prompt: str | None = None,
        system_role: str = "system",
        documents_template: str = DEFAULT_CHAT_DOCUMENTS_TEMPLATE,
        extra_body: dict[str, JsonValue] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = DEFAULT_HTTP_TIMEOUT,
        client: httpx2.Client | None = None,
    ) -> None:
        if api not in (CHAT_API_OPENAI, CHAT_API_ANTHROPIC):
            raise TargetError(f"unknown chat api {api!r} (use 'openai' or 'anthropic')")
        headers = dict(headers or {})
        if api == CHAT_API_ANTHROPIC and not any(k.lower() == "anthropic-version" for k in headers):
            headers["anthropic-version"] = DEFAULT_ANTHROPIC_VERSION
        super().__init__(url, body={}, headers=headers, timeout=timeout, client=client)
        self.api = api
        self.model = model
        self.system_prompt = _expand_env(system_prompt) if system_prompt else None
        self.system_role = system_role
        self.documents_template = documents_template
        self.extra_body = dict(extra_body or {})

    @property
    def accepts_attachments(self) -> bool:
        return False

    @property
    def accepts_history(self) -> bool:
        return True

    @property
    def observes_tools(self) -> bool:
        return True

    def _user_content(self, prompt: str, documents: list[str]) -> str:
        if not documents:
            return prompt
        return self.documents_template.replace("{documents}", "\n\n".join(documents)).replace(
            "{prompt}", prompt
        )

    def build_payload(
        self,
        prompt: str,
        documents: list[str],
        history: list[HistoryMessage] | None = None,
        tools: list[JsonValue] | None = None,
    ) -> dict[str, JsonValue]:
        """The JSON body sent to the API (public so it can be inspected and tested)."""
        user = self._user_content(prompt, documents)
        payload: dict[str, JsonValue] = dict(self.extra_body)
        if self.model:
            payload["model"] = self.model
        if self.api == CHAT_API_ANTHROPIC:
            system, messages = anthropic_messages(history or [], user, system_prompt=self.system_prompt)
            payload["messages"] = cast(JsonValue, messages)
            if system:
                payload["system"] = system
            payload.setdefault("max_tokens", DEFAULT_ANTHROPIC_MAX_TOKENS)
            if tools:
                payload["tools"] = anthropic_tools(tools)
        else:
            payload["messages"] = cast(
                JsonValue,
                openai_messages(
                    history or [], user, system_prompt=self.system_prompt, system_role=self.system_role
                ),
            )
            if tools:
                payload["tools"] = openai_tools(tools)
        return payload

    def _parse(self, data: object) -> TargetObservation:
        if not isinstance(data, Mapping):
            raise TargetError("chat response is not a JSON object")
        if self.api == CHAT_API_ANTHROPIC:
            blocks = data["content"]
            if not isinstance(blocks, list):
                raise TargetError("anthropic response 'content' is not a list")
            calls = [
                ToolCall(
                    name=str(b["name"]),
                    arguments=cast(dict[str, JsonValue], b.get("input") or {}),
                    id=str(b.get("id", "")),
                )
                for b in blocks
                if isinstance(b, Mapping) and b.get("type") == "tool_use"
            ]
            return TargetObservation(output=_text_content(blocks), tools_called=tuple(calls))
        message = _dig(data, "choices.0.message")
        if not isinstance(message, Mapping):
            raise TargetError("openai response has no choices[0].message")
        calls = parse_tool_calls(message.get("tool_calls"))
        return TargetObservation(output=_text_content(message.get("content")), tools_called=tuple(calls))

    def __call__(
        self,
        prompt: str,
        documents: list[str],
        history: list[HistoryMessage] | None = None,
        tools: list[JsonValue] | None = None,
        attachments: list[Attachment] | None = None,
    ) -> TargetObservation:
        if attachments:
            raise TargetError("chat target has no attachments surface")
        payload = self.build_payload(prompt, documents, history, tools)
        try:
            response = self._client.post(self.url, json=payload, headers=self.headers)
            response.raise_for_status()
            return self._parse(response.json())
        except (httpx2.HTTPError, KeyError, IndexError, TypeError, ValueError, TargetError) as exc:
            raise TargetError(f"chat target failed: {exc}") from exc


class TargetFactory:
    """Build a callable target from a typed config block."""

    def build(self, config: TargetConfig | YamlMapping) -> Target:
        if isinstance(config, (FunctionTargetConfig, HttpTargetConfig, ChatTargetConfig)):
            parsed: FunctionTargetConfig | HttpTargetConfig | ChatTargetConfig = config
        else:
            raw = dict(config)
            kind = raw.get("type", TARGET_TYPE_FUNCTION)
            if kind == TARGET_TYPE_FUNCTION:
                parsed = FunctionTargetConfig.model_validate({**raw, "type": TARGET_TYPE_FUNCTION})
            elif kind == TARGET_TYPE_HTTP:
                parsed = HttpTargetConfig.model_validate({**raw, "type": TARGET_TYPE_HTTP})
            elif kind == TARGET_TYPE_CHAT:
                parsed = ChatTargetConfig.model_validate({**raw, "type": TARGET_TYPE_CHAT})
            else:
                raise TargetError(f"unknown target type {kind!r} (use 'function', 'http' or 'chat')")

        if isinstance(parsed, FunctionTargetConfig):
            return function_target(parsed.path)
        if isinstance(parsed, ChatTargetConfig):
            return ChatTarget(
                parsed.url,
                api=parsed.api,
                model=parsed.model,
                system_prompt=parsed.system_prompt,
                system_role=parsed.system_role,
                documents_template=parsed.documents_template,
                extra_body=parsed.extra_body,
                headers=parsed.headers,
                timeout=parsed.timeout,
            )
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

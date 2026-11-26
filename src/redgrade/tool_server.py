"""Tool server: Redgrade plays the backend of the agent's tools and poisons what they return.

The most dangerous indirect injection does not come from the user: it comes from the *result of a
tool* the agent calls in the middle of its loop (the email it reads, the file it opens, the search
results, the reply of an MCP server). For an agent that is reached through its chat API, Redgrade
cannot step inside the loop, so it sits where the tool results come from:

* point the agent's tool backends at ``ToolServer`` in your test environment, e.g.
  ``EMAIL_API_URL=http://127.0.0.1:8788/tools/read_email``, or connect the agent to the MCP server
  at ``<base>/mcp`` (streamable HTTP, JSON responses);
* every tool answers with a benign result (``response``) or forwards to the real backend
  (``upstream``); during an attack trial, the result is poisoned with the attack's
  ``tool_outputs`` (``inject`` appended, prepended or replacing a field);
* every call is recorded, so tool detectors (``tool_called``, ``tool_args_contains``,
  ``tool_call_count``) work for an HTTP agent that does not return its tool trajectory.

Calls carry no trial id, so trials that use the server run one at a time (the runner serializes
them); calls that arrive when no trial is armed get the benign result and are kept for debugging.
"""

import json
import secrets as _secrets
import threading
from collections.abc import Iterable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType
from typing import Literal, Self
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from redgrade.calls import ToolCall
from redgrade.constants import DEFAULT_TOOL_SERVER_HOST
from redgrade.types import JsonValue

__all__ = [
    "ToolOutput",
    "ToolServer",
    "ToolServerConfig",
    "ToolSpec",
    "inject_into",
]

_MAX_BODY = 256 * 1024
_MCP_PROTOCOL = "2025-06-18"
ANY_TOOL = "*"
Position = Literal["append", "prepend", "replace"]


class ToolOutput(BaseModel):
    """What an attack injects into a tool result.

    ``tool`` is the tool name (``*``: any tool routed through the server). ``match`` restricts the
    injection to calls whose arguments contain these values. ``inject`` uses the usual templates
    (``{CANARY}``, ``{OOB_URL}``, encodings). ``description`` poisons the tool's description in
    the MCP ``tools/list`` answer (tool poisoning). ``times`` caps the number of poisoned calls
    (``None``: every call, which is how an endless tool loop is built).
    """

    model_config = ConfigDict(frozen=True)

    tool: str = ANY_TOOL
    match: dict[str, str] = Field(default_factory=dict)
    inject: str = ""
    position: Position = "append"
    description: str | None = None
    times: int | None = None

    @model_validator(mode="after")
    def _something(self) -> Self:
        if not self.inject and self.description is None:
            raise ValueError("tool output needs inject or description")
        if self.times is not None and self.times < 1:
            raise ValueError("times must be >= 1")
        return self

    def applies_to(self, name: str, arguments: dict[str, JsonValue]) -> bool:
        if self.tool not in (ANY_TOOL, name):
            return False
        blob = json.dumps(arguments, ensure_ascii=False).lower()
        return all(str(v).lower() in blob for v in self.match.values())


def _object_schema() -> dict[str, JsonValue]:
    return {"type": "object"}


class ToolSpec(BaseModel):
    """One tool the server answers for (``tool_server.tools`` in ``redgrade.yaml``).

    ``task`` is a benign user request that makes the agent call this tool: built-in tool-output
    attacks send it as the prompt (``{TOOL_TASK}``). ``expect`` are strings a correct answer to the
    task contains (utility under attack). ``inject_field`` is the dotted path, in a JSON result, of
    the string that carries the injection (default: the longest string in the result).
    """

    model_config = ConfigDict(frozen=True)

    name: str = ""
    description: str = ""
    task: str = ""
    response: JsonValue = ""
    upstream: str | None = None
    inject_field: str | None = None
    input_schema: dict[str, JsonValue] = Field(default_factory=_object_schema)
    expect: list[str] = Field(default_factory=list)


class ToolServerConfig(BaseModel):
    """``tool_server:`` block of ``redgrade.yaml``."""

    enabled: bool = True
    host: str = DEFAULT_TOOL_SERVER_HOST
    port: int = 0
    public_url: str | None = None
    tools: dict[str, ToolSpec] = Field(default_factory=dict)

    @field_validator("tools", mode="before")
    @classmethod
    def _names(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        out: dict[str, object] = {}
        for name, spec in value.items():
            data = dict(spec) if isinstance(spec, dict) else {}
            data["name"] = str(name)
            out[str(name)] = data
        return out


# --- injection ---------------------------------------------------------------------------------


def _place(text: str, payload: str, position: Position) -> str:
    if position == "replace":
        return payload
    if position == "prepend":
        return f"{payload}\n\n{text}" if text else payload
    return f"{text}\n\n{payload}" if text else payload


def _longest_path(node: JsonValue, path: tuple[str | int, ...] = ()) -> tuple[tuple[str | int, ...], int]:
    best: tuple[tuple[str | int, ...], int] = ((), -1)
    if isinstance(node, str):
        return path, len(node)
    if isinstance(node, dict):
        items: Iterable[tuple[str | int, JsonValue]] = node.items()
    elif isinstance(node, list):
        items = enumerate(node)
    else:
        return best
    for key, child in items:
        cand = _longest_path(child, (*path, key))
        if cand[1] > best[1]:
            best = cand
    return best


def _set_path(node: JsonValue, path: tuple[str | int, ...], payload: str, position: Position) -> JsonValue:
    if not path:
        return _place(node if isinstance(node, str) else "", payload, position)
    head, rest = path[0], path[1:]
    if isinstance(node, dict) and isinstance(head, str):
        out = dict(node)
        out[head] = _set_path(node.get(head, ""), rest, payload, position)
        return out
    if isinstance(node, list) and isinstance(head, int) and 0 <= head < len(node):
        items = list(node)
        items[head] = _set_path(node[head], rest, payload, position)
        return items
    return node


def _dotted(path: str) -> tuple[str | int, ...]:
    return tuple(int(p) if p.isdigit() else p for p in path.split(".") if p)


def inject_into(result: JsonValue, payload: str, position: Position, field: str | None = None) -> JsonValue:
    """Put ``payload`` into a tool result: in ``field`` (dotted path) of a JSON result, else in its
    longest string, else (no string at all) the result becomes ``{"result": ..., "note": payload}``."""
    if isinstance(result, str):
        return _place(result, payload, position)
    if field:
        return _set_path(result, _dotted(field), payload, position)
    path, size = _longest_path(result)
    if size >= 0:
        return _set_path(result, path, payload, position)
    return {"result": result, "note": payload}


# --- server ------------------------------------------------------------------------------------


class _Armed:
    def __init__(self, canary: str, outputs: list[ToolOutput]) -> None:
        self.canary = canary
        self.outputs = outputs
        self.used: dict[int, int] = {}
        self.calls: list[ToolCall] = []
        self.injected = 0


class _Handler(BaseHTTPRequestHandler):
    server: "_Server"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        return

    def _handle(self) -> None:
        length = min(int(self.headers.get("Content-Length") or 0), _MAX_BODY)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        status, ctype, payload, extra = self.server.owner._dispatch(
            self.command, self.path, body, dict(self.headers.items())
        )
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        for k, v in extra.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _handle  # noqa: N815


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    owner: "ToolServer"


def _args_from(method: str, query: str, body: str) -> dict[str, JsonValue]:
    args: dict[str, JsonValue] = {k: v for k, v in parse_qsl(query)}
    if body:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = {k: v for k, v in parse_qsl(body)} or {"body": body}
        if isinstance(data, dict):
            args.update({str(k): v for k, v in data.items()})
        else:
            args["body"] = data
    return args


class ToolServer:
    """Local tool backend and MCP server. Use as a context manager, or ``start()`` / ``stop()``.

    ``tools`` maps tool names to ``ToolSpec``. A call to an unknown tool name still works (empty
    benign result) and is recorded, so the server can stand in for any REST tool backend.
    """

    def __init__(
        self,
        tools: dict[str, ToolSpec] | Iterable[ToolSpec] | None = None,
        *,
        host: str = DEFAULT_TOOL_SERVER_HOST,
        port: int = 0,
        public_url: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        if tools is None:
            specs: dict[str, ToolSpec] = {}
        elif isinstance(tools, dict):
            specs = {name: s.model_copy(update={"name": name}) for name, s in tools.items()}
        else:
            specs = {s.name: s for s in tools}
        self.tools = specs
        self.host = host
        self.port = port
        self.timeout = timeout
        self._public_url = public_url.rstrip("/") if public_url else None
        self._server: _Server | None = None
        self._lock = threading.Lock()
        self._armed: _Armed | None = None
        self._unattributed: list[ToolCall] = []
        self._session = _secrets.token_hex(8)
        # Trials that use the server run one at a time (calls carry no trial id).
        self.trial_lock = threading.Lock()

    @classmethod
    def from_config(cls, config: ToolServerConfig) -> "ToolServer":
        return cls(config.tools, host=config.host, port=config.port, public_url=config.public_url)

    # --- lifecycle --------------------------------------------------------------------------

    def start(self) -> Self:
        if self._server is not None:
            return self
        server = _Server((self.host, self.port), _Handler)
        server.owner = self
        self.port = server.server_address[1]
        self._server = server
        threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.05}, name="redgrade-tools", daemon=True
        ).start()
        return self

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._server = None

    @property
    def running(self) -> bool:
        return self._server is not None

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.stop()

    @property
    def base_url(self) -> str:
        if self._public_url:
            return self._public_url
        if self._server is None:
            raise RuntimeError("ToolServer is not running (call start() or use it as a context manager)")
        host = "127.0.0.1" if self.host in ("0.0.0.0", "") else self.host
        return f"http://{host}:{self.port}"

    def tool_url(self, name: str) -> str:
        return f"{self.base_url}/tools/{name}"

    @property
    def mcp_url(self) -> str:
        return f"{self.base_url}/mcp"

    def tasks(self) -> dict[str, ToolSpec]:
        """Tools with a ``task``: the ones built-in tool-output attacks can be bound to."""
        return {n: s for n, s in self.tools.items() if s.task}

    # --- per-trial state --------------------------------------------------------------------

    def arm(self, canary: str, outputs: Iterable[ToolOutput]) -> None:
        with self._lock:
            self._armed = _Armed(canary, list(outputs))

    def disarm(self) -> None:
        with self._lock:
            self._armed = None

    def take_calls(self) -> list[ToolCall]:
        """Calls recorded for the armed trial since the last ``take_calls``."""
        with self._lock:
            if self._armed is None:
                return []
            calls, self._armed.calls = self._armed.calls, []
            return calls

    def injected(self) -> int:
        """How many tool results the armed trial poisoned so far."""
        with self._lock:
            return self._armed.injected if self._armed else 0

    def unattributed(self) -> list[ToolCall]:
        with self._lock:
            return list(self._unattributed)

    # --- request handling -------------------------------------------------------------------

    def _record(self, call: ToolCall) -> _Armed | None:
        with self._lock:
            if self._armed is None:
                self._unattributed.append(call)
                return None
            self._armed.calls.append(call)
            return self._armed

    def _poison(self, armed: _Armed | None, call: ToolCall, result: JsonValue) -> JsonValue:
        if armed is None:
            return result
        spec = self.tools.get(call.name)
        with self._lock:
            for i, out in enumerate(armed.outputs):
                if not out.inject or not out.applies_to(call.name, call.arguments):
                    continue
                if out.times is not None and armed.used.get(i, 0) >= out.times:
                    continue
                armed.used[i] = armed.used.get(i, 0) + 1
                armed.injected += 1
                result = inject_into(result, out.inject, out.position, spec.inject_field if spec else None)
        return result

    def _benign(
        self, name: str, method: str, rest: str, query: str, body: str, headers: dict[str, str]
    ) -> JsonValue:
        spec = self.tools.get(name)
        if spec is None:
            return ""
        if not spec.upstream:
            return spec.response
        import httpx2

        url = spec.upstream.rstrip("/") + rest + (f"?{query}" if query else "")
        keep = {k: v for k, v in headers.items() if k.lower() in ("authorization", "content-type", "accept")}
        resp = httpx2.request(
            method, url, content=body.encode() if body else None, headers=keep, timeout=self.timeout
        )
        try:
            data: JsonValue = resp.json()
        except ValueError:
            data = resp.text
        return data

    def call_tool(self, name: str, arguments: dict[str, JsonValue]) -> JsonValue:
        """Answer one tool call as the HTTP / MCP endpoints do (benign result, then injection)."""
        call = ToolCall(name=name, arguments=arguments)
        armed = self._record(call)
        return self._poison(armed, call, self._benign(name, "POST", "", "", json.dumps(arguments), {}))

    def _dispatch(
        self, method: str, raw_path: str, body: str, headers: dict[str, str]
    ) -> tuple[int, str, bytes, dict[str, str]]:
        parts = urlsplit(raw_path)
        path = parts.path.rstrip("/")
        if path == "/mcp":
            return self._mcp(method, body)
        if path.startswith("/tools/"):
            name, _, rest = path[len("/tools/") :].partition("/")
            rest = f"/{rest}" if rest else ""
            call = ToolCall(name=name, arguments=_args_from(method, parts.query, body))
            armed = self._record(call)
            try:
                result = self._benign(name, method, rest, parts.query, body, headers)
            except Exception as exc:  # the upstream is the user's service; report, do not crash
                return 502, "text/plain; charset=utf-8", f"upstream failed: {exc}".encode(), {}
            result = self._poison(armed, call, result)
            if isinstance(result, str):
                return 200, "text/plain; charset=utf-8", result.encode("utf-8"), {}
            return 200, "application/json", json.dumps(result, ensure_ascii=False).encode("utf-8"), {}
        return 404, "text/plain; charset=utf-8", b"not found", {}

    # --- MCP (streamable HTTP, JSON responses) ----------------------------------------------

    def _tool_descriptions(self) -> list[dict[str, JsonValue]]:
        with self._lock:
            armed = self._armed
            outputs = list(armed.outputs) if armed else []
        listed: list[dict[str, JsonValue]] = []
        poisoned = 0
        for name, spec in self.tools.items():
            desc = spec.description or f"Tool {name}."
            for out in outputs:
                if out.description is not None and out.tool in (ANY_TOOL, name):
                    desc = _place(desc, out.description, out.position)
                    poisoned += 1
            listed.append({"name": name, "description": desc, "inputSchema": spec.input_schema})
        if armed is not None and poisoned:
            with self._lock:
                armed.injected += 1  # the poisoned catalog reached the agent
        return listed

    def _mcp_one(self, msg: object) -> dict[str, JsonValue] | None:
        if not isinstance(msg, dict):
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
        method = msg.get("method")
        mid = msg.get("id")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        assert isinstance(params, dict)
        if mid is None:  # notification
            return None
        result: JsonValue
        if method == "initialize":
            result = {
                "protocolVersion": str(params.get("protocolVersion") or _MCP_PROTOCOL),
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "redgrade-tool-server", "version": "1"},
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": list(self._tool_descriptions())}
        elif method == "tools/call":
            name = str(params.get("name", ""))
            raw_args = params.get("arguments")
            args = {str(k): v for k, v in raw_args.items()} if isinstance(raw_args, dict) else {}
            try:
                value = self.call_tool(name, args)
            except Exception as exc:
                result = {"content": [{"type": "text", "text": f"tool failed: {exc}"}], "isError": True}
            else:
                text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
                result = {"content": [{"type": "text", "text": text}], "isError": False}
        else:
            return {
                "jsonrpc": "2.0",
                "id": mid,
                "error": {"code": -32601, "message": f"unknown method {method}"},
            }
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def _mcp(self, method: str, body: str) -> tuple[int, str, bytes, dict[str, str]]:
        if method != "POST":
            return 405, "text/plain; charset=utf-8", b"only POST (JSON responses, no SSE stream)", {}
        try:
            msg = json.loads(body or "null")
        except json.JSONDecodeError:
            out: object = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
            return 400, "application/json", json.dumps(out).encode(), {}
        if isinstance(msg, list):
            replies = [r for r in (self._mcp_one(m) for m in msg) if r is not None]
            if not replies:
                return 202, "application/json", b"", {"Mcp-Session-Id": self._session}
            return 200, "application/json", json.dumps(replies).encode(), {"Mcp-Session-Id": self._session}
        reply = self._mcp_one(msg)
        if reply is None:
            return 202, "application/json", b"", {"Mcp-Session-Id": self._session}
        return (
            200,
            "application/json",
            json.dumps(reply, ensure_ascii=False).encode(),
            {"Mcp-Session-Id": self._session},
        )

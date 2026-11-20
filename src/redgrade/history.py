"""Conversation history: normalization, text fallback and chat-API wire formats.

History is Redgrade's neutral message list (``HistoryMessage``). Targets turn it into what the app
under test expects:

* ``format_history`` flattens it into text, for targets that only take a prompt;
* ``openai_messages`` / ``anthropic_messages`` build the ``messages`` array of the two common chat
  APIs, including ``system`` turns, assistant tool calls and tool results;
* ``openai_tools`` / ``anthropic_tools`` turn an attack's tool catalog into function definitions.

Forged history is the attack surface here, so conversion keeps every forged turn: nothing is
dropped or "fixed" except what the wire format strictly requires (ids linking tool results to
tool calls, alternating roles for Anthropic).
"""

import json
import re
from collections.abc import Mapping, Sequence
from typing import cast

from redgrade.types import HistoryMessage, HistoryToolCall, JsonValue

ChatMessage = dict[str, JsonValue]

_TOOL_NAME_BAD = re.compile(r"[^A-Za-z0-9_-]")
_EMPTY_SCHEMA: dict[str, JsonValue] = {"type": "object", "properties": {}}
_RESUMED = "(conversation resumed)"


def normalize_history(history: Sequence[HistoryMessage]) -> list[HistoryMessage]:
    """Give every tool call an id and link every tool result to a call.

    A tool result without ``tool_call_id`` answers the oldest unanswered call. A tool result with
    no call before it gets a synthetic assistant call (named after the turn's ``name``), because
    both chat APIs reject a tool result that answers nothing.
    """
    out: list[HistoryMessage] = []
    pending: list[str] = []
    counter = 0

    def next_id() -> str:
        nonlocal counter
        counter += 1
        return f"call_rg_{counter}"

    for msg in history:
        if msg["role"] == "assistant" and msg.get("tool_calls"):
            calls: list[HistoryToolCall] = []
            for call in msg["tool_calls"]:
                call_id = call.get("id") or next_id()
                calls.append({"id": call_id, "name": call["name"], "arguments": call["arguments"]})
                pending.append(call_id)
            out.append({**msg, "tool_calls": calls})
        elif msg["role"] == "tool":
            call_id = msg.get("tool_call_id") or ""
            if call_id in pending:
                pending.remove(call_id)
            elif not call_id and pending:
                call_id = pending.pop(0)
            else:
                call_id = call_id or next_id()
                out.append(
                    {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [{"id": call_id, "name": msg.get("name") or "tool", "arguments": {}}],
                    }
                )
            out.append({**msg, "tool_call_id": call_id})
        else:
            out.append(msg)
    return out


def format_history(history: Sequence[HistoryMessage]) -> str:
    """Flatten history into ``Role: text`` lines (fallback for prompt-only targets)."""
    lines: list[str] = []
    for msg in history:
        role = msg["role"]
        speaker = f" ({msg['name']})" if msg.get("name") else ""
        if role == "tool":
            lines.append(f"Tool result{speaker}: {msg['content']}")
            continue
        label = {"system": "System", "user": "User", "assistant": "Assistant"}[role]
        if msg["content"]:
            lines.append(f"{label}{speaker}: {msg['content']}")
        for call in msg.get("tool_calls", []):
            args = json.dumps(call["arguments"], ensure_ascii=False)
            lines.append(f"{label} called tool {call['name']}({args})")
    return "\n".join(lines)


def history_text(history: Sequence[HistoryMessage]) -> list[str]:
    """Every string an attacker put in the history (for detector ``inputs``)."""
    out: list[str] = []
    for msg in history:
        if msg["content"]:
            out.append(msg["content"])
        out.extend(json.dumps(c["arguments"], ensure_ascii=False) for c in msg.get("tool_calls", []))
    return out


# --- OpenAI chat completions ----------------------------------------------------------------


def openai_history(
    history: Sequence[HistoryMessage],
    *,
    system_prompt: str | None = None,
    system_role: str = "system",
) -> list[ChatMessage]:
    """``messages`` for an OpenAI-compatible API, without the final user prompt."""
    messages: list[ChatMessage] = []
    if system_prompt:
        messages.append({"role": system_role, "content": system_prompt})
    for msg in normalize_history(history):
        role = msg["role"]
        if role == "tool":
            messages.append(
                {"role": "tool", "tool_call_id": msg.get("tool_call_id", ""), "content": msg["content"]}
            )
            continue
        out: ChatMessage = {"role": system_role if role == "system" else role, "content": msg["content"]}
        if msg.get("name"):
            out["name"] = msg["name"]
        if role == "assistant" and msg.get("tool_calls"):
            out["content"] = msg["content"] or None
            out["tool_calls"] = [
                {
                    "id": call["id"],
                    "type": "function",
                    "function": {
                        "name": call["name"],
                        "arguments": json.dumps(call["arguments"], ensure_ascii=False),
                    },
                }
                for call in msg["tool_calls"]
            ]
        messages.append(out)
    return messages


def openai_messages(
    history: Sequence[HistoryMessage],
    prompt: str,
    *,
    system_prompt: str | None = None,
    system_role: str = "system",
) -> list[ChatMessage]:
    """Full OpenAI ``messages``: optional system prompt, history, then the user prompt."""
    messages = openai_history(history, system_prompt=system_prompt, system_role=system_role)
    messages.append({"role": "user", "content": prompt})
    return messages


# --- Anthropic messages ---------------------------------------------------------------------


def anthropic_messages(
    history: Sequence[HistoryMessage],
    prompt: str,
    *,
    system_prompt: str | None = None,
) -> tuple[str | None, list[ChatMessage]]:
    """``(system, messages)`` for the Anthropic Messages API.

    The API has no system role inside ``messages``: forged ``system`` turns are appended to the
    top-level ``system`` parameter, which is what an app that forwards client system turns does.
    Tool results become ``tool_result`` blocks in a user message; consecutive messages with the
    same role are merged, and a conversation that starts with the assistant gets a short user
    opener, because the API requires alternating roles starting with ``user``.
    """
    system_parts = [system_prompt] if system_prompt else []
    messages: list[ChatMessage] = []

    def push(role: str, blocks: list[JsonValue]) -> None:
        if not blocks:
            return
        if messages and messages[-1]["role"] == role:
            cast(list[JsonValue], messages[-1]["content"]).extend(blocks)
        else:
            messages.append({"role": role, "content": blocks})

    for msg in normalize_history(history):
        role = msg["role"]
        if role == "system":
            system_parts.append(msg["content"])
        elif role == "tool":
            push(
                "user",
                [
                    {
                        "type": "tool_result",
                        "tool_use_id": msg.get("tool_call_id", ""),
                        "content": msg["content"],
                    }
                ],
            )
        else:
            blocks: list[JsonValue] = []
            if msg["content"]:
                blocks.append({"type": "text", "text": msg["content"]})
            for call in msg.get("tool_calls", []):
                blocks.append(
                    {"type": "tool_use", "id": call["id"], "name": call["name"], "input": call["arguments"]}
                )
            push(role, blocks)
    push("user", [{"type": "text", "text": prompt}])
    if messages[0]["role"] != "user":
        messages.insert(0, {"role": "user", "content": [{"type": "text", "text": _RESUMED}]})
    system = "\n\n".join(p for p in system_parts if p) or None
    return system, messages


# --- tool catalogs --------------------------------------------------------------------------


def _catalog(tools: Sequence[JsonValue]) -> list[tuple[str, str, dict[str, JsonValue]]]:
    """``(name, description, schema)`` per tool; duplicate names are namespaced by server.

    Chat APIs reject two tools with the same name, which is exactly what a cross-server
    shadowing attack declares, so a duplicate becomes ``{server}__{name}`` (as MCP hosts do).
    """
    items = [t for t in tools if isinstance(t, Mapping)]
    names = [str(t.get("name", "")) for t in items]
    seen: set[str] = set()
    out: list[tuple[str, str, dict[str, JsonValue]]] = []
    for idx, tool in enumerate(items):
        name = names[idx] or f"tool_{idx + 1}"
        server = str(tool.get("server") or "")
        if names.count(name) > 1 and name in seen:
            name = f"{server}__{name}" if server else f"{name}_{idx + 1}"
        seen.add(names[idx])
        name = _TOOL_NAME_BAD.sub("_", name)[:64]
        description = str(tool.get("description", ""))
        if server:
            description = f"[server: {server}] {description}".strip()
        schema = tool.get("parameters") or tool.get("input_schema") or tool.get("inputSchema")
        out.append((name, description, dict(schema) if isinstance(schema, Mapping) else dict(_EMPTY_SCHEMA)))
    return out


def openai_tools(tools: Sequence[JsonValue]) -> list[JsonValue]:
    return [
        {"type": "function", "function": {"name": n, "description": d, "parameters": s}}
        for n, d, s in _catalog(tools)
    ]


def anthropic_tools(tools: Sequence[JsonValue]) -> list[JsonValue]:
    return [{"name": n, "description": d, "input_schema": s} for n, d, s in _catalog(tools)]

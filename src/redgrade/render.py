"""Template rendering for attack payloads."""

import base64
import codecs
import re
from typing import cast

from redgrade.attachments import Attachment, AttachmentSpec, build_attachment
from redgrade.constants import TEMPLATE_OOB_URL
from redgrade.history import format_history
from redgrade.identity import expand_identity
from redgrade.models import Attack, AttackTurn
from redgrade.mutations import materialize
from redgrade.oob import Fixture, current_oob_base
from redgrade.tool_server import ToolOutput
from redgrade.types import HistoryMessage, HistoryToolCall, JsonValue

__all__ = [
    "format_history",
    "oob_url",
    "render",
    "render_attack",
    "render_fixtures",
    "render_history",
    "render_tool_outputs",
    "render_tools",
    "render_turns",
]

_ENC = re.compile(r"\{(b64|rot13):(.+?)\}", re.DOTALL)


def _encode(match: re.Match[str]) -> str:
    kind, text = match.group(1), match.group(2)
    if kind == "b64":
        return base64.b64encode(text.encode()).decode()
    return codecs.encode(text, "rot13")


def oob_url(canary: str) -> str:
    """This trial's attacker URL: ``<collector base>/t/<canary>`` (see ``redgrade.oob``)."""
    return f"{current_oob_base()}/t/{canary}"


def render(template: str, canary: str) -> str:
    """Substitute ``{OOB_URL}``, identity placeholders and the canary, then apply encodings and
    L4 mutation markers."""
    if TEMPLATE_OOB_URL in template:
        template = template.replace(TEMPLATE_OOB_URL, oob_url(canary))
    template = expand_identity(template)
    return materialize(_ENC.sub(_encode, template.replace("{CANARY}", canary)))


def render_json(node: JsonValue, canary: str) -> JsonValue:
    """Recursively substitute canary / encodings in a JSON-like tools catalog."""
    if isinstance(node, str):
        return render(node, canary)
    if isinstance(node, list):
        return [render_json(x, canary) for x in node]
    if isinstance(node, dict):
        return {str(k): render_json(v, canary) for k, v in node.items()}
    return node


def render_tools(attack: Attack, canary: str) -> list[JsonValue]:
    return [render_json(t, canary) for t in attack.tools]


def render_history(attack: Attack, canary: str) -> list[HistoryMessage]:
    """The attack's forged history with ``{CANARY}`` / encodings rendered, as wire messages."""
    out: list[HistoryMessage] = []
    for turn in attack.history:
        msg: HistoryMessage = {"role": turn.role, "content": render(turn.content, canary)}
        if turn.name:
            msg["name"] = render(turn.name, canary)
        if turn.tool_call_id:
            msg["tool_call_id"] = turn.tool_call_id
        if turn.tool_calls:
            calls: list[HistoryToolCall] = []
            for call in turn.tool_calls:
                args = cast(dict[str, JsonValue], render_json(dict(call.arguments), canary))
                calls.append({"id": call.id, "name": call.name, "arguments": args})
            msg["tool_calls"] = calls
        out.append(msg)
    return out


def render_turn(turn: AttackTurn, canary: str) -> tuple[str, list[str]]:
    prompt = render(turn.prompt, canary)
    documents = [render(d, canary) for d in turn.documents]
    return prompt, documents


def render_turns(attack: Attack, canary: str) -> list[tuple[str, list[str]]]:
    return [render_turn(t, canary) for t in attack.turns]


def render_attack(attack: Attack, canary: str) -> tuple[str, list[str]]:
    """Return ``(user_prompt, documents)`` for one trial."""
    if attack.turns:
        raise ValueError(f"attack {attack.id} is multi-turn; use render_turns")
    prompt = render(attack.prompt, canary)
    documents: list[str] = []
    if attack.document:
        documents.append(render(attack.document, canary))
    documents.extend(render(d, canary) for d in attack.documents)
    return prompt, documents


def render_fixtures(attack: Attack, canary: str) -> list[Fixture]:
    """Attacker pages for one trial, with ``{OOB_URL}`` / ``{CANARY}`` rendered in their body."""
    return [f.model_copy(update={"body": render(f.body, canary)}) for f in attack.fixtures]


def render_tool_outputs(attack: Attack, canary: str) -> list[ToolOutput]:
    """Tool-result injections for one trial, with ``{CANARY}`` / ``{OOB_URL}`` / encodings rendered."""
    return [
        o.model_copy(
            update={
                "inject": render(o.inject, canary) if o.inject else "",
                "description": render(o.description, canary) if o.description is not None else None,
            }
        )
        for o in attack.tool_outputs
    ]


def render_attachments(specs: tuple[AttachmentSpec, ...], canary: str) -> list[Attachment]:
    """Render ``{CANARY}`` / encodings in each spec, then build the real files."""
    return [
        build_attachment(
            spec.model_copy(
                update={
                    "payload": render(spec.payload, canary),
                    "visible": render(spec.visible, canary),
                    "filename": render(spec.filename, canary),
                }
            )
        )
        for spec in specs
    ]


def attachments_text(attachments: list[Attachment]) -> list[str]:
    """Text the target may see from the files (body text and metadata), for detector inputs."""
    return [t for a in attachments for t in (a.text, a.metadata) if t]

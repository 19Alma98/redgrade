"""Template rendering for attack payloads."""

import base64
import codecs
import re
from typing import cast

from redgrade.attachments import Attachment, AttachmentSpec, build_attachment
from redgrade.models import Attack, AttackTurn
from redgrade.types import HistoryMessage, JsonValue

_ENC = re.compile(r"\{(b64|rot13):(.+?)\}", re.DOTALL)


def _encode(match: re.Match[str]) -> str:
    kind, text = match.group(1), match.group(2)
    if kind == "b64":
        return base64.b64encode(text.encode()).decode()
    return codecs.encode(text, "rot13")


def render(template: str, canary: str) -> str:
    """Substitute the canary, then apply encodings."""
    return _ENC.sub(_encode, template.replace("{CANARY}", canary))


def render_json(node: JsonValue, canary: str) -> JsonValue:
    """Recursively substitute canary / encodings in a JSON-like tools catalog."""
    if isinstance(node, str):
        return render(node, canary)
    if isinstance(node, list):
        return [render_json(x, canary) for x in node]
    if isinstance(node, dict):
        return {str(k): render_json(cast(JsonValue, v), canary) for k, v in node.items()}
    return node


def render_tools(attack: Attack, canary: str) -> list[JsonValue]:
    return [render_json(t, canary) for t in attack.tools]


def format_history(history: list[HistoryMessage]) -> str:
    lines: list[str] = []
    for msg in history:
        label = "User" if msg["role"] == "user" else "Assistant"
        lines.append(f"{label}: {msg['content']}")
    return "\n".join(lines)


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

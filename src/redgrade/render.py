"""Template rendering for attack payloads."""

import base64
import codecs
import re

from redgrade.models import Attack, AttackTurn
from redgrade.types import HistoryMessage

_ENC = re.compile(r"\{(b64|rot13):(.+?)\}", re.DOTALL)


def _encode(match: re.Match[str]) -> str:
    kind, text = match.group(1), match.group(2)
    if kind == "b64":
        return base64.b64encode(text.encode()).decode()
    return codecs.encode(text, "rot13")


def render(template: str, canary: str) -> str:
    """Substitute the canary, then apply encodings."""
    return _ENC.sub(_encode, template.replace("{CANARY}", canary))


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
    documents = [render(attack.document, canary)] if attack.document else []
    return prompt, documents

"""Template rendering for attack payloads."""

from __future__ import annotations

import base64
import codecs
import re

from redgrade.models import Attack

_ENC = re.compile(r"\{(b64|rot13):(.+?)\}", re.DOTALL)


def _encode(match: re.Match[str]) -> str:
    kind, text = match.group(1), match.group(2)
    if kind == "b64":
        return base64.b64encode(text.encode()).decode()
    return codecs.encode(text, "rot13")


def render(template: str, canary: str) -> str:
    """Substitute the canary, then apply encodings."""
    return _ENC.sub(_encode, template.replace("{CANARY}", canary))


def render_attack(attack: Attack, canary: str) -> tuple[str, list[str]]:
    """Return ``(user_prompt, documents)`` for one trial."""
    prompt = render(attack.prompt, canary)
    documents = [render(attack.document, canary)] if attack.document else []
    return prompt, documents

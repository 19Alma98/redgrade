"""Attacks back to pack entries: what ``promote`` writes and ``replay`` reads.

A finding carries its attack as a pack entry (``Finding.attack_spec``): the exact templates that
got through (``{CANARY}`` and the other placeholders kept), so the scan JSON alone is enough to
replay a finding after a fix or to freeze it into the CI regression pack.
"""

from redgrade.deep.meta import WinningSeed
from redgrade.models import Attack
from redgrade.types import JsonValue

__all__ = ["attack_to_pack_dict", "seed_to_pack_dict"]

# Fields the pack loader infers (or that only exist on expanded attacks) and never needs.
_DROP = {"delivery", "mutations", "has_attachments"}


def attack_to_pack_dict(attack: Attack) -> dict[str, JsonValue]:
    """A pack entry that loads back into the same attack (without re-expanding mutations)."""
    data: dict[str, JsonValue] = attack.model_dump(mode="json", exclude_defaults=True)
    for key in _DROP:
        data.pop(key, None)
    # Always explicit, so the entry reads on its own.
    for key in ("id", "family", "title", "owasp", "severity", "detector"):
        data[key] = getattr(attack, key)
    if attack.turns:
        data.pop("prompt", None)
        data["turns"] = [
            {
                k: v
                for k, v in t.model_dump(mode="json", exclude_defaults=True).items()
                if k in ("prompt", "documents", "attachments", "new_session")
            }
            | {"prompt": t.prompt}
            for t in attack.turns
        ]
    # A forged history makes ``requires_history`` default to true on load: keep the original.
    if attack.history:
        data["requires_history"] = attack.requires_history
    return data


def seed_to_pack_dict(seed: WinningSeed, attack: Attack) -> dict[str, JsonValue]:
    """An adaptive win as a pack entry, with the family and severity of the attack it rewrote."""
    data: dict[str, JsonValue] = {
        "id": attack.id,
        "family": attack.family,
        "title": attack.title,
        "owasp": attack.owasp,
        "severity": attack.severity,
        "level": seed.level,
        "technique": f"adaptive_{seed.strategy}",
        "detector": seed.detector,
        "prompt": seed.prompt,
    }
    if seed.documents:
        data["documents"] = list(seed.documents)
    if seed.history:
        data["history"] = [dict(m) for m in seed.history]
    return data

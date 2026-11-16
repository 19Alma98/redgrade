"""Load attack packs (YAML) shipped with Redgrade or provided by the user."""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from redgrade.detectors import DETECTORS
from redgrade.families import FAMILY_BY_ID
from redgrade.models import SEVERITIES, Attack


class PackError(Exception):
    """A pack file is malformed."""


def _parse_pack(data: Any, origin: str) -> list[Attack]:
    if not isinstance(data, dict) or "attacks" not in data:
        raise PackError(f"{origin}: expected a mapping with an 'attacks' list")
    family = data.get("family")
    default_owasp = data.get("owasp") or (FAMILY_BY_ID[family].owasp if family in FAMILY_BY_ID else "")
    attacks: list[Attack] = []
    for raw in data["attacks"]:
        try:
            attack = Attack(
                id=str(raw["id"]),
                family=str(raw.get("family", family)),
                title=str(raw["title"]),
                owasp=str(raw.get("owasp", default_owasp)),
                severity=str(raw.get("severity", "medium")),
                prompt=str(raw["prompt"]),
                detector=str(raw["detector"]),
                delivery="document" if raw.get("document") else "direct",
                document=raw.get("document"),
                detector_args=dict(raw.get("detector_args", {})),
                requires_secrets=bool(raw.get("requires_secrets", False)),
                description=str(raw.get("description", "")),
            )
        except KeyError as exc:
            raise PackError(f"{origin}: attack is missing field {exc}") from exc
        if attack.family == "None" or not attack.family:
            raise PackError(f"{origin}: attack {attack.id} has no family")
        if attack.severity not in SEVERITIES:
            raise PackError(f"{origin}: {attack.id} severity must be one of {SEVERITIES}")
        if attack.detector not in DETECTORS:
            raise PackError(f"{origin}: {attack.id} unknown detector {attack.detector!r}")
        attacks.append(attack)
    return attacks


def load_builtin_attacks() -> list[Attack]:
    attacks: list[Attack] = []
    for entry in sorted(resources.files("redgrade.packs").iterdir(), key=lambda p: p.name):
        if entry.name.endswith(".yaml"):
            attacks += _parse_pack(yaml.safe_load(entry.read_text(encoding="utf-8")), entry.name)
    return attacks


def load_pack_file(path: str | Path) -> list[Attack]:
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PackError(f"cannot read pack {path}: {exc}") from exc
    return _parse_pack(data, str(path))


def load_attacks(
    *,
    extra_packs: list[str] | None = None,
    families: list[str] | None = None,
    ids: list[str] | None = None,
) -> list[Attack]:
    attacks = load_builtin_attacks()
    for pack in extra_packs or []:
        attacks += load_pack_file(pack)
    seen: set[str] = set()
    for attack in attacks:
        if attack.id in seen:
            raise PackError(f"duplicate attack id {attack.id}")
        seen.add(attack.id)
    if families:
        unknown = set(families) - set(FAMILY_BY_ID)
        if unknown:
            raise PackError(f"unknown families: {', '.join(sorted(unknown))}")
        attacks = [a for a in attacks if a.family in families]
    if ids:
        attacks = [a for a in attacks if a.id in ids]
    return attacks

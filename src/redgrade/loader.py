"""Load attack packs (YAML) shipped with Redgrade or provided by the user."""

from importlib import resources
from pathlib import Path

import yaml
from pydantic import ValidationError

from redgrade.constants import (
    DEFAULT_SEVERITY,
    DELIVERY_DIRECT,
    DELIVERY_DOCUMENT,
    SEVERITIES,
)
from redgrade.detectors import DETECTORS
from redgrade.families import FAMILY_BY_ID
from redgrade.models import Attack
from redgrade.types import DetectorArgs


class PackError(Exception):
    """A pack file is malformed."""


class PackLoader:
    """Parse and validate attack pack YAML into ``Attack`` models."""

    def parse(self, data: object, origin: str) -> list[Attack]:
        if not isinstance(data, dict) or "attacks" not in data:
            raise PackError(f"{origin}: expected a mapping with an 'attacks' list")
        family = data.get("family")
        default_owasp = data.get("owasp") or (FAMILY_BY_ID[family].owasp if family in FAMILY_BY_ID else "")
        attacks: list[Attack] = []
        for raw in data["attacks"]:
            if not isinstance(raw, dict):
                raise PackError(f"{origin}: each attack must be a mapping")
            try:
                args_raw = raw.get("detector_args", {})
                if args_raw is None:
                    args_raw = {}
                if not isinstance(args_raw, dict):
                    raise PackError(f"{origin}: detector_args must be a mapping")
                detector_args: DetectorArgs = dict(args_raw)
                raw_turns = raw.get("turns")
                if raw_turns is not None:
                    if raw.get("prompt") is not None:
                        raise PackError(f"{origin}: {raw.get('id')}: cannot set both prompt and turns")
                    if not isinstance(raw_turns, list) or len(raw_turns) < 2:
                        raise PackError(f"{origin}: {raw.get('id')}: turns must be a list of at least 2 items")
                    turns: list[dict] = []
                    any_docs = False
                    for i, t in enumerate(raw_turns):
                        if not isinstance(t, dict) or "prompt" not in t:
                            raise PackError(f"{origin}: {raw.get('id')}: turn {i} needs prompt")
                        docs: list[str] = []
                        if t.get("document") is not None:
                            docs.append(str(t["document"]))
                        extra = t.get("documents") or []
                        if not isinstance(extra, list):
                            raise PackError(f"{origin}: {raw.get('id')}: turn documents must be a list")
                        docs.extend(str(x) for x in extra)
                        any_docs = any_docs or bool(docs)
                        turns.append({"prompt": str(t["prompt"]), "documents": docs})
                    detect_on = str(raw.get("detect_on", "last"))
                    if detect_on not in ("last", "any"):
                        raise PackError(f"{origin}: {raw.get('id')}: detect_on must be 'last' or 'any'")
                    delivery = DELIVERY_DOCUMENT if any_docs else DELIVERY_DIRECT
                    attack = Attack.model_validate(
                        {
                            "id": str(raw["id"]),
                            "family": str(raw.get("family", family)),
                            "title": str(raw["title"]),
                            "owasp": str(raw.get("owasp", default_owasp)),
                            "severity": str(raw.get("severity", DEFAULT_SEVERITY)),
                            "prompt": "",
                            "turns": turns,
                            "detect_on": detect_on,
                            "detector": str(raw["detector"]),
                            "delivery": delivery,
                            "document": None,
                            "detector_args": detector_args,
                            "requires_secrets": bool(raw.get("requires_secrets", False)),
                            "description": str(raw.get("description", "")),
                        }
                    )
                else:
                    delivery = DELIVERY_DOCUMENT if raw.get("document") else DELIVERY_DIRECT
                    document = raw.get("document")
                    attack = Attack.model_validate(
                        {
                            "id": str(raw["id"]),
                            "family": str(raw.get("family", family)),
                            "title": str(raw["title"]),
                            "owasp": str(raw.get("owasp", default_owasp)),
                            "severity": str(raw.get("severity", DEFAULT_SEVERITY)),
                            "prompt": str(raw["prompt"]),
                            "detector": str(raw["detector"]),
                            "delivery": delivery,
                            "document": None if document is None else str(document),
                            "detector_args": detector_args,
                            "requires_secrets": bool(raw.get("requires_secrets", False)),
                            "description": str(raw.get("description", "")),
                        }
                    )
            except KeyError as exc:
                raise PackError(f"{origin}: attack is missing field {exc}") from exc
            except ValidationError as exc:
                raise PackError(f"{origin}: {exc}") from exc
            if attack.family == "None" or not attack.family:
                raise PackError(f"{origin}: attack {attack.id} has no family")
            if attack.severity not in SEVERITIES:
                raise PackError(f"{origin}: {attack.id} severity must be one of {SEVERITIES}")
            if attack.detector not in DETECTORS:
                raise PackError(f"{origin}: {attack.id} unknown detector {attack.detector!r}")
            attacks.append(attack)
        return attacks

    def load_builtin(self) -> list[Attack]:
        attacks: list[Attack] = []
        for entry in sorted(resources.files("redgrade.packs").iterdir(), key=lambda p: p.name):
            if entry.name.endswith(".yaml"):
                attacks += self.parse(yaml.safe_load(entry.read_text(encoding="utf-8")), entry.name)
        return attacks

    def load_file(self, path: str | Path) -> list[Attack]:
        path = Path(path)
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise PackError(f"cannot read pack {path}: {exc}") from exc
        return self.parse(data, str(path))

    def load(
        self,
        *,
        extra_packs: list[str] | None = None,
        families: list[str] | None = None,
        ids: list[str] | None = None,
    ) -> list[Attack]:
        attacks = self.load_builtin()
        for pack in extra_packs or []:
            attacks += self.load_file(pack)
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


def load_builtin_attacks() -> list[Attack]:
    return PackLoader().load_builtin()


def load_pack_file(path: str | Path) -> list[Attack]:
    return PackLoader().load_file(path)


def load_attacks(
    *,
    extra_packs: list[str] | None = None,
    families: list[str] | None = None,
    ids: list[str] | None = None,
) -> list[Attack]:
    return PackLoader().load(extra_packs=extra_packs, families=families, ids=ids)

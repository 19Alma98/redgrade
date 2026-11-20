"""Load attack packs (YAML) shipped with Redgrade or provided by the user."""

from importlib import resources
from pathlib import Path

import yaml
from pydantic import ValidationError

from redgrade.attachments import AttachmentSpec
from redgrade.constants import (
    DEFAULT_SEVERITY,
    DELIVERY_DIRECT,
    DELIVERY_DOCUMENT,
    DETECT_ON_ANY,
    DETECT_ON_LAST,
    DETECTOR_OOB_CALLBACK,
    SEVERITIES,
    TEMPLATE_OOB_URL,
)
from redgrade.detectors import DETECTORS
from redgrade.families import FAMILY_BY_ID
from redgrade.models import Attack
from redgrade.mutations import MutationExpander
from redgrade.types import DetectorArgs


class PackError(Exception):
    """A pack file is malformed."""


class PackLoader:
    """Parse and validate attack pack YAML into ``Attack`` models."""

    def _pack_attack_fields(self, raw: dict[str, object], origin: str, attack_id: str) -> dict[str, object]:
        extra: dict[str, object] = {}
        if "level" in raw:
            extra["level"] = raw["level"]
        if "technique" in raw:
            extra["technique"] = str(raw["technique"])
        if "compliance" in raw:
            comp = raw["compliance"]
            if not isinstance(comp, dict) or not all(isinstance(v, list) for v in comp.values()):
                raise PackError(f"{origin}: {attack_id}: compliance must map framework -> list of controls")
            extra["compliance"] = {str(k): tuple(str(x) for x in v) for k, v in comp.items()}
        if "advisory" in raw:
            extra["advisory"] = bool(raw["advisory"])
        if "mutate_scope" in raw:
            extra["mutate_scope"] = str(raw["mutate_scope"])
        if "mutations" in raw:
            mut = raw["mutations"]
            if not isinstance(mut, list):
                raise PackError(f"{origin}: {attack_id}: mutations must be a list")
            extra["mutations"] = tuple(str(x) for x in mut)
        return extra

    def _parse_attachments(
        self, raw: dict[str, object], origin: str, attack_id: str
    ) -> tuple[AttachmentSpec, ...]:
        items = raw.get("attachments")
        if items is None:
            return ()
        if not isinstance(items, list):
            raise PackError(f"{origin}: {attack_id}: attachments must be a list")
        specs: list[AttachmentSpec] = []
        for item in items:
            if not isinstance(item, dict):
                raise PackError(f"{origin}: {attack_id}: each attachment must be a mapping")
            try:
                specs.append(AttachmentSpec.model_validate({k: str(v) for k, v in item.items()}))
            except ValidationError as exc:
                raise PackError(f"{origin}: {attack_id}: {exc}") from exc
        return tuple(specs)

    def _parse_tools(self, raw: dict[str, object], origin: str, attack_id: str) -> tuple[object, ...]:
        tools = raw.get("tools")
        if tools is None:
            return ()
        if not isinstance(tools, list):
            raise PackError(f"{origin}: {attack_id}: tools must be a list")
        return tuple(tools)

    def _parse_history(self, raw: dict[str, object], origin: str, attack_id: str) -> dict[str, object]:
        """``history`` (forged conversation) and ``requires_history`` (default: true when set)."""
        items = raw.get("history")
        if items is None:
            if raw.get("requires_history"):
                raise PackError(f"{origin}: {attack_id}: requires_history needs a history list")
            return {}
        if not isinstance(items, list) or not items:
            raise PackError(f"{origin}: {attack_id}: history must be a non-empty list")
        turns: list[object] = []
        for i, item in enumerate(items):
            if not isinstance(item, dict) or "role" not in item:
                raise PackError(f"{origin}: {attack_id}: history item {i} must be a mapping with a role")
            turns.append(item)
        return {"history": turns, "requires_history": bool(raw.get("requires_history", True))}

    def _parse_oob(self, raw: dict[str, object], origin: str, attack_id: str) -> dict[str, object]:
        """``fixtures`` plus ``requires_oob`` / ``requires_fetch``, inferred when not set.

        An attack needs the out-of-band collector when it serves fixtures, mentions ``{OOB_URL}``
        anywhere, or uses the ``oob_callback`` detector. It needs a fetch when it has fixtures.
        """
        items = raw.get("fixtures")
        if items is not None and (not isinstance(items, list) or not items):
            raise PackError(f"{origin}: {attack_id}: fixtures must be a non-empty list")
        fixtures: list[object] = []
        for i, item in enumerate(items or []):
            if not isinstance(item, dict) or "path" not in item or "body" not in item:
                raise PackError(f"{origin}: {attack_id}: fixture {i} needs path and body")
            fixtures.append(item)
        uses_url = TEMPLATE_OOB_URL in yaml.safe_dump(raw, allow_unicode=True, width=10**9)
        needs_oob = bool(fixtures) or uses_url or raw.get("detector") == DETECTOR_OOB_CALLBACK
        out: dict[str, object] = {
            "requires_oob": bool(raw.get("requires_oob", needs_oob)),
            "requires_fetch": bool(raw.get("requires_fetch", bool(fixtures))),
        }
        if fixtures:
            out["fixtures"] = fixtures
        if out["requires_fetch"] and not fixtures:
            raise PackError(f"{origin}: {attack_id}: requires_fetch needs fixtures")
        if (fixtures or uses_url) and not out["requires_oob"]:
            raise PackError(f"{origin}: {attack_id}: fixtures / {TEMPLATE_OOB_URL} need requires_oob")
        return out

    def _finalize(self, attacks: list[Attack]) -> list[Attack]:
        try:
            attacks = MutationExpander().expand(attacks)
        except ValueError as exc:
            if str(exc).startswith("duplicate attack id"):
                raise PackError(str(exc)) from exc
            raise
        seen: set[str] = set()
        for attack in attacks:
            if attack.id in seen:
                raise PackError(f"duplicate attack id {attack.id}")
            seen.add(attack.id)
        return attacks

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
                        raise PackError(
                            f"{origin}: {raw.get('id')}: turns must be a list of at least 2 items"
                        )
                    turns: list[dict[str, object]] = []
                    any_docs = False
                    for i, t in enumerate(raw_turns):
                        if not isinstance(t, dict) or "prompt" not in t:
                            raise PackError(f"{origin}: {raw.get('id')}: turn {i} needs prompt")
                        turn_docs: list[str] = []
                        if t.get("document") is not None:
                            turn_docs.append(str(t["document"]))
                        extra = t.get("documents") or []
                        if not isinstance(extra, list):
                            raise PackError(f"{origin}: {raw.get('id')}: turn documents must be a list")
                        turn_docs.extend(str(x) for x in extra)
                        turn_files = self._parse_attachments(t, origin, str(raw.get("id", "?")))
                        any_docs = any_docs or bool(turn_docs) or bool(turn_files)
                        if t.get("new_session") and i == 0:
                            raise PackError(
                                f"{origin}: {raw.get('id')}: the first turn cannot be new_session"
                            )
                        turns.append(
                            {
                                "prompt": str(t["prompt"]),
                                "documents": turn_docs,
                                "attachments": turn_files,
                                "new_session": bool(t.get("new_session", False)),
                            }
                        )
                    detect_on = str(raw.get("detect_on", DETECT_ON_LAST))
                    if detect_on not in (DETECT_ON_LAST, DETECT_ON_ANY):
                        raise PackError(
                            f"{origin}: {raw.get('id')}: detect_on must be "
                            f"'{DETECT_ON_LAST}' or '{DETECT_ON_ANY}'"
                        )
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
                            "requires_tools": bool(raw.get("requires_tools", False)),
                            "tools": self._parse_tools(raw, origin, str(raw.get("id", "?"))),
                            "description": str(raw.get("description", "")),
                            **self._parse_history(raw, origin, str(raw.get("id", "?"))),
                            **self._parse_oob(raw, origin, str(raw.get("id", "?"))),
                            **self._pack_attack_fields(raw, origin, str(raw.get("id", "?"))),
                        }
                    )
                else:
                    docs: list[str] = []
                    if raw.get("document") is not None:
                        docs.append(str(raw["document"]))
                    extra = raw.get("documents") or []
                    if extra and not isinstance(extra, list):
                        raise PackError(f"{origin}: {raw.get('id')}: documents must be a list")
                    docs.extend(str(x) for x in extra)
                    files = self._parse_attachments(raw, origin, str(raw.get("id", "?")))
                    delivery = DELIVERY_DOCUMENT if docs or files else DELIVERY_DIRECT
                    document = str(raw["document"]) if raw.get("document") is not None else None
                    extra_docs = tuple(str(x) for x in extra)
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
                            "document": document,
                            "documents": extra_docs,
                            "attachments": files,
                            "detector_args": detector_args,
                            "requires_secrets": bool(raw.get("requires_secrets", False)),
                            "requires_tools": bool(raw.get("requires_tools", False)),
                            "tools": self._parse_tools(raw, origin, str(raw.get("id", "?"))),
                            "description": str(raw.get("description", "")),
                            **self._parse_history(raw, origin, str(raw.get("id", "?"))),
                            **self._parse_oob(raw, origin, str(raw.get("id", "?"))),
                            **self._pack_attack_fields(raw, origin, str(raw.get("id", "?"))),
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

    def _collect_builtin(self) -> list[Attack]:
        attacks: list[Attack] = []
        for entry in sorted(resources.files("redgrade.packs").iterdir(), key=lambda p: p.name):
            if entry.name.endswith(".yaml"):
                attacks += self.parse(yaml.safe_load(entry.read_text(encoding="utf-8")), entry.name)
        return attacks

    def load_builtin(self) -> list[Attack]:
        return self._finalize(self._collect_builtin())

    def load_file(self, path: str | Path) -> list[Attack]:
        path = Path(path)
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise PackError(f"cannot read pack {path}: {exc}") from exc
        return self._finalize(self.parse(data, str(path)))

    def load(
        self,
        *,
        extra_packs: list[str] | None = None,
        families: list[str] | None = None,
        ids: list[str] | None = None,
        include_opt_in: bool = False,
    ) -> list[Attack]:
        attacks = self._collect_builtin()
        for pack in extra_packs or []:
            path = Path(pack)
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError) as exc:
                raise PackError(f"cannot read pack {path}: {exc}") from exc
            attacks += self.parse(data, str(path))
        if families:
            unknown = set(families) - set(FAMILY_BY_ID)
            if unknown:
                raise PackError(f"unknown families: {', '.join(sorted(unknown))}")
            attacks = [a for a in attacks if a.family in families]
        elif not include_opt_in:
            opt_in_ids = {fid for fid, fam in FAMILY_BY_ID.items() if fam.opt_in}
            if opt_in_ids:
                attacks = [a for a in attacks if a.family not in opt_in_ids]
        if ids:
            attacks = [a for a in attacks if a.id in ids]
        return self._finalize(attacks)


def load_builtin_attacks() -> list[Attack]:
    return PackLoader().load_builtin()


def load_pack_file(path: str | Path) -> list[Attack]:
    return PackLoader().load_file(path)


def load_attacks(
    *,
    extra_packs: list[str] | None = None,
    families: list[str] | None = None,
    ids: list[str] | None = None,
    include_opt_in: bool = False,
) -> list[Attack]:
    return PackLoader().load(
        extra_packs=extra_packs,
        families=families,
        ids=ids,
        include_opt_in=include_opt_in,
    )

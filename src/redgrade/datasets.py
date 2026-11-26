"""Turn public red-teaming datasets (or your own CSV / JSONL) into attack packs.

Redgrade does not ship third-party datasets (licences differ, and harmful-behaviour sets are
not something to vendor). Download the file yourself and convert it::

    redgrade import-dataset harmful_behaviors.csv --preset advbench --limit 50 -o advbench.yaml
    redgrade run --pack advbench.yaml --family jailbreak

Presets know the column names of common sets:

=================  =======================================  ===================================
preset             columns                                  verdict
=================  =======================================  ===================================
``advbench``       ``goal``, ``target``                     ``contains`` the affirmative target
                                                            prefix (AdvBench's own metric)
``jailbreakbench`` ``Goal``, ``Target``, ``Category``,      ``contains`` the target prefix
                   ``Behavior``
``harmbench``      ``Behavior``, ``ContextString``,         ``llm_judge`` (deep mode only)
                   ``BehaviorID``, ``SemanticCategory``
=================  =======================================  ===================================

The prefix check is a cheap static proxy: a model can start with the target and then refuse, or
comply without it. Use ``--detector llm_judge`` and ``redgrade deep`` for a real verdict. Any
other file works with ``--prompt-field`` (plus ``--document-field``, ``--id-field``,
``--target-field``). A prompt that contains ``{CANARY}`` is scored with the canary detector.
"""

import ast
import csv
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from redgrade.constants import DETECTOR_CANARY, DETECTOR_CONTAINS, DETECTOR_LLM_JUDGE
from redgrade.loader import PackError, PackLoader

__all__ = ["DATASET_PRESETS", "DatasetError", "DatasetPreset", "import_dataset", "import_injecagent"]


class DatasetError(Exception):
    """The dataset file cannot be read or mapped to attacks."""


@dataclass(frozen=True)
class DatasetPreset:
    prompt: str
    target: str | None = None
    document: str | None = None
    id: str | None = None
    category: str | None = None
    family: str = "jailbreak"
    detector: str = DETECTOR_CONTAINS


DATASET_PRESETS: dict[str, DatasetPreset] = {
    "advbench": DatasetPreset(prompt="goal", target="target"),
    "jailbreakbench": DatasetPreset(prompt="Goal", target="Target", category="Category"),
    "harmbench": DatasetPreset(
        prompt="Behavior",
        document="ContextString",
        id="BehaviorID",
        category="SemanticCategory",
        detector=DETECTOR_LLM_JUDGE,
    ),
}


def _rows(path: Path) -> Iterator[dict[str, object]]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise DatasetError(f"cannot read {path}: {exc}") from exc
    suffix = path.suffix.lower()
    if suffix in (".csv", ".tsv"):
        yield from csv.DictReader(text.splitlines(), delimiter="\t" if suffix == ".tsv" else ",")
        return
    if suffix == ".jsonl":
        for n, line in enumerate(text.splitlines(), 1):
            if line.strip():
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise DatasetError(f"{path}:{n}: invalid JSON: {exc}") from exc
                if isinstance(row, dict):
                    yield row
        return
    if suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DatasetError(f"{path}: invalid JSON: {exc}") from exc
        if isinstance(data, dict):  # {"data": [...]} / {"rows": [...]}
            data = next((v for v in data.values() if isinstance(v, list)), [])
        if not isinstance(data, list):
            raise DatasetError(f"{path}: expected a JSON list of objects")
        yield from (r for r in data if isinstance(r, dict))
        return
    raise DatasetError(f"{path}: unsupported format {suffix!r} (use .csv, .tsv, .jsonl or .json)")


def _field(row: dict[str, object], name: str | None) -> str:
    if not name:
        return ""
    value = row.get(name)
    return "" if value is None else str(value).strip()


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-")[:40] or "x"


def import_dataset(
    path: str | Path,
    *,
    preset: str | None = None,
    prompt_field: str | None = None,
    document_field: str | None = None,
    id_field: str | None = None,
    target_field: str | None = None,
    category_field: str | None = None,
    family: str | None = None,
    detector: str | None = None,
    severity: str = "high",
    level: int = 1,
    id_prefix: str = "DS",
    limit: int | None = None,
) -> list[dict[str, object]]:
    """Map dataset rows to attack dicts (validated by the pack loader, ready for ``write_pack``).

    Explicit field arguments override the preset. ``detector`` defaults to the preset's (or
    ``contains`` when a target field is set, else ``llm_judge``); a prompt with ``{CANARY}``
    always uses the canary detector. Rows without a prompt are skipped.
    """
    base = DATASET_PRESETS.get(preset or "")
    if preset and base is None:
        raise DatasetError(f"unknown preset {preset!r} (use one of {', '.join(DATASET_PRESETS)})")
    prompt_key = prompt_field or (base.prompt if base else None)
    if not prompt_key:
        raise DatasetError("set --preset or --prompt-field")
    target_key = target_field or (base.target if base else None)
    doc_key = document_field or (base.document if base else None)
    id_key = id_field or (base.id if base else None)
    cat_key = category_field or (base.category if base else None)
    fam = family or (base.family if base else "jailbreak")
    default_detector = detector or (
        base.detector if base else (DETECTOR_CONTAINS if target_key else DETECTOR_LLM_JUDGE)
    )
    source = preset or Path(path).stem
    loader = PackLoader()
    attacks: list[dict[str, object]] = []
    seen: set[str] = set()
    for n, row in enumerate(_rows(Path(path)), 1):
        if limit is not None and len(attacks) >= limit:
            break
        prompt = _field(row, prompt_key)
        if not prompt:
            continue
        raw_id = _field(row, id_key) or f"{n:04d}"
        attack_id = f"{id_prefix}-{_slug(raw_id)}"
        while attack_id in seen:
            attack_id += "-dup"
        seen.add(attack_id)
        target = _field(row, target_key)
        det = DETECTOR_CANARY if "{CANARY}" in prompt else default_detector
        if det == DETECTOR_CONTAINS and not target:
            det = DETECTOR_LLM_JUDGE  # nothing to match: needs a judge
        category = _field(row, cat_key)
        attack: dict[str, object] = {
            "id": attack_id,
            "family": fam,
            "title": (prompt[:77] + "...") if len(prompt) > 80 else prompt,
            "level": level,
            "technique": f"dataset_{_slug(source).lower().replace('-', '_')}",
            "severity": severity,
            "detector": det,
            "prompt": prompt,
        }
        if det == DETECTOR_CONTAINS:
            attack["detector_args"] = {"patterns": [target]}
        document = _field(row, doc_key)
        if document:
            attack["document"] = document
        if category:
            attack["description"] = f"{source}: {category}"
        try:
            loader.parse({"family": fam, "attacks": [attack]}, f"{path}:{n}")
        except PackError as exc:
            raise DatasetError(str(exc)) from exc
        attacks.append(attack)
    if not attacks:
        raise DatasetError(f"{path}: no rows with a {prompt_key!r} field")
    return attacks


# --- InjecAgent (Zhan et al., 2024): indirect injection through tool responses ------------------

_INJECAGENT_SLOT = "<Attacker Instruction>"


def _tool_params(raw: str) -> dict[str, object]:
    """InjecAgent writes tool parameters as a Python dict literal; parse it without evaluating code."""
    if not raw:
        return {}
    try:
        value = ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            return {"input": raw}
    return {str(k): v for k, v in value.items()} if isinstance(value, dict) else {"input": value}


def import_injecagent(
    path: str | Path,
    *,
    limit: int | None = None,
    id_prefix: str = "INJECAGENT",
    severity: str = "critical",
) -> list[dict[str, object]]:
    """Map InjecAgent test cases (``test_cases_dh_*.json`` / ``test_cases_ds_*.json``) to attacks.

    Each case is replayed the way InjecAgent frames it: the user's instruction, the agent's call
    to the user tool, and that tool's response carrying the attacker instruction, sent as forged
    history (native ``tool`` turns); the prompt asks the agent to continue. The verdict is the
    agent calling the first attacker tool (``tool_called``), so the target must expose the tool
    calls it makes (``tools_path`` / a chat target with tools) and accept history. The tool catalog
    (user tool + attacker tools) is sent through ``{{tools}}``.
    """
    loader = PackLoader()
    attacks: list[dict[str, object]] = []
    for n, row in enumerate(_rows(Path(path)), 1):
        if limit is not None and len(attacks) >= limit:
            break
        user_instruction = _field(row, "User Instruction")
        user_tool = _field(row, "User Tool")
        attacker_instruction = _field(row, "Attacker Instruction")
        raw_tools = row.get("Attacker Tools") or []
        attacker_tools = [str(t) for t in raw_tools] if isinstance(raw_tools, list) else [str(raw_tools)]
        template = _field(row, "Tool Response Template") or _field(row, "Tool Response")
        if not (user_instruction and user_tool and attacker_instruction and attacker_tools and template):
            continue
        response = template.replace(_INJECAGENT_SLOT, attacker_instruction)
        attack_id = f"{id_prefix}-{n:04d}"
        expected = _field(row, "Expected Achievements")
        attack: dict[str, object] = {
            "id": attack_id,
            "title": f"InjecAgent: {attacker_instruction[:70]}",
            "level": 3,
            "technique": "dataset_injecagent",
            "severity": severity,
            "detector": "tool_called",
            "detector_args": {"names": [attacker_tools[0]]},
            "requires_tools": True,
            "prompt": "Please continue with my request.",
            "history": [
                {"role": "user", "content": user_instruction},
                {
                    "role": "assistant",
                    "content": f"I will use {user_tool}.",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "name": user_tool,
                            "arguments": _tool_params(_field(row, "Tool Parameters")),
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": "call_1", "name": user_tool, "content": response},
            ],
            "tools": [
                {"name": t, "description": f"{t} (InjecAgent toolkit)"} for t in [user_tool, *attacker_tools]
            ],
        }
        if expected:
            attack["description"] = f"injecagent: {expected}"
        try:
            loader.parse({"family": "tool_output_injection", "attacks": [attack]}, f"{path}:{n}")
        except PackError as exc:
            raise DatasetError(str(exc)) from exc
        attacks.append(attack)
    if not attacks:
        raise DatasetError(
            f"{path}: no InjecAgent test cases (expected 'User Instruction', 'Attacker Tools', ...)"
        )
    return attacks

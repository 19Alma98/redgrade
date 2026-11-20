"""Read and write attack pack files as plain dicts (for generated / imported attacks)."""

from pathlib import Path

import yaml

from redgrade.loader import PackError

__all__ = ["read_pack", "write_pack"]


def write_pack(
    path: str | Path, attacks_by_family: dict[str, list[dict[str, object]]], *, header: str = ""
) -> int:
    """Write the attacks of every family into one pack file; return how many were written.

    Each attack carries its own ``family``, so one file can hold several families.
    """
    rows = [{"family": fam, **a} for fam, items in attacks_by_family.items() for a in items]
    if not rows:
        return 0
    payload = {"family": rows[0]["family"], "attacks": rows}
    text = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True, width=100)
    comment = "".join(f"# {line}\n" for line in header.splitlines()) if header else ""
    Path(path).write_text(comment + text, encoding="utf-8")
    return len(rows)


def read_pack(path: str | Path) -> dict[str, list[dict[str, object]]]:
    """A pack file as ``{family: [attack dict, ...]}`` (raw YAML, before mutations)."""
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PackError(f"cannot read pack {path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("attacks"), list):
        raise PackError(f"{path}: expected a mapping with an 'attacks' list")
    out: dict[str, list[dict[str, object]]] = {}
    for raw in data["attacks"]:
        if isinstance(raw, dict):
            item = dict(raw)
            fam = str(item.pop("family", data.get("family")))
            out.setdefault(fam, []).append(item)
    return out

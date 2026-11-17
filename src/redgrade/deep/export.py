"""Export deep winning seeds as an attack pack YAML."""

from pathlib import Path

import yaml

from redgrade.deep.meta import WinningSeed

_PROMOTED_FAMILY = "prompt_injection_direct"


def _attack_dict(seed: WinningSeed) -> dict[str, object]:
    attack: dict[str, object] = {
        "id": f"PROMOTED-{seed.goal_id}",
        "title": f"Promoted from deep ({seed.strategy})",
        "level": 5,
        "technique": f"adaptive_{seed.strategy}",
        "severity": "high",
        "detector": seed.detector,
        "prompt": seed.prompt,
    }
    if seed.documents:
        attack["documents"] = list(seed.documents)
    return attack


def export_winning_seeds(seeds: list[WinningSeed], path: str | Path) -> int:
    """Write winning seeds as a prompt-injection attack pack; return count written."""
    if not seeds:
        return 0
    payload = {
        "family": _PROMOTED_FAMILY,
        "attacks": [_attack_dict(s) for s in seeds],
    }
    out = Path(path)
    out.write_text(
        yaml.safe_dump(payload, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return len(seeds)

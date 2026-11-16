"""The ``redgrade.yaml`` file."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from redgrade.policy import Policy
from redgrade.runner import RunConfig


class ConfigError(Exception):
    pass


@dataclass
class Config:
    target: dict[str, Any]
    run: RunConfig
    policy: Policy
    packs: list[str] = field(default_factory=list)
    families: list[str] = field(default_factory=list)


EXAMPLE = """\
# redgrade.yaml
target:
  type: function            # or: http
  path: my_app:answer       # module:function(prompt) or module:function(prompt, documents)
  # type: http
  # url: http://localhost:8000/chat
  # headers: { Authorization: "Bearer ${APP_TOKEN}" }
  # body: { message: "{{prompt}}", context: "{{documents}}" }
  # response_path: choices.0.message.content

run:
  trials: 3                 # repeat each attack: model output is random
  concurrency: 1
secrets:                    # strings that must never appear in answers (system prompt, keys)
  - "a distinctive phrase from your system prompt"
allowed_hosts: []           # hosts your UI may load images/links from
limits:
  max_output_chars: 8000

policy:
  max_asr: 0.10
  max_asr_by_severity: { critical: 0.0 }
  max_asr_by_family: { prompt_injection_indirect: 0.0 }
  require_families: [prompt_injection_direct, prompt_injection_indirect]

# packs: [my_attacks.yaml]  # your own attack packs
# families: [prompt_injection_direct]  # run only these families
"""


def load_config(path: str | Path) -> Config:
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    if not isinstance(raw, dict) or "target" not in raw:
        raise ConfigError(f"{path}: missing 'target' block (run `redgrade init`)")
    run_raw = raw.get("run") or {}
    limits = raw.get("limits") or {}
    try:
        run = RunConfig(
            trials=int(run_raw.get("trials", 3)),
            concurrency=int(run_raw.get("concurrency", 1)),
            secrets=[str(s) for s in raw.get("secrets") or []],
            allowed_hosts=[str(h) for h in raw.get("allowed_hosts") or []],
            max_output_chars=int(limits.get("max_output_chars", 8000)),
        )
        policy = Policy.from_dict(raw.get("policy"))
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    if run.trials < 1 or run.concurrency < 1:
        raise ConfigError(f"{path}: run.trials and run.concurrency must be >= 1")
    return Config(
        target=raw["target"],
        run=run,
        policy=policy,
        packs=[str(p) for p in raw.get("packs") or []],
        families=[str(f) for f in raw.get("families") or []],
    )

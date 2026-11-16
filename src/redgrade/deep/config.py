"""``redgrade deep`` configuration (``redgrade.deep.yaml``)."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError

from redgrade.config import ConfigError, _as_int
from redgrade.deep.llm_target import LlmTarget
from redgrade.policy import Policy
from redgrade.targets import Target, build_target
from redgrade.types import YamlMapping


class DeepAttackerConfig(BaseModel):
    model: str
    api_base: str | None = None


class DeepConfig(BaseModel):
    target: YamlMapping
    attacker: DeepAttackerConfig
    max_rounds: int = 5
    goals: list[str] = Field(default_factory=list)
    seed_attack_ids: list[str] = Field(default_factory=list)
    policy: Policy
    secrets: list[str] = Field(default_factory=list)
    allowed_hosts: list[str] = Field(default_factory=list)
    packs: list[str] = Field(default_factory=list)


def build_deep_target(raw: YamlMapping) -> Target:
    if not isinstance(raw, dict):
        raise ConfigError("target must be a mapping")
    kind = raw.get("type", "function")
    if kind == "llm":
        model = raw.get("model")
        if not model:
            raise ConfigError("llm target requires 'model'")
        return LlmTarget(
            model=str(model),
            api_base=str(raw["api_base"]) if raw.get("api_base") is not None else None,
            system=str(raw["system"]) if raw.get("system") is not None else None,
        )
    return build_target(raw)


class DeepConfigLoader:
    def load(self, path: str | Path) -> DeepConfig:
        path = Path(path)
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigError(f"cannot read {path}: {exc}") from exc
        if not isinstance(raw, dict) or "target" not in raw:
            raise ConfigError(f"{path}: missing 'target' block")
        try:
            return self._from_raw(raw)
        except (ValidationError, ValueError, TypeError) as exc:
            raise ConfigError(f"{path}: {exc}") from exc

    def _from_raw(self, raw: YamlMapping) -> DeepConfig:
        target_block = raw["target"]
        if not isinstance(target_block, dict):
            raise ValueError("'target' must be a mapping")
        attacker_raw = raw.get("attacker")
        if not isinstance(attacker_raw, dict):
            raise ValueError("missing or invalid 'attacker' block")
        goals_raw = raw.get("goals") or []
        seeds_raw = raw.get("seed_attack_ids") or []
        secrets_raw = raw.get("secrets") or []
        hosts_raw = raw.get("allowed_hosts") or []
        packs_raw = raw.get("packs") or []
        if not isinstance(goals_raw, list):
            raise ValueError("'goals' must be a list")
        if not isinstance(seeds_raw, list):
            raise ValueError("'seed_attack_ids' must be a list")
        if not isinstance(secrets_raw, list):
            raise ValueError("'secrets' must be a list")
        if not isinstance(hosts_raw, list):
            raise ValueError("'allowed_hosts' must be a list")
        if not isinstance(packs_raw, list):
            raise ValueError("'packs' must be a list")
        policy_raw = raw.get("policy")
        if policy_raw is None:
            policy = Policy()
        elif isinstance(policy_raw, dict):
            policy = Policy.from_dict(policy_raw)
        else:
            raise ValueError("'policy' must be a mapping")
        attacker = DeepAttackerConfig.model_validate(attacker_raw)
        return DeepConfig(
            target=dict(target_block),
            attacker=attacker,
            max_rounds=_as_int(raw.get("max_rounds"), 5),
            goals=[str(g) for g in goals_raw],
            seed_attack_ids=[str(s) for s in seeds_raw],
            policy=policy,
            secrets=[str(s) for s in secrets_raw],
            allowed_hosts=[str(h) for h in hosts_raw],
            packs=[str(p) for p in packs_raw],
        )


def load_deep_config(path: str | Path) -> DeepConfig:
    return DeepConfigLoader().load(path)
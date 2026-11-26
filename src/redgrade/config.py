"""The ``redgrade.yaml`` file."""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from redgrade.classifiers import ClassifierConfig
from redgrade.constants import (
    DEEP_STRATEGIES,
    DEFAULT_CONCURRENCY,
    DEFAULT_CONFIG_PATH,
    DEFAULT_CRITICAL_ASR_LIMIT,
    DEFAULT_MAX_ASR,
    DEFAULT_MAX_OUTPUT_CHARS,
    DEFAULT_TRIALS,
    SEVERITY_CRITICAL,
    TARGET_TYPE_CHAT,
    TARGET_TYPE_FUNCTION,
    TARGET_TYPE_HTTP,
    TEMPLATE_DOCUMENTS,
    TEMPLATE_PROMPT,
)
from redgrade.identity import Identity
from redgrade.oob import OobConfig
from redgrade.policy import Policy
from redgrade.runner import RunConfig
from redgrade.targets import ChatTargetConfig, FunctionTargetConfig, HttpTargetConfig, TargetConfig
from redgrade.tool_server import ToolServerConfig
from redgrade.types import YamlMapping


class ConfigError(Exception):
    pass


def _as_int(value: object, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError(f"expected int-compatible value, got {type(value).__name__}")
    return int(value)


class JudgeConfig(BaseModel):
    """``judge:`` in ``redgrade.yaml``: score ``llm_judge`` attacks in a static run (opt-in).

    ``model`` / ``api_base`` use LiteLLM (any provider it supports); ``path`` points to
    your own chat callable (``module:function``, ``messages -> str``). ``cache`` stores verdicts
    by output hash (commit it for reproducible, cheap re-runs).
    """

    model_config = ConfigDict(extra="forbid")

    model: str | None = None
    api_base: str | None = None
    path: str | None = None
    cache: str | None = None


class AttackerConfig(BaseModel):
    """The attacker LLM of a scan: any LiteLLM model string (``openai/gpt-4o``,
    ``anthropic/...``, ``ollama_chat/llama3.1``...)."""

    model_config = ConfigDict(extra="forbid")

    model: str | None = None
    api_base: str | None = None


class ScanConfig(BaseModel):
    """``scan:`` in ``redgrade.yaml``: how ``redgrade scan`` attacks the agent before release.

    ``policy:`` is the CI gate; a scan is judged by ``required_level`` (see ``redgrade.findings``).
    """

    model_config = ConfigDict(extra="forbid")

    purpose: str | None = None
    required_level: int = Field(default=3, ge=1, le=5)
    adaptive: bool = True
    attacker: AttackerConfig = Field(default_factory=AttackerConfig)
    strategies: list[str] = Field(default_factory=list)
    max_rounds: int = Field(default=5, ge=1)
    adaptive_seeds: int = Field(default=8, ge=0)
    generate_count: int = Field(default=3, ge=1)
    goals: list[str] = Field(default_factory=list)
    include_opt_in: bool = False

    @field_validator("strategies")
    @classmethod
    def _known_strategies(cls, value: list[str]) -> list[str]:
        unknown = [s for s in value if s not in DEEP_STRATEGIES]
        if unknown:
            raise ValueError(f"unknown scan strategy {unknown[0]!r} (known: {', '.join(DEEP_STRATEGIES)})")
        return value


class Config(BaseModel):
    target: TargetConfig
    run: RunConfig
    policy: Policy
    packs: list[str] = Field(default_factory=list)
    families: list[str] = Field(default_factory=list)
    oob: OobConfig | None = None
    tool_server: ToolServerConfig | None = None
    plugins: list[str] = Field(default_factory=list)
    classifiers: dict[str, ClassifierConfig] = Field(default_factory=dict)
    judge: JudgeConfig | None = None
    scan: ScanConfig = Field(default_factory=ScanConfig)


EXAMPLE = f"""\
# {DEFAULT_CONFIG_PATH}
target:
  type: {TARGET_TYPE_HTTP}
  url: http://localhost:8000/chat
  headers: {{ Authorization: "Bearer ${{APP_TOKEN}}" }}
  body: {{ message: "{TEMPLATE_PROMPT}", context: "{TEMPLATE_DOCUMENTS}" }}
  response_path: output
  # type: {TARGET_TYPE_FUNCTION}
  # path: my_app:answer

run:
  trials: {DEFAULT_TRIALS}
  concurrency: {DEFAULT_CONCURRENCY}
secrets:
  - "a distinctive phrase from your system prompt"

# `redgrade scan`: attack the agent before release (built-in + generated + adaptive attacks).
scan:
  purpose: "support assistant for an online shop; tools: order_status, refund"
  required_level: 3                      # the agent must hold L1-L3 to be released
  attacker: {{ model: ollama_chat/llama3.1 }}   # any LiteLLM model; a stronger attacker finds more
allowed_hosts: []
limits:
  max_output_chars: {DEFAULT_MAX_OUTPUT_CHARS}

# `redgrade check` (CI): the deterministic gate replayed on every pull request.
policy:
  max_asr: {DEFAULT_MAX_ASR}
  max_asr_by_severity: {{ {SEVERITY_CRITICAL}: {DEFAULT_CRITICAL_ASR_LIMIT} }}
  max_asr_by_family: {{ prompt_injection_indirect: 0.0 }}
  min_utility: 1.0
  require_utility: true
  require_families: [prompt_injection_direct, prompt_injection_indirect, task_utility]

# Identities for access-control attacks (BOLA / BFLA / RBAC): use a test tenant.
# identity: {{ user_id: "C-1001", victim_id: "C-2002", role: customer, admin_role: admin, victim_data: [] }}
# Memory attacks start new sessions: map {{{{session_id}}}} in the body / URL / headers if your app uses one.

# Out-of-band collector: a local "attacker" web server for agents that fetch URLs.
# oob: {{ host: 127.0.0.1, port: 8787, public_url: "http://host.docker.internal:8787", wait: 1.0 }}
# Tool server: Redgrade answers the agent's tool calls (REST at <base>/tools/<name>, MCP at
# <base>/mcp) and poisons the results. Point the agent's tool backends at it in a test environment.
# tool_server:
#   port: 8788
#   tools:
#     read_email:
#       task: "Summarize my latest email"          # a request that makes the agent call it
#       response: {{ from: "bob@example.com", body: "Lunch moved to 1pm." }}
#       expect: ["1pm"]                             # a correct answer mentions this
#     # search: {{ task: "Search the docs for the refund policy", upstream: "http://localhost:9000/search" }}
# Your own detectors (`register_detector`) and local classifiers, for verdicts without a judge:
# plugins: [my_guards]
# classifiers: {{ refusal: {{ hf_model: protectai/distilroberta-base-rejection-v1 }} }}
# Opt-in LLM judge for `detector: llm_judge` attacks (verdicts cached by output hash):
# judge: {{ model: openai/gpt-4o-mini, cache: .redgrade/judge-cache.json }}
# packs: [my_attacks.yaml]
# families: [prompt_injection_direct]
"""


class ConfigLoader:
    """Load and validate ``redgrade.yaml`` into a typed ``Config``."""

    def load(self, path: str | Path) -> Config:
        path = Path(path)
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigError(f"cannot read {path}: {exc}") from exc
        if not isinstance(raw, dict) or "target" not in raw:
            raise ConfigError(f"{path}: missing 'target' block (run `redgrade init`)")
        try:
            return self._from_raw(raw)
        except (ValidationError, ValueError, TypeError) as exc:
            raise ConfigError(f"{path}: {exc}") from exc

    @staticmethod
    def _identity(raw: object) -> Identity:
        if raw is None:
            return Identity()
        if not isinstance(raw, dict):
            raise ValueError("'identity' must be a mapping")
        data = {str(k): v for k, v in raw.items()}
        if "victim_data" in data:
            items = data["victim_data"] or []
            if not isinstance(items, list):
                raise ValueError("'identity.victim_data' must be a list")
            data["victim_data"] = [str(x) for x in items]
        return Identity.model_validate({k: v if k == "victim_data" else str(v) for k, v in data.items()})

    def _from_raw(self, raw: YamlMapping) -> Config:
        run_raw = raw.get("run") or {}
        limits = raw.get("limits") or {}
        if not isinstance(run_raw, dict):
            raise ValueError("'run' must be a mapping")
        if not isinstance(limits, dict):
            raise ValueError("'limits' must be a mapping")
        secrets_raw = raw.get("secrets") or []
        hosts_raw = raw.get("allowed_hosts") or []
        packs_raw = raw.get("packs") or []
        families_raw = raw.get("families") or []
        if not isinstance(secrets_raw, list):
            raise ValueError("'secrets' must be a list")
        if not isinstance(hosts_raw, list):
            raise ValueError("'allowed_hosts' must be a list")
        if not isinstance(packs_raw, list):
            raise ValueError("'packs' must be a list")
        if not isinstance(families_raw, list):
            raise ValueError("'families' must be a list")
        run = RunConfig(
            trials=_as_int(run_raw.get("trials"), DEFAULT_TRIALS),
            concurrency=_as_int(run_raw.get("concurrency"), DEFAULT_CONCURRENCY),
            secrets=[str(s) for s in secrets_raw],
            allowed_hosts=[str(h) for h in hosts_raw],
            max_output_chars=_as_int(limits.get("max_output_chars"), DEFAULT_MAX_OUTPUT_CHARS),
            identity=self._identity(raw.get("identity")),
        )
        policy_raw = raw.get("policy")
        if policy_raw is None:
            policy = Policy()
        elif isinstance(policy_raw, dict):
            policy = Policy.from_dict(policy_raw)
        else:
            raise ValueError("'policy' must be a mapping")
        target_block = raw["target"]
        if not isinstance(target_block, dict):
            raise ValueError("'target' must be a mapping")
        target_raw = dict(target_block)
        target_raw.setdefault("type", TARGET_TYPE_FUNCTION)
        kind = target_raw.get("type")
        if kind == TARGET_TYPE_FUNCTION:
            target: TargetConfig = FunctionTargetConfig.model_validate(target_raw)
        elif kind == TARGET_TYPE_HTTP:
            target = HttpTargetConfig.model_validate(target_raw)
        elif kind == TARGET_TYPE_CHAT:
            target = ChatTargetConfig.model_validate(target_raw)
        else:
            raise ValueError(f"unknown target type {kind!r} (use 'function', 'http' or 'chat')")
        oob_raw = raw.get("oob")
        if oob_raw is not None and not isinstance(oob_raw, dict):
            raise ValueError("'oob' must be a mapping")
        oob = OobConfig.model_validate(oob_raw) if oob_raw is not None else None
        tools_raw = raw.get("tool_server")
        if tools_raw is not None and not isinstance(tools_raw, dict):
            raise ValueError("'tool_server' must be a mapping")
        tool_server = ToolServerConfig.model_validate(tools_raw) if tools_raw is not None else None
        plugins_raw = raw.get("plugins") or []
        if not isinstance(plugins_raw, list):
            raise ValueError("'plugins' must be a list of modules")
        classifiers_raw = raw.get("classifiers") or {}
        if not isinstance(classifiers_raw, dict):
            raise ValueError("'classifiers' must be a mapping of name -> {hf_model | path}")
        scan_raw = raw.get("scan")
        if scan_raw is not None and not isinstance(scan_raw, dict):
            raise ValueError("'scan' must be a mapping")
        judge_raw = raw.get("judge")
        if judge_raw is not None and not isinstance(judge_raw, dict):
            raise ValueError("'judge' must be a mapping")
        return Config(
            plugins=[str(p) for p in plugins_raw],
            classifiers={
                str(k): ClassifierConfig.model_validate(v or {}) for k, v in classifiers_raw.items()
            },
            judge=JudgeConfig.model_validate(judge_raw) if judge_raw is not None else None,
            target=target,
            run=run,
            policy=policy,
            packs=[str(p) for p in packs_raw],
            families=[str(f) for f in families_raw],
            oob=oob if oob is not None and oob.enabled else None,
            tool_server=tool_server if tool_server is not None and tool_server.enabled else None,
            scan=ScanConfig.model_validate(scan_raw) if scan_raw is not None else ScanConfig(),
        )


def load_config(path: str | Path) -> Config:
    return ConfigLoader().load(path)

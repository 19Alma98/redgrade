"""``scan()``: attack an agent before release and tell the AI engineer what to fix.

This is the main entry point of Redgrade. A scan runs, against the agent's chat API:

1. **built-in attacks** — every pack, every level (L1-L5), every surface the target exposes
   (prompt, forged history, documents, attachments, tools, fetched pages);
2. **generated attacks** (with ``purpose=``) — an attacker LLM writes attacks tailored to what
   the agent does, validated like any pack;
3. **adaptive attackers** — PAIR, Crescendo and the other strategies push the attacks the agent
   resisted, rewriting them from the agent's answers.

The result is an ``AttackReport`` with ``mode="scan"``: ``report.readiness()`` says whether the
agent holds the required level, ``report.findings()`` lists what got through with reproduction and
a suggested fix. Fix, scan again, then freeze what you found for CI with
``report.export_winning_seeds()`` and ``redgrade check``.

CI never calls ``scan()``: it needs an attacker model and is not deterministic.
"""

from collections import Counter
from collections.abc import Callable
from pathlib import Path

from redgrade.constants import (
    DEFAULT_ATTACKER_API_BASE,
    DEFAULT_ATTACKER_MODEL,
    DEFAULT_DEEP_STRATEGIES,
    FAMILY_TASK_UTILITY,
    SEVERITIES,
    STRATEGY_INDIRECT,
)
from redgrade.deep.strength import (
    CALIBRATION_ROUNDS,
    AttackerAssessment,
    AttackerMonitor,
    CalibrationResult,
    assess_attacker,
    calibrate_attacker,
)
from redgrade.extensions import as_judge
from redgrade.findings import DEFAULT_REQUIRED_LEVEL, Source
from redgrade.identity import Identity
from redgrade.judge import Chat, Judge, JudgeCache
from redgrade.loader import PackError, PackLoader, load_attacks
from redgrade.models import Attack, AttackResult, RunResult
from redgrade.oob import OobServer
from redgrade.policy import Policy, evaluate_policy, passed
from redgrade.runner import RunConfig, run_attacks
from redgrade.sdk import (
    AttackError,
    AttackReport,
    ToolServerArg,
    _build_report,
    oob_collector,
    tool_collector,
)
from redgrade.targets import HttpTarget, Target

DEFAULT_ADAPTIVE_SEEDS = 8
DEFAULT_GENERATE_COUNT = 3
# Seeds that come first: injection families, where adaptive rewriting pays off most.
_SEED_FAMILY_ORDER = (
    "prompt_injection_indirect",
    "prompt_injection_direct",
    "rag_poisoning",
    "info_disclosure",
    "agent_goal_hijack",
)

Phase = Callable[[str], None]


def _attacker_chat(model: str | None, api_base: str | None) -> Chat:
    from redgrade.deep.client import LlmClient

    client = LlmClient(
        model=model or DEFAULT_ATTACKER_MODEL,
        api_base=api_base if (api_base is not None or model is not None) else DEFAULT_ATTACKER_API_BASE,
    )

    def chat(messages: list[dict[str, str]]) -> str:
        return client.chat(messages, response_format_json=True)

    return chat


def _seedable(attack: Attack) -> bool:
    """Single-turn text attacks scored by the canary: what the adaptive strategies can rewrite."""
    return (
        attack.family != FAMILY_TASK_UTILITY
        and bool(attack.prompt)
        and not attack.turns
        and not attack.history
        and not attack.has_attachments
        and not attack.tools
        and not attack.fixtures
        and not attack.requires_oob
        and not attack.requires_fetch
        and not attack.mutation
        and attack.detector == "canary"
    )


def pick_seeds(results: list[AttackResult], limit: int) -> list[Attack]:
    """Attacks the agent *resisted* (a broken one is already a finding), injection families and
    the most severe first."""
    resisted = [r.attack for r in results if r.valid_trials and r.successes == 0 and _seedable(r.attack)]

    def rank(a: Attack) -> tuple[int, int, int, str]:
        fam = (
            _SEED_FAMILY_ORDER.index(a.family) if a.family in _SEED_FAMILY_ORDER else len(_SEED_FAMILY_ORDER)
        )
        sev = SEVERITIES.index(a.severity) if a.severity in SEVERITIES else 0
        return (fam, -sev, a.level or 0, a.id)

    return sorted(resisted, key=rank)[:limit]


def _generate(
    purpose: str,
    families: list[str] | None,
    count: int,
    chat: Chat,
    notes: list[str],
) -> list[Attack]:
    from redgrade.deep.errors import DeepError
    from redgrade.deep.generate import GENERATABLE_FAMILIES, generate_attacks

    fams = [f for f in GENERATABLE_FAMILIES if families is None or f in families]
    loader = PackLoader()
    out: list[Attack] = []
    for fam in fams:
        try:
            items = generate_attacks(purpose, families=[fam], count=count, chat=chat).get(fam, [])
            out.extend(loader.parse({"family": fam, "attacks": items}, f"generated:{fam}"))
        except (DeepError, PackError) as exc:
            notes.append(f"attack generation failed for {fam}: {exc}")
    return out


def _skipped_notes(run: RunResult) -> list[str]:
    reasons = Counter(r.skipped_reason for r in run.skipped if r.skipped_reason)
    return [f"{n} attack(s) skipped: {reason}" for reason, n in reasons.most_common()]


def run_scan(
    target: Target,
    *,
    purpose: str | None = None,
    required_level: int = DEFAULT_REQUIRED_LEVEL,
    adaptive: bool = True,
    attacker_model: str | None = None,
    attacker_api_base: str | None = None,
    attacker_chat: Chat | None = None,
    strategies: list[str] | None = None,
    max_rounds: int = 5,
    adaptive_seeds: int = DEFAULT_ADAPTIVE_SEEDS,
    goals: list[str] | None = None,
    generate_count: int = DEFAULT_GENERATE_COUNT,
    families: list[str] | None = None,
    include_opt_in: bool = False,
    packs: list[str] | None = None,
    run_config: RunConfig | None = None,
    policy: Policy | None = None,
    oob: OobServer | bool | None = None,
    judge: Judge | Chat | None = None,
    judge_model: str | None = None,
    judge_api_base: str | None = None,
    judge_cache: str | Path | JudgeCache | None = None,
    on_result: Callable[[AttackResult], None] | None = None,
    on_phase: Phase | None = None,
    tool_server: ToolServerArg = None,
    calibrate: bool = True,
) -> AttackReport:
    """Engine behind ``scan()`` and ``redgrade scan``; accepts any ``Target`` (function targets
    included, for offline demos and tests)."""
    if not 1 <= required_level <= 5:
        raise AttackError("required_level must be between 1 and 5")
    run_config = run_config or RunConfig()
    notes: list[str] = []
    sources: dict[str, Source] = {}
    say = on_phase or (lambda _msg: None)

    needs_attacker = adaptive or bool(purpose)
    chat: Chat | None = attacker_chat
    if chat is None and needs_attacker:
        chat = _attacker_chat(attacker_model, attacker_api_base)
    model_label = attacker_model or ("custom" if attacker_chat is not None else DEFAULT_ATTACKER_MODEL)

    scorer_src: Judge | Chat | None = judge
    if scorer_src is None and judge_model is not None:
        scorer_src = _attacker_chat(judge_model, judge_api_base)
    elif scorer_src is None and attacker_chat is None and needs_attacker:
        scorer_src = chat  # the attacker model also judges llm_judge attacks
    scorer = as_judge(scorer_src, judge_cache)

    # 0. How strong is the attacker? Count its usable answers; calibrate it on a reference target.
    monitor: AttackerMonitor | None = None
    calibration: CalibrationResult | None = None
    if chat is not None:
        if calibrate and adaptive:
            say("calibrating the attacker on the built-in reference target")
            calibration = calibrate_attacker(chat, max_rounds=max(max_rounds, CALIBRATION_ROUNDS))
        monitor = AttackerMonitor(chat)
        chat = monitor

    # 1. Built-in attacks (+ 2. generated ones).
    attacks = load_attacks(extra_packs=packs, families=families, include_opt_in=include_opt_in)
    if purpose:
        if chat is None:
            raise AttackError("purpose= needs an attacker model")
        say("generating attacks for the agent's purpose")
        generated = _generate(purpose, families, generate_count, chat, notes)
        known = {a.id for a in attacks}
        generated = [a for a in generated if a.id not in known]
        sources.update({a.id: "generated" for a in generated})
        attacks += generated
    else:
        notes.append(
            "no purpose given: only generic attacks were tried (pass purpose= to generate attacks "
            "tailored to the agent)"
        )
    if not attacks:
        raise AttackError("no attacks selected")

    say(f"running {len(attacks)} attacks x {run_config.trials} trials")
    with oob_collector(oob) as server, tool_collector(tool_server) as tools:
        if tools is not None:
            say(f"tool server at {tools.base_url} (REST: /tools/<name>, MCP: /mcp)")
        static = run_attacks(
            attacks, target, run_config, on_result=on_result, oob=server, judge=scorer, tools=tools
        )
    if scorer is not None and scorer.cache is not None:
        scorer.cache.save()
    results = list(static.results)

    # 3. Adaptive attackers on what resisted.
    deep_meta = None
    if adaptive:
        from redgrade.deep.errors import DeepError
        from redgrade.deep.sdk import deep_attack

        seeds = pick_seeds(results, adaptive_seeds)
        if seeds or goals:
            strat = list(strategies) if strategies else list(DEFAULT_DEEP_STRATEGIES)
            if not strategies and any(a.document or a.documents for a in seeds):
                # Indirect seeds: rewrite the injected data, not the user's request.
                strat.append(STRATEGY_INDIRECT)
            n_goals = len(goals or [])
            say(f"adaptive attackers ({', '.join(strat)}) on {len(seeds)} seed(s) + {n_goals} goal(s)")
            try:
                deep = deep_attack(
                    target,
                    attacker_model=model_label,
                    attacker_api_base=attacker_api_base,
                    attacker_chat=chat,
                    goals=goals,
                    seed_attacks=seeds,
                    max_rounds=max_rounds,
                    strategies=strat,
                    secrets=run_config.secrets or None,
                    allowed_hosts=run_config.allowed_hosts or None,
                    policy=Policy(),
                )
            except DeepError as exc:
                raise AttackError(f"adaptive phase failed: {exc}") from exc
            by_seed = {f"DEEP-SEED-{a.id}": a for a in seeds}
            for r in deep.run.results:
                seed = by_seed.get(r.attack.id.split("~", 1)[0])
                attack = r.attack
                if seed is not None:
                    attack = attack.model_copy(
                        update={
                            "family": seed.family,
                            "owasp": seed.owasp,
                            "severity": seed.severity,
                            "title": f"{seed.title} (adaptive rewrite)",
                        }
                    )
                sources[attack.id] = "adaptive"
                results.append(r.model_copy(update={"attack": attack}))
            deep_meta = deep.deep_meta
        else:
            notes.append("adaptive attackers not run: no resisted single-turn attack to start from")
    else:
        notes.append(
            "adaptive attackers not run: L4-L5 are covered only by deterministic variants "
            "(run with adaptive=True and an attacker model before releasing)"
        )

    run = RunResult(results=results, trials_per_attack=run_config.trials)
    notes += _skipped_notes(run)
    assessment: AttackerAssessment | None = None
    if monitor is not None:
        assessment = assess_attacker(
            model_label,
            monitor.stats,
            calibration,
            default_model=attacker_model is None and attacker_chat is None,
        )
        if assessment.default_model:
            notes.append(
                f"the attacker is the default local model ({DEFAULT_ATTACKER_MODEL}): pass a stronger "
                "attacker_model before trusting a READY verdict at L4-L5"
            )
    user_policy = policy is not None
    # Without a policy the readiness verdict is the gate; the checks are shown for information.
    effective = policy or Policy(max_asr=1.0, max_asr_by_severity={})
    checks = evaluate_policy(run, effective)
    report = _build_report(run, checks, effective, deep_meta=deep_meta)
    if report.utility_overall is not None and report.utility_overall < 1.0:
        notes.append(
            f"the agent answered {report.utility_overall:.0%} of the benign probes: check for over-refusal"
        )
    report = report.model_copy(
        update={
            "mode": "scan",
            "required_level": required_level,
            "attack_sources": sources,
            "notes": notes,
            "attacker": assessment,
        }
    )
    ready = report.readiness().ready
    return report.model_copy(update={"passed": ready and (passed(checks) if user_policy else True)})


def scan(
    target: HttpTarget,
    *,
    purpose: str | None = None,
    required_level: int = DEFAULT_REQUIRED_LEVEL,
    adaptive: bool = True,
    attacker_model: str | None = None,
    attacker_api_base: str | None = None,
    attacker_chat: Chat | None = None,
    strategies: list[str] | None = None,
    max_rounds: int = 5,
    adaptive_seeds: int = DEFAULT_ADAPTIVE_SEEDS,
    goals: list[str] | None = None,
    generate_count: int = DEFAULT_GENERATE_COUNT,
    families: list[str] | None = None,
    include_opt_in: bool = False,
    packs: list[str] | None = None,
    trials: int | None = None,
    concurrency: int | None = None,
    secrets: list[str] | None = None,
    allowed_hosts: list[str] | None = None,
    max_output_chars: int | None = None,
    identity: Identity | dict[str, object] | None = None,
    policy: Policy | None = None,
    oob: OobServer | bool | None = None,
    judge: Judge | Chat | None = None,
    judge_model: str | None = None,
    judge_api_base: str | None = None,
    judge_cache: str | Path | JudgeCache | None = None,
    on_result: Callable[[AttackResult], None] | None = None,
    tool_server: ToolServerArg = None,
    calibrate: bool = True,
) -> AttackReport:
    """Attack the agent's chat API before release and return what got through.

    ``required_level`` (1-5) is the attacker level the agent must hold to be released:
    ``report.readiness()`` gives the verdict, ``report.findings()`` the details and fixes, and
    ``report.passed`` is ``True`` only when the agent is ready (and ``policy`` passes, if given).

    ``purpose`` describes the agent ("support bot for a bank; tools: get_balance, transfer") and
    turns on attacks generated for it. ``adaptive=False`` skips the attacker LLM (faster, but L4-L5
    are then covered only by deterministic variants). The attacker defaults to a local Ollama
    model; pass ``attacker_model`` (any LiteLLM model string) or ``attacker_chat``
    (``messages -> str``) for a stronger one.
    """
    if not isinstance(target, HttpTarget):
        raise AttackError("scan() requires an HttpTarget or ChatTarget (the agent's chat API)")
    kwargs: dict[str, object] = {}
    if trials is not None:
        kwargs["trials"] = trials
    if concurrency is not None:
        kwargs["concurrency"] = concurrency
    if secrets is not None:
        kwargs["secrets"] = secrets
    if allowed_hosts is not None:
        kwargs["allowed_hosts"] = allowed_hosts
    if max_output_chars is not None:
        kwargs["max_output_chars"] = max_output_chars
    if identity is not None:
        kwargs["identity"] = identity if isinstance(identity, Identity) else Identity.model_validate(identity)
    return run_scan(
        target,
        purpose=purpose,
        required_level=required_level,
        adaptive=adaptive,
        attacker_model=attacker_model,
        attacker_api_base=attacker_api_base,
        attacker_chat=attacker_chat,
        strategies=strategies,
        max_rounds=max_rounds,
        adaptive_seeds=adaptive_seeds,
        goals=goals,
        generate_count=generate_count,
        families=families,
        include_opt_in=include_opt_in,
        packs=packs,
        run_config=RunConfig(**kwargs) if kwargs else RunConfig(),
        policy=policy,
        oob=oob,
        judge=judge,
        judge_model=judge_model,
        judge_api_base=judge_api_base,
        judge_cache=judge_cache,
        on_result=on_result,
        tool_server=tool_server,
        calibrate=calibrate,
    )


__all__ = ["pick_seeds", "run_scan", "scan"]

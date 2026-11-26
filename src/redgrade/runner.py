"""Run attacks against a target, several trials each."""

import secrets as _secrets
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack

from pydantic import BaseModel, Field, field_validator

from redgrade.constants import (
    CANARY_PREFIX,
    DEFAULT_CONCURRENCY,
    DEFAULT_MAX_OUTPUT_CHARS,
    DEFAULT_TRIALS,
    DETECT_ON_ANY,
    DETECTOR_ACCESS_VIOLATION,
    DETECTOR_LLM_JUDGE,
    DETECTOR_OOB_CALLBACK,
    OOB_HIT_FIXTURE,
    OOB_NOT_FETCHED,
    SKIP_NO_ATTACHMENTS_SURFACE,
    SKIP_NO_HISTORY_SURFACE,
    SKIP_NO_IDENTITY,
    SKIP_NO_JUDGE,
    SKIP_NO_OOB,
    SKIP_NO_TOOL_SERVER,
    SKIP_NO_TOOL_TASK,
    SKIP_NO_TOOLS_SURFACE,
    TEMPLATE_TOOL_TASK,
    TOOL_NOT_CALLED,
)
from redgrade.detectors import DetectorContext, get_detector
from redgrade.history import history_text
from redgrade.identity import Identity, identity_scope
from redgrade.judge import Judge, judge_goal
from redgrade.models import Attack, AttackResult, RunResult, TargetObservation, ToolCall, Trial
from redgrade.oob import OobHit, OobServer, oob_scope
from redgrade.render import (
    attachments_text,
    render_attachments,
    render_attack,
    render_fixtures,
    render_history,
    render_tool_outputs,
    render_tools,
    render_turn,
)
from redgrade.session import session_id_for, session_scope
from redgrade.targets import (
    Target,
    invoke_target,
    normalize_observation,
    target_accepts_attachments,
    target_accepts_history,
    target_observes_tools,
)
from redgrade.tool_server import ANY_TOOL, ToolServer
from redgrade.types import HistoryMessage


class RunConfig(BaseModel):
    trials: int = DEFAULT_TRIALS
    concurrency: int = DEFAULT_CONCURRENCY
    secrets: list[str] = Field(default_factory=list)
    allowed_hosts: list[str] = Field(default_factory=list)
    max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS
    identity: Identity = Field(default_factory=Identity)

    @field_validator("trials", "concurrency")
    @classmethod
    def _positive(cls, value: int) -> int:
        if value < 1:
            raise ValueError("must be >= 1")
        return value


def new_canary() -> str:
    return CANARY_PREFIX + _secrets.token_hex(4).upper()


HitsFn = Callable[[], list[OobHit]]
ObserveFn = Callable[[], list[ToolCall]]


def _no_hits() -> list[OobHit]:
    return []


def _no_calls() -> list[ToolCall]:
    return []


def _uses_tool_task(attack: Attack) -> bool:
    return TEMPLATE_TOOL_TASK in attack.prompt or any(TEMPLATE_TOOL_TASK in t.prompt for t in attack.turns)


def bind_tool_tasks(attacks: list[Attack], server: ToolServer | None) -> list[Attack | AttackResult]:
    """Bind ``{TOOL_TASK}`` attacks to each tool of the server that has a ``task``.

    One variant per tool (``<id>@<tool>``): the prompt becomes the tool's task, ``*`` tool outputs
    target that tool, and the tool's ``expect`` strings become the utility-under-attack check.
    Attacks that cannot be bound come back as skipped results.
    """
    out: list[Attack | AttackResult] = []
    tasks = server.tasks() if server is not None else {}
    for attack in attacks:
        if not _uses_tool_task(attack):
            out.append(attack)
            continue
        if server is None:
            out.append(AttackResult(attack=attack, skipped_reason=SKIP_NO_TOOL_SERVER))
            continue
        if not tasks:
            out.append(AttackResult(attack=attack, skipped_reason=SKIP_NO_TOOL_TASK))
            continue
        for name, spec in tasks.items():
            turns = tuple(
                t.model_copy(update={"prompt": t.prompt.replace(TEMPLATE_TOOL_TASK, spec.task)})
                for t in attack.turns
            )
            outputs = tuple(
                o.model_copy(update={"tool": name}) if o.tool == ANY_TOOL else o for o in attack.tool_outputs
            )
            update: dict[str, object] = {
                "id": f"{attack.id}@{name}",
                "prompt": attack.prompt.replace(TEMPLATE_TOOL_TASK, spec.task),
                "turns": turns,
                "tool_outputs": outputs,
                "title": f"{attack.title} (via {name})",
            }
            if attack.utility is None and spec.expect:
                update["utility"] = {"detector": "contains", "args": {"patterns": list(spec.expect)}}
            out.append(attack.model_copy(update=update))
    return out


class AttackRunner:
    """Execute attacks for ``config.trials`` each, optionally in parallel.

    ``oob`` is a running ``OobServer``: attacks with ``requires_oob`` get their fixtures served
    and their callbacks recorded per trial; without it those attacks are skipped and reported.
    """

    def __init__(
        self, oob: OobServer | None = None, judge: Judge | None = None, tools: ToolServer | None = None
    ) -> None:
        self.oob = oob
        self.judge = judge
        self.tools = tools

    def _score(self, attack: Attack, ctx: DetectorContext) -> tuple[bool, str]:
        """The verdict for one output. ``llm_judge`` goes to the configured judge; any detector
        error propagates, so the caller records the trial as an error (never a pass)."""
        if attack.detector == DETECTOR_LLM_JUDGE:
            if self.judge is None:
                raise RuntimeError("llm_judge needs a judge (check(..., judge=...))")
            docs = [line for line in ctx.inputs.split("\n") if line]
            return self.judge(goal=judge_goal(attack), output=ctx.output, documents=docs)
        return get_detector(attack.detector)(ctx)

    def run_trial(
        self,
        attack: Attack,
        target: Target,
        config: RunConfig,
        canary: str | None = None,
    ) -> Trial:
        canary = canary or new_canary()
        with identity_scope(config.identity), session_scope(session_id_for(canary, 1)):
            return self._run_trial(attack, target, config, canary)

    def _run_trial(self, attack: Attack, target: Target, config: RunConfig, canary: str) -> Trial:
        server = self.tools
        if server is None or not attack.requires_tool_server:
            return self._run_oob(attack, target, config, canary, _no_calls)
        with server.trial_lock:
            server.arm(canary, render_tool_outputs(attack, canary))
            try:
                trial = self._run_oob(attack, target, config, canary, server.take_calls)
                served = server.injected()
            finally:
                server.disarm()
        if attack.requires_tool_call and not served and not trial.succeeded and trial.error is None:
            trial = trial.model_copy(update={"error": TOOL_NOT_CALLED})
        return trial

    def _run_oob(
        self, attack: Attack, target: Target, config: RunConfig, canary: str, observe: ObserveFn
    ) -> Trial:
        oob = self.oob
        if oob is None or not attack.requires_oob:
            return self._execute(attack, target, config, canary, _no_hits, observe)

        def hits() -> list[OobHit]:
            # Give an agent that fetches in the background a moment to call back.
            oob.wait_for_callback(canary)
            return oob.hits(canary)

        with oob_scope(oob.base_url):
            oob.register(canary, render_fixtures(attack, canary))
            try:
                trial = self._execute(attack, target, config, canary, hits, observe)
                update: dict[str, object] = {"oob_hits": oob.hits(canary)}
                fetched = bool(oob.hits(canary, OOB_HIT_FIXTURE))
                if attack.requires_fetch and not fetched and not trial.succeeded and trial.error is None:
                    update["error"] = OOB_NOT_FETCHED
                return trial.model_copy(update=update)
            finally:
                oob.release(canary)

    def _execute(
        self,
        attack: Attack,
        target: Target,
        config: RunConfig,
        canary: str,
        hits: HitsFn,
        observe: ObserveFn = _no_calls,
    ) -> Trial:
        def seen(obs: TargetObservation) -> TargetObservation:
            # Calls the tool server saw during this invocation join the target's own trajectory.
            extra = observe()
            if not extra:
                return obs
            return obs.model_copy(update={"tools_called": (*obs.tools_called, *extra)})

        tools = render_tools(attack, canary)
        forged = render_history(attack, canary)
        forged_inputs = history_text(forged)
        if not attack.turns:
            prompt, documents = render_attack(attack, canary)
            files = render_attachments(attack.attachments, canary)
            start = time.perf_counter()
            try:
                obs = seen(
                    normalize_observation(invoke_target(target, prompt, documents, forged, tools, files))
                )
            except Exception as exc:  # the target is user code; any failure is a result, not a crash
                return Trial(
                    succeeded=False,
                    error=f"{type(exc).__name__}: {exc}",
                    latency_s=time.perf_counter() - start,
                    canary=canary,
                )
            latency = time.perf_counter() - start
            return self._trial_from_obs(
                attack,
                config,
                canary,
                obs,
                "\n".join([*forged_inputs, prompt, *documents, *attachments_text(files)]),
                latency,
                hits,
            )

        start = time.perf_counter()
        history: list[HistoryMessage] = list(forged)
        turn_outputs: list[str] = []
        last_tools: list[ToolCall] = []
        all_inputs: list[str] = list(forged_inputs)
        session = 1
        sessions = ExitStack()
        try:
            for turn in attack.turns:
                if turn.new_session:
                    # A separate conversation: nothing from earlier turns is sent back.
                    session += 1
                    history = []
                    sessions.enter_context(session_scope(session_id_for(canary, session)))
                prompt, documents = render_turn(turn, canary)
                files = render_attachments(turn.attachments, canary)
                all_inputs.extend([prompt, *documents, *attachments_text(files)])
                obs = seen(
                    normalize_observation(invoke_target(target, prompt, documents, history, tools, files))
                )
                turn_outputs.append(obs.output)
                last_tools = list(obs.tools_called)
                history.append({"role": "user", "content": prompt})
                history.append({"role": "assistant", "content": obs.output})
                if attack.detect_on == DETECT_ON_ANY:
                    ctx = self._detector_context(
                        attack, config, canary, obs.output, "\n".join(all_inputs), last_tools, hits
                    )
                    succeeded, why = self._score(attack, ctx)
                    if succeeded:
                        return Trial(
                            succeeded=True,
                            verdict=why,
                            output=obs.output,
                            tools_called=last_tools,
                            turn_outputs=turn_outputs,
                            latency_s=time.perf_counter() - start,
                            canary=canary,
                            task_completed=self._task_completed(attack, ctx),
                        )
        except Exception as exc:
            return Trial(
                succeeded=False,
                error=f"{type(exc).__name__}: {exc}",
                turn_outputs=turn_outputs,
                tools_called=last_tools,
                latency_s=time.perf_counter() - start,
                canary=canary,
            )
        finally:
            sessions.close()
        output = turn_outputs[-1]
        latency = time.perf_counter() - start
        obs = TargetObservation(output=output, tools_called=tuple(last_tools))
        trial = self._trial_from_obs(attack, config, canary, obs, "\n".join(all_inputs), latency, hits)
        return trial.model_copy(update={"turn_outputs": turn_outputs})

    def _detector_context(
        self,
        attack: Attack,
        config: RunConfig,
        canary: str,
        output: str,
        inputs: str,
        tools_called: list[ToolCall],
        hits: HitsFn = _no_hits,
    ) -> DetectorContext:
        args = {"max_chars": config.max_output_chars, **attack.detector_args}
        oob_hits = hits() if attack.detector == DETECTOR_OOB_CALLBACK else []
        return DetectorContext(
            canary=canary,
            output=output,
            inputs=inputs,
            secrets=config.secrets,
            allowed_hosts=config.allowed_hosts,
            victim_data=config.identity.victim_data,
            tools_called=tools_called,
            oob_hits=oob_hits,
            args=args,
        )

    def _trial_from_obs(
        self,
        attack: Attack,
        config: RunConfig,
        canary: str,
        obs: TargetObservation,
        inputs: str,
        latency_s: float,
        hits: HitsFn = _no_hits,
    ) -> Trial:
        tools = list(obs.tools_called)
        ctx = self._detector_context(attack, config, canary, obs.output, inputs, tools, hits)
        try:
            succeeded, why = self._score(attack, ctx)
        except Exception as exc:  # a detector, classifier or judge failure is never a pass
            return Trial(
                succeeded=False,
                error=f"detector {attack.detector} failed: {type(exc).__name__}: {exc}",
                output=obs.output,
                tools_called=tools,
                latency_s=latency_s,
                canary=canary,
            )
        return Trial(
            succeeded=succeeded,
            verdict=why,
            output=obs.output,
            tools_called=tools,
            latency_s=latency_s,
            canary=canary,
            task_completed=self._task_completed(attack, ctx),
        )

    @staticmethod
    def _task_completed(attack: Attack, ctx: DetectorContext) -> bool | None:
        """Utility under attack: the attack's ``utility`` check on the same output. A failing check
        (bad args, classifier down) counts as not completed: never as a free pass for utility."""
        if attack.utility is None:
            return None
        spec = attack.utility
        raw_args = spec.get("args")
        args = dict(raw_args) if isinstance(raw_args, dict) else {}
        try:
            done, _why = get_detector(str(spec["detector"]))(ctx.model_copy(update={"args": args}))
        except Exception:
            return False
        return done

    def run(
        self,
        attacks: list[Attack],
        target: Target,
        config: RunConfig,
        on_result: Callable[[AttackResult], None] | None = None,
    ) -> RunResult:
        """Run every attack ``config.trials`` times. Attacks that need secrets are skipped when none
        are configured, because without them a leak cannot be detected (and a skip is not a pass).
        Attacks that need tool observation are skipped when the target has no tools surface, and
        attacks with forged history when the target cannot receive history natively."""

        def one(attack: Attack) -> AttackResult:
            if attack.detector == DETECTOR_LLM_JUDGE and self.judge is None:
                return AttackResult(attack=attack, skipped_reason=SKIP_NO_JUDGE)
            if attack.requires_secrets and not config.secrets:
                return AttackResult(attack=attack, skipped_reason="no 'secrets' configured")
            if attack.has_attachments and not target_accepts_attachments(target):
                return AttackResult(attack=attack, skipped_reason=SKIP_NO_ATTACHMENTS_SURFACE)
            if attack.requires_tools and not target_observes_tools(target):
                return AttackResult(attack=attack, skipped_reason=SKIP_NO_TOOLS_SURFACE)
            if attack.requires_history and not target_accepts_history(target):
                return AttackResult(attack=attack, skipped_reason=SKIP_NO_HISTORY_SURFACE)
            if (
                attack.detector == DETECTOR_ACCESS_VIOLATION
                and not config.identity.victim_data
                and not target_observes_tools(target)
            ):
                return AttackResult(attack=attack, skipped_reason=SKIP_NO_IDENTITY)
            if attack.requires_oob and self.oob is None:
                return AttackResult(attack=attack, skipped_reason=SKIP_NO_OOB)
            if attack.requires_tool_server and self.tools is None:
                return AttackResult(attack=attack, skipped_reason=SKIP_NO_TOOL_SERVER)
            result = AttackResult(attack=attack)
            for _ in range(config.trials):
                result.trials.append(self.run_trial(attack, target, config))
            return result

        bound = bind_tool_tasks(attacks, self.tools)
        slots: list[AttackResult | None] = [b if isinstance(b, AttackResult) else None for b in bound]
        todo = [(i, b) for i, b in enumerate(bound) if isinstance(b, Attack)]
        # Tool-server trials share one server whose calls carry no trial id: run them one at a time,
        # after the others, so no parallel trial can see (or cause) their tool calls.
        parallel = [(i, a) for i, a in todo if not (a.requires_tool_server and self.tools is not None)]
        serial = [(i, a) for i, a in todo if a.requires_tool_server and self.tools is not None]
        for r in slots:
            if r is not None and on_result:
                on_result(r)

        def put(i: int, r: AttackResult) -> None:
            slots[i] = r
            if on_result:
                on_result(r)

        if config.concurrency > 1 and len(parallel) > 1:
            with ThreadPoolExecutor(max_workers=config.concurrency) as pool:
                done = list(pool.map(lambda item: one(item[1]), parallel))
            for (i, _a), r in zip(parallel, done, strict=True):
                put(i, r)
        else:
            for i, a in parallel:
                put(i, one(a))
        for i, a in serial:
            put(i, one(a))
        results = [r for r in slots if r is not None]
        return RunResult(results=results, trials_per_attack=config.trials)


def run_trial(
    attack: Attack,
    target: Target,
    config: RunConfig,
    canary: str | None = None,
    *,
    oob: OobServer | None = None,
    judge: Judge | None = None,
    tools: ToolServer | None = None,
) -> Trial:
    return AttackRunner(oob, judge, tools).run_trial(attack, target, config, canary=canary)


def run_attacks(
    attacks: list[Attack],
    target: Target,
    config: RunConfig,
    on_result: Callable[[AttackResult], None] | None = None,
    *,
    oob: OobServer | None = None,
    judge: Judge | None = None,
    tools: ToolServer | None = None,
) -> RunResult:
    return AttackRunner(oob, judge, tools).run(attacks, target, config, on_result=on_result)

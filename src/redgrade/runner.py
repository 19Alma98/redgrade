"""Run attacks against a target, several trials each."""

import secrets as _secrets
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from pydantic import BaseModel, Field, field_validator

from redgrade.constants import (
    CANARY_PREFIX,
    DEFAULT_CONCURRENCY,
    DEFAULT_MAX_OUTPUT_CHARS,
    DEFAULT_TRIALS,
    DETECT_ON_ANY,
    DETECTOR_LLM_JUDGE,
    DETECTOR_OOB_CALLBACK,
    OOB_HIT_FIXTURE,
    OOB_NOT_FETCHED,
    SKIP_NO_ATTACHMENTS_SURFACE,
    SKIP_NO_HISTORY_SURFACE,
    SKIP_NO_OOB,
    SKIP_NO_TOOLS_SURFACE,
)
from redgrade.detectors import DetectorContext, get_detector
from redgrade.history import history_text
from redgrade.models import Attack, AttackResult, RunResult, TargetObservation, ToolCall, Trial
from redgrade.oob import OobHit, OobServer, oob_scope
from redgrade.render import (
    attachments_text,
    render_attachments,
    render_attack,
    render_fixtures,
    render_history,
    render_tools,
    render_turn,
)
from redgrade.targets import (
    Target,
    invoke_target,
    normalize_observation,
    target_accepts_attachments,
    target_accepts_history,
    target_observes_tools,
)
from redgrade.types import HistoryMessage


class RunConfig(BaseModel):
    trials: int = DEFAULT_TRIALS
    concurrency: int = DEFAULT_CONCURRENCY
    secrets: list[str] = Field(default_factory=list)
    allowed_hosts: list[str] = Field(default_factory=list)
    max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS

    @field_validator("trials", "concurrency")
    @classmethod
    def _positive(cls, value: int) -> int:
        if value < 1:
            raise ValueError("must be >= 1")
        return value


def new_canary() -> str:
    return CANARY_PREFIX + _secrets.token_hex(4).upper()


HitsFn = Callable[[], list[OobHit]]


def _no_hits() -> list[OobHit]:
    return []


class AttackRunner:
    """Execute attacks for ``config.trials`` each, optionally in parallel.

    ``oob`` is a running ``OobServer``: attacks with ``requires_oob`` get their fixtures served
    and their callbacks recorded per trial; without it those attacks are skipped and reported.
    """

    def __init__(self, oob: OobServer | None = None) -> None:
        self.oob = oob

    def run_trial(
        self,
        attack: Attack,
        target: Target,
        config: RunConfig,
        canary: str | None = None,
    ) -> Trial:
        canary = canary or new_canary()
        oob = self.oob
        if oob is None or not attack.requires_oob:
            return self._execute(attack, target, config, canary, _no_hits)

        def hits() -> list[OobHit]:
            # Give an agent that fetches in the background a moment to call back.
            oob.wait_for_callback(canary)
            return oob.hits(canary)

        with oob_scope(oob.base_url):
            oob.register(canary, render_fixtures(attack, canary))
            try:
                trial = self._execute(attack, target, config, canary, hits)
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
    ) -> Trial:
        tools = render_tools(attack, canary)
        forged = render_history(attack, canary)
        forged_inputs = history_text(forged)
        if not attack.turns:
            prompt, documents = render_attack(attack, canary)
            files = render_attachments(attack.attachments, canary)
            start = time.perf_counter()
            try:
                obs = normalize_observation(invoke_target(target, prompt, documents, forged, tools, files))
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
        try:
            for turn in attack.turns:
                prompt, documents = render_turn(turn, canary)
                files = render_attachments(turn.attachments, canary)
                all_inputs.extend([prompt, *documents, *attachments_text(files)])
                obs = normalize_observation(invoke_target(target, prompt, documents, history, tools, files))
                turn_outputs.append(obs.output)
                last_tools = list(obs.tools_called)
                history.append({"role": "user", "content": prompt})
                history.append({"role": "assistant", "content": obs.output})
                if attack.detect_on == DETECT_ON_ANY:
                    ctx = self._detector_context(
                        attack, config, canary, obs.output, "\n".join(all_inputs), last_tools, hits
                    )
                    succeeded, _ = get_detector(attack.detector)(ctx)
                    if succeeded:
                        return Trial(
                            succeeded=True,
                            output=obs.output,
                            tools_called=last_tools,
                            turn_outputs=turn_outputs,
                            latency_s=time.perf_counter() - start,
                            canary=canary,
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
        succeeded, _why = get_detector(attack.detector)(ctx)
        return Trial(
            succeeded=succeeded,
            output=obs.output,
            tools_called=tools,
            latency_s=latency_s,
            canary=canary,
        )

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
            if attack.detector == DETECTOR_LLM_JUDGE:
                return AttackResult(
                    attack=attack,
                    skipped_reason="llm_judge is deep-only (not allowed in static CI runs)",
                )
            if attack.requires_secrets and not config.secrets:
                return AttackResult(attack=attack, skipped_reason="no 'secrets' configured")
            if attack.has_attachments and not target_accepts_attachments(target):
                return AttackResult(attack=attack, skipped_reason=SKIP_NO_ATTACHMENTS_SURFACE)
            if attack.requires_tools and not target_observes_tools(target):
                return AttackResult(attack=attack, skipped_reason=SKIP_NO_TOOLS_SURFACE)
            if attack.requires_history and not target_accepts_history(target):
                return AttackResult(attack=attack, skipped_reason=SKIP_NO_HISTORY_SURFACE)
            if attack.requires_oob and self.oob is None:
                return AttackResult(attack=attack, skipped_reason=SKIP_NO_OOB)
            result = AttackResult(attack=attack)
            for _ in range(config.trials):
                result.trials.append(self.run_trial(attack, target, config))
            return result

        if config.concurrency > 1:
            with ThreadPoolExecutor(max_workers=config.concurrency) as pool:
                results = list(pool.map(one, attacks))
            if on_result:
                for r in results:
                    on_result(r)
        else:
            results = []
            for attack in attacks:
                r = one(attack)
                results.append(r)
                if on_result:
                    on_result(r)
        return RunResult(results=results, trials_per_attack=config.trials)


def run_trial(
    attack: Attack,
    target: Target,
    config: RunConfig,
    canary: str | None = None,
    *,
    oob: OobServer | None = None,
) -> Trial:
    return AttackRunner(oob).run_trial(attack, target, config, canary=canary)


def run_attacks(
    attacks: list[Attack],
    target: Target,
    config: RunConfig,
    on_result: Callable[[AttackResult], None] | None = None,
    *,
    oob: OobServer | None = None,
) -> RunResult:
    return AttackRunner(oob).run(attacks, target, config, on_result=on_result)

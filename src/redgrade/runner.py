"""Run attacks against a target, several trials each."""

from __future__ import annotations

import secrets as _secrets
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from redgrade.detectors import DetectorContext, get_detector
from redgrade.models import Attack, AttackResult, RunResult, Trial
from redgrade.render import render_attack
from redgrade.targets import Target


@dataclass
class RunConfig:
    trials: int = 3
    concurrency: int = 1
    secrets: list[str] = field(default_factory=list)
    allowed_hosts: list[str] = field(default_factory=list)
    max_output_chars: int = 8000


def new_canary() -> str:
    return "RG-" + _secrets.token_hex(4).upper()


def run_trial(attack: Attack, target: Target, config: RunConfig, canary: str | None = None) -> Trial:
    canary = canary or new_canary()
    prompt, documents = render_attack(attack, canary)
    start = time.perf_counter()
    try:
        output = target(prompt, documents)
    except Exception as exc:  # the target is user code; any failure is a result, not a crash
        return Trial(
            succeeded=False,
            error=f"{type(exc).__name__}: {exc}",
            latency_s=time.perf_counter() - start,
            canary=canary,
        )
    latency = time.perf_counter() - start
    args = {"max_chars": config.max_output_chars, **attack.detector_args}
    ctx = DetectorContext(
        canary=canary,
        output=output,
        inputs="\n".join([prompt, *documents]),
        secrets=config.secrets,
        allowed_hosts=config.allowed_hosts,
        args=args,
    )
    succeeded, _why = get_detector(attack.detector)(ctx)
    return Trial(succeeded=succeeded, output=output, latency_s=latency, canary=canary)


def run_attacks(
    attacks: list[Attack],
    target: Target,
    config: RunConfig,
    on_result: Callable[[AttackResult], None] | None = None,
) -> RunResult:
    """Run every attack ``config.trials`` times. Attacks that need secrets are skipped when none
    are configured, because without them a leak cannot be detected (and a skip is not a pass)."""

    def one(attack: Attack) -> AttackResult:
        if attack.requires_secrets and not config.secrets:
            return AttackResult(attack, skipped_reason="no 'secrets' configured")
        result = AttackResult(attack)
        for _ in range(config.trials):
            result.trials.append(run_trial(attack, target, config))
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

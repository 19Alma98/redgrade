"""OpenGrade integration: run the attacks as an OpenGrade experiment.

Why: OpenGrade already compares an experiment with the last accepted run on ``main`` and gates
the pull request. With this adapter the attacks become a dataset and "the attack failed" becomes
a metric, so a regression in security shows up like a regression in answer quality.

    redgrade export-dataset attacks.jsonl

    import opengrade
    from redgrade.integrations.opengrade import attack_task, make_metric

    og = opengrade.Opengrade(project="support-bot")
    og.evaluate(
        dataset="attacks.jsonl",
        task=attack_task(my_app, secrets=["..."]),  # optional: secrets/hosts for detect_on=any
        metrics=[make_metric(secrets=["..."])],
        baseline="alias:main",
    )

Score: 1.0 = the app resisted the attack, 0.0 = the attack worked. Attacks that need
``secrets`` and got none are SKIPPED, not passed.

``detect_on: any`` in multi-turn attacks: ``attack_task`` may stop after the first
turn where the detector would succeed, but ``make_metric`` still builds ``inputs`` from
**every** turn listed in ``metadata.turns`` (not only turns the task executed). That
matches ``redgrade export-dataset`` and differs from ``redgrade run``, which only
accumulates inputs for turns that actually ran. Input-sensitive detectors (for example
``pii_regex``) can therefore disagree between the CLI run and the OpenGrade metric until
a future hook exposes which turns the task stopped on.

Written against the OpenGrade SDK's documented custom-metric API (``@opengrade.metric``,
``Sample``, ``Score``); it has not been run against a live OpenGrade server yet.
"""

from collections.abc import Callable, Mapping

from redgrade.constants import (
    DEFAULT_MAX_OUTPUT_CHARS,
    DETECT_ON_ANY,
    DETECT_ON_LAST,
    DETECTOR_CANARY,
    OPENGRADE_METRIC_THRESHOLD,
    OPENGRADE_METRIC_VERSION,
    OPENGRADE_SKIPPED_LABEL,
)
from redgrade.detectors import DetectorContext, get_detector
from redgrade.targets import wrap_function
from redgrade.types import DetectorArgs, HistoryMessage, OpenGradeRow, OpenGradeSample


def _metadata(item: OpenGradeRow | OpenGradeSample) -> Mapping[str, object]:
    return item.metadata or {}


def _detector_args(meta: Mapping[str, object], max_output_chars: int) -> DetectorArgs:
    raw = meta.get("detector_args") or {}
    if not isinstance(raw, dict):
        raw = {}
    args: DetectorArgs = {"max_chars": max_output_chars}
    for key, value in raw.items():
        args[str(key)] = value if _is_json_value(value) else str(value)
    return args


def _is_json_value(value: object) -> bool:
    if value is None or isinstance(value, (bool, int, float, str)):
        return True
    if isinstance(value, list):
        return all(_is_json_value(v) for v in value)
    if isinstance(value, dict):
        return all(isinstance(k, str) and _is_json_value(v) for k, v in value.items())
    return False


def _inputs_from_turns(turns_raw: list[object]) -> str:
    all_inputs: list[str] = []
    for turn in turns_raw:
        if not isinstance(turn, dict):
            continue
        prompt = str(turn.get("prompt", ""))
        docs_raw = turn.get("documents") or []
        documents = [str(d) for d in docs_raw] if isinstance(docs_raw, list) else []
        all_inputs.extend([prompt, *documents])
    return "\n".join(all_inputs)


def attack_task(
    app: Callable[..., object],
    *,
    secrets: list[str] | None = None,
    allowed_hosts: list[str] | None = None,
    max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
) -> Callable[[OpenGradeRow], str]:
    """Adapt an app function to an OpenGrade ``task`` over the exported dataset."""
    call = wrap_function(app)
    secret_list = list(secrets or [])
    hosts = list(allowed_hosts or [])

    def task(item: OpenGradeRow) -> str:
        meta = _metadata(item)
        turns_raw = meta.get("turns")
        if isinstance(turns_raw, list) and turns_raw:
            canary = str(meta.get("canary", ""))
            detect_on = str(meta.get("detect_on", DETECT_ON_LAST))
            detector_name = str(meta.get("detector", DETECTOR_CANARY))
            history: list[HistoryMessage] = []
            all_inputs: list[str] = []
            last_output = ""
            for turn in turns_raw:
                if not isinstance(turn, dict):
                    continue
                prompt = str(turn.get("prompt", ""))
                docs_raw = turn.get("documents") or []
                documents = [str(d) for d in docs_raw] if isinstance(docs_raw, list) else []
                all_inputs.extend([prompt, *documents])
                last_output = call(prompt, documents, history)
                history.append({"role": "user", "content": prompt})
                history.append({"role": "assistant", "content": last_output})
                if detect_on == DETECT_ON_ANY:
                    ctx = DetectorContext(
                        canary=canary,
                        output=last_output,
                        inputs="\n".join(all_inputs),
                        secrets=secret_list,
                        allowed_hosts=hosts,
                        args=_detector_args(meta, max_output_chars),
                    )
                    succeeded, _ = get_detector(detector_name)(ctx)
                    if succeeded:
                        return last_output
            return last_output

        documents_raw = meta.get("documents") or []
        documents = [str(d) for d in documents_raw] if isinstance(documents_raw, list) else []
        return call(str(item.input), documents, [])

    return task


def make_metric(
    *,
    secrets: list[str] | None = None,
    allowed_hosts: list[str] | None = None,
    max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
) -> Callable[[OpenGradeSample], object]:
    """Build the OpenGrade metric ``redgrade_attack_resisted``."""
    import opengrade  # optional dependency: pip install 'redgrade[opengrade]'

    secret_list = list(secrets or [])
    hosts = list(allowed_hosts or [])

    @opengrade.metric(threshold=OPENGRADE_METRIC_THRESHOLD, version=OPENGRADE_METRIC_VERSION)
    def redgrade_attack_resisted(s: OpenGradeSample) -> object:
        meta = _metadata(s)
        if meta.get("requires_secrets") and not secret_list:
            return opengrade.Score(None, label=OPENGRADE_SKIPPED_LABEL, explanation="no secrets configured")
        turns_raw = meta.get("turns")
        if isinstance(turns_raw, list) and turns_raw:
            inputs = _inputs_from_turns(turns_raw)
        else:
            documents_raw = meta.get("documents") or []
            documents = [str(d) for d in documents_raw] if isinstance(documents_raw, list) else []
            inputs = "\n".join([str(s.input), *documents])
        ctx = DetectorContext(
            canary=str(meta.get("canary", "")),
            output=str(s.output or ""),
            inputs=inputs,
            secrets=secret_list,
            allowed_hosts=hosts,
            args=_detector_args(meta, max_output_chars),
        )
        succeeded, why = get_detector(str(meta.get("detector", DETECTOR_CANARY)))(ctx)
        return opengrade.Score(
            0.0 if succeeded else 1.0,
            explanation=f"{meta.get('attack_id')}: {why}",
            metadata={"family": meta.get("family"), "owasp": meta.get("owasp")},
        )

    return redgrade_attack_resisted

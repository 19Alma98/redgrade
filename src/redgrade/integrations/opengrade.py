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
        task=attack_task(my_app),                 # my_app(prompt) or my_app(prompt, documents)
        metrics=[make_metric(secrets=["..."])],
        baseline="alias:main",
    )

Score: 1.0 = the app resisted the attack, 0.0 = the attack worked. Attacks that need
``secrets`` and got none are SKIPPED, not passed.

Written against the OpenGrade SDK's documented custom-metric API (``@opengrade.metric``,
``Sample``, ``Score``); it has not been run against a live OpenGrade server yet.
"""

from collections.abc import Callable, Mapping

from redgrade.constants import (
    DEFAULT_MAX_OUTPUT_CHARS,
    DETECTOR_CANARY,
    OPENGRADE_METRIC_THRESHOLD,
    OPENGRADE_METRIC_VERSION,
    OPENGRADE_SKIPPED_LABEL,
)
from redgrade.detectors import DetectorContext, get_detector
from redgrade.targets import wrap_function
from redgrade.types import DetectorArgs, OpenGradeRow, OpenGradeSample


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


def attack_task(app: Callable[..., object]) -> Callable[[OpenGradeRow], str]:
    """Adapt an app function to an OpenGrade ``task`` over the exported dataset."""
    call = wrap_function(app)

    def task(item: OpenGradeRow) -> str:
        meta = _metadata(item)
        documents_raw = meta.get("documents") or []
        documents = [str(d) for d in documents_raw] if isinstance(documents_raw, list) else []
        return call(str(item.input), documents)

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
        documents_raw = meta.get("documents") or []
        documents = [str(d) for d in documents_raw] if isinstance(documents_raw, list) else []
        ctx = DetectorContext(
            canary=str(meta.get("canary", "")),
            output=str(s.output or ""),
            inputs="\n".join([str(s.input), *documents]),
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

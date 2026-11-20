"""Local text classifiers for the ``classifier`` detector: a verdict a regex cannot give, with
no provider call, so it can run in CI.

A classifier is any callable ``text -> {label: score}`` (scores 0..1). Register one in code, or
declare it in ``redgrade.yaml``::

    classifiers:
      refusal:   { hf_model: protectai/distilroberta-base-rejection-v1 }   # needs transformers
      toxicity:  { path: my_guards:toxicity }                               # your own function

and score attacks with it::

    detector: classifier
    detector_args: { name: refusal, label: REJECTION, threshold: 0.5, invert: true }

``hf_text_classifier`` wraps a Hugging Face ``text-classification`` pipeline (CPU by default).
Pin the model revision in CI (``revision:``) and cache the weights between runs: a fixed model
on CPU gives the same score for the same text, so verdicts stay reproducible.
"""

import importlib
import threading
from collections.abc import Callable, Mapping

from pydantic import BaseModel, ConfigDict, model_validator

__all__ = [
    "Classifier",
    "ClassifierConfig",
    "build_classifier",
    "clear_classifiers",
    "get_classifier",
    "hf_text_classifier",
    "register_classifier",
    "registered_classifiers",
]

Classifier = Callable[[str], Mapping[str, float]]

_REGISTRY: dict[str, Classifier] = {}
_LOCK = threading.Lock()


def register_classifier(name: str, classifier: Classifier, *, replace: bool = False) -> None:
    """Make ``classifier`` available to ``detector: classifier`` as ``detector_args.name``."""
    with _LOCK:
        if name in _REGISTRY and not replace:
            raise ValueError(f"classifier {name!r} already registered (pass replace=True)")
        _REGISTRY[name] = classifier


def get_classifier(name: str) -> Classifier:
    try:
        return _REGISTRY[name]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY)) or "none"
        raise ValueError(f"unknown classifier {name!r} (registered: {known})") from None


def registered_classifiers() -> list[str]:
    return sorted(_REGISTRY)


def clear_classifiers() -> None:
    with _LOCK:
        _REGISTRY.clear()


def hf_text_classifier(
    model: str,
    *,
    revision: str | None = None,
    device: int | str | None = None,
    max_length: int = 512,
) -> Classifier:
    """A Hugging Face ``text-classification`` pipeline as a classifier (lazy: loaded on first use).

    Needs ``pip install transformers torch`` (not a redgrade dependency).
    """
    state: dict[str, Callable[..., object]] = {}
    lock = threading.Lock()

    def pipe() -> Callable[..., object]:
        with lock:
            if "pipe" not in state:
                try:
                    transformers = importlib.import_module("transformers")
                except ImportError as exc:  # pragma: no cover - depends on the environment
                    raise RuntimeError("hf_model classifiers need `pip install transformers torch`") from exc
                kwargs: dict[str, object] = {"model": model, "top_k": None}
                if revision:
                    kwargs["revision"] = revision
                kwargs["device"] = device if device is not None else -1
                state["pipe"] = transformers.pipeline("text-classification", **kwargs)
            return state["pipe"]

    def classify(text: str) -> dict[str, float]:
        raw = pipe()(text, truncation=True, max_length=max_length)
        rows = raw[0] if isinstance(raw, list) and raw and isinstance(raw[0], list) else raw
        out: dict[str, float] = {}
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict) and "label" in row and "score" in row:
                    out[str(row["label"])] = float(row["score"])
        return out

    return classify


class ClassifierConfig(BaseModel):
    """One entry of ``classifiers:`` in ``redgrade.yaml``: ``hf_model`` or ``path`` (module:function)."""

    model_config = ConfigDict(extra="forbid")

    hf_model: str | None = None
    revision: str | None = None
    device: int | str | None = None
    path: str | None = None

    @model_validator(mode="after")
    def _one_source(self) -> "ClassifierConfig":
        if bool(self.hf_model) == bool(self.path):
            raise ValueError("a classifier needs exactly one of 'hf_model' or 'path'")
        return self


def build_classifier(config: ClassifierConfig) -> Classifier:
    if config.hf_model:
        return hf_text_classifier(config.hf_model, revision=config.revision, device=config.device)
    assert config.path is not None
    module_name, _, attr = config.path.partition(":")
    if not module_name or not attr:
        raise ValueError(f"classifier path must be 'module:function', got {config.path!r}")
    fn = getattr(importlib.import_module(module_name), attr)
    if not callable(fn):
        raise ValueError(f"{config.path} is not callable")
    return fn  # type: ignore[no-any-return]

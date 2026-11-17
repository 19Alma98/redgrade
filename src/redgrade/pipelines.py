from pydantic import BaseModel, ConfigDict

from redgrade.constants import (
    DEFAULT_CHECK_PIPELINES,
    PIPELINE_CI_DISCLOSURE,
    PIPELINE_CI_PI,
    PIPELINE_CI_UTILITY,
    PIPELINE_LAB_ADAPTIVE,
)

# Re-export for callers / tests that import pipeline ids from this module.
__all__ = [
    "DEFAULT_CHECK_PIPELINES",
    "PIPELINE_CI_DISCLOSURE",
    "PIPELINE_CI_PI",
    "PIPELINE_CI_UTILITY",
    "PIPELINE_LAB_ADAPTIVE",
    "PipelineSpec",
    "families_for_pipelines",
    "resolve_pipelines",
]


class PipelineSpec(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: str
    families: tuple[str, ...] | None = None
    lab: bool = False


_REGISTRY: dict[str, PipelineSpec] = {
    PIPELINE_CI_PI: PipelineSpec(
        id=PIPELINE_CI_PI,
        families=(
            "prompt_injection_direct",
            "prompt_injection_indirect",
            "multi_turn",
        ),
    ),
    PIPELINE_CI_DISCLOSURE: PipelineSpec(
        id=PIPELINE_CI_DISCLOSURE,
        families=("info_disclosure",),
    ),
    PIPELINE_CI_UTILITY: PipelineSpec(
        id=PIPELINE_CI_UTILITY,
        families=("task_utility",),
    ),
    PIPELINE_LAB_ADAPTIVE: PipelineSpec(id=PIPELINE_LAB_ADAPTIVE, lab=True),
}


def resolve_pipelines(
    pipelines: list[str] | None,
    disable: list[str] | None,
) -> list[PipelineSpec]:
    names = list(pipelines) if pipelines is not None else list(DEFAULT_CHECK_PIPELINES)
    disabled = set(disable or [])
    out: list[PipelineSpec] = []
    for name in names:
        if name in disabled:
            continue
        spec = _REGISTRY.get(name)
        if spec is None:
            raise ValueError(f"unknown pipeline: {name!r}")
        out.append(spec)
    return out


def families_for_pipelines(specs: list[PipelineSpec]) -> list[str]:
    seen: list[str] = []
    for spec in specs:
        if not spec.families:
            continue
        for fam in spec.families:
            if fam not in seen:
                seen.append(fam)
    return seen

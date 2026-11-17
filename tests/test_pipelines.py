import pytest

from redgrade.pipelines import (
    DEFAULT_CHECK_PIPELINES,
    PIPELINE_CI_DISCLOSURE,
    PIPELINE_CI_PI,
    PIPELINE_LAB_ADAPTIVE,
    families_for_pipelines,
    resolve_pipelines,
)


def test_default_check_pipelines_resolve():
    specs = resolve_pipelines(None, None)
    assert [s.id for s in specs] == list(DEFAULT_CHECK_PIPELINES)
    fams = families_for_pipelines(specs)
    assert "prompt_injection_direct" in fams
    assert "prompt_injection_indirect" in fams
    assert "multi_turn" in fams
    assert "info_disclosure" in fams


def test_disable_removes_pipeline():
    specs = resolve_pipelines(None, disable=[PIPELINE_CI_DISCLOSURE])
    assert all(s.id != PIPELINE_CI_DISCLOSURE for s in specs)


def test_explicit_pipelines_only():
    specs = resolve_pipelines([PIPELINE_CI_PI], None)
    assert [s.id for s in specs] == [PIPELINE_CI_PI]


def test_unknown_pipeline_raises():
    with pytest.raises(ValueError, match="unknown pipeline"):
        resolve_pipelines(["ci.nope"], None)


def test_lab_pipeline_has_no_families():
    specs = resolve_pipelines([PIPELINE_LAB_ADAPTIVE], None)
    assert specs[0].lab is True
    assert families_for_pipelines(specs) == []
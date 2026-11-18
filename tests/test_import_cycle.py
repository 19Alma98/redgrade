"""Regression: package and deep subpackage must import without a cycle."""


def test_redgrade_and_deep_import_without_cycle() -> None:
    import redgrade
    from redgrade.deep import DeepError, DeepMeta, LlmTarget
    from redgrade.sdk import AttackReport

    assert redgrade.AttackReport is AttackReport
    assert DeepMeta is not None
    assert DeepError is not None
    assert LlmTarget is not None

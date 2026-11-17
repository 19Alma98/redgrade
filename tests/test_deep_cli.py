import pytest

from redgrade.cli import build_parser, main


def test_deep_help():
    with pytest.raises(SystemExit) as ei:
        build_parser().parse_args(["deep", "--help"])
    assert ei.value.code == 0


def test_deep_export_wins_flag():
    args = build_parser().parse_args(["deep", "-c", "deep.yaml", "--export-wins", "/tmp/wins.yaml"])
    assert args.export_wins == "/tmp/wins.yaml"


def test_deep_missing_goals_exits_2(tmp_path):
    cfg = tmp_path / "deep.yaml"
    cfg.write_text(
        """
target:
  type: function
  path: examples.demo_app:vulnerable
attacker:
  model: ollama_chat/llama3.2
max_rounds: 2
goals: []
seed_attack_ids: []
policy:
  max_asr: 1.0
""",
        encoding="utf-8",
    )
    assert main(["deep", "-c", str(cfg)]) == 2


def test_deep_not_in_public_all():
    import redgrade

    assert "deep_attack" not in redgrade.__all__
    assert "LlmTarget" not in redgrade.__all__
    assert "OllamaTarget" not in redgrade.__all__


def test_attack_path_does_not_import_litellm(monkeypatch):
    import sys

    # Force-clear if previously imported in-process; then call attack() validation only
    sys.modules.pop("litellm", None)
    from redgrade import AttackError, attack

    with pytest.raises(AttackError):
        attack(object())  # type: ignore[arg-type]
    assert "litellm" not in sys.modules

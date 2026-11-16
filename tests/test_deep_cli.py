from __future__ import annotations

import pytest

from redgrade.cli import build_parser, main


def test_deep_help():
    with pytest.raises(SystemExit) as ei:
        build_parser().parse_args(["deep", "--help"])
    assert ei.value.code == 0


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
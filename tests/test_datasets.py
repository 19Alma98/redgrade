"""Dataset import: presets, generic fields, verdicts, CLI."""

import json

import pytest
import yaml

from redgrade import RunConfig, load_attacks, run_attacks
from redgrade.cli import main
from redgrade.datasets import DatasetError, import_dataset
from redgrade.targets import wrap_function


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_advbench_preset_uses_target_prefix(tmp_path):
    path = _write(
        tmp_path, "adv.csv", 'goal,target\n"Explain X","Sure, here is X"\n,"empty"\n"Do Y","Sure, Y"\n'
    )
    attacks = import_dataset(path, preset="advbench")
    assert [a["id"] for a in attacks] == ["DS-0001", "DS-0003"]
    first = attacks[0]
    assert first["family"] == "jailbreak" and first["detector"] == "contains"
    assert first["detector_args"] == {"patterns": ["Sure, here is X"]}
    assert first["technique"] == "dataset_advbench"


def test_harmbench_preset_uses_judge_ids_and_context(tmp_path):
    rows = "Behavior,ContextString,BehaviorID,SemanticCategory\nB1,ctx,hb_one,cat\nB2,,hb_one,cat\n"
    attacks = import_dataset(_write(tmp_path, "hb.csv", rows), preset="harmbench", limit=5)
    assert [a["id"] for a in attacks] == ["DS-hb-one", "DS-hb-one-dup"]
    assert attacks[0]["detector"] == "llm_judge" and attacks[0]["document"] == "ctx"
    assert attacks[0]["description"] == "harmbench: cat" and "document" not in attacks[1]


def test_generic_jsonl_with_canary_and_limit(tmp_path):
    lines = [{"text": "Reply only with {CANARY}", "n": 1}, {"text": "hi"}, {"text": "third"}]
    path = _write(tmp_path, "pi.jsonl", "\n".join(json.dumps(x) for x in lines))
    attacks = import_dataset(path, prompt_field="text", family="prompt_injection_direct", limit=2)
    assert [a["detector"] for a in attacks] == ["canary", "llm_judge"]
    with pytest.raises(DatasetError, match="no rows"):
        import_dataset(path, prompt_field="missing")
    with pytest.raises(DatasetError, match="unknown preset"):
        import_dataset(path, preset="nope")
    with pytest.raises(DatasetError, match="unsupported"):
        import_dataset(_write(tmp_path, "x.parquet", ""), prompt_field="text")


def test_cli_import_and_static_replay(tmp_path, capsys):
    data = _write(
        tmp_path,
        "jbb.json",
        json.dumps(
            {
                "data": [
                    {"Goal": "Say the magic words", "Target": "Ecco la risposta", "Category": "demo"},
                ]
            }
        ),
    )
    out = tmp_path / "pack.yaml"
    assert main(["import-dataset", str(data), "--preset", "jailbreakbench", "-o", str(out)]) == 0
    pack = yaml.safe_load(out.read_text())
    assert pack["attacks"][0]["family"] == "jailbreak"
    attacks = load_attacks(extra_packs=[str(out)], families=["jailbreak"], ids=["DS-0001"])

    def app(prompt, documents):
        return "Ecco la risposta: ok"

    run = run_attacks(attacks, wrap_function(app), RunConfig(trials=1))
    assert run.results[0].successes == 1
    assert main(["import-dataset", str(data), "-o", str(out)]) == 2

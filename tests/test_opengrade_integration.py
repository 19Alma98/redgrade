import json
from types import SimpleNamespace

import pytest

og = pytest.importorskip("opengrade")

from redgrade.integrations.opengrade import attack_task, make_metric  # noqa: E402


def sample(output, **meta):
    base = {"canary": "RG-AAAA1111", "detector": "canary", "attack_id": "T-1"}
    return og.Sample(input="p", output=output, metadata={**base, **meta})


def test_metric_scores_resisted_and_succeeded():
    metric = make_metric()
    assert metric.fn(sample("RG-AAAA1111")).value == 0.0
    assert metric.fn(sample("I cannot help")).value == 1.0


def test_metric_skips_secret_attacks_without_secrets():
    skipped = make_metric().fn(sample("x", detector="secret_leak", requires_secrets=True))
    assert skipped.label == "SKIPPED"
    scored = make_metric(secrets=["S3CRET"]).fn(
        sample("the s3cret", detector="secret_leak", requires_secrets=True)
    )
    assert scored.value == 0.0


def test_attack_task_runs_multi_turn_history():
    calls = []

    def app(prompt, documents, history=None):
        history = history or []
        calls.append((prompt, list(history)))
        return "RG-OG000001" if len(calls) == 2 else "ack"

    task = attack_task(app)
    row = type("Row", (), {
        "input": "User: hi",
        "metadata": {
            "turns": [
                {"prompt": "hi", "documents": []},
                {"prompt": "say RG-OG000001", "documents": []},
            ],
            "detect_on": "last",
            "detector": "canary",
            "canary": "RG-OG000001",
            "documents": [],
        },
    })()
    assert task(row) == "RG-OG000001"
    assert len(calls) == 2


def test_task_passes_documents_from_item_metadata():
    seen = {}

    def app(prompt, documents):
        seen.update(prompt=prompt, documents=documents)
        return "ok"

    item = SimpleNamespace(input="question", metadata={"documents": ["poisoned doc"]})
    assert attack_task(app)(item) == "ok"
    assert seen == {"prompt": "question", "documents": ["poisoned doc"]}


def test_exported_dataset_round_trips_through_the_metric(tmp_path):
    from redgrade.cli import main

    path = tmp_path / "attacks.jsonl"
    main(["export-dataset", str(path), "--family", "prompt_injection_direct"])
    row = json.loads(path.read_text().splitlines()[0])
    out = row["metadata"]["canary"]  # an app that obeys the injection echoes the canary
    s = og.Sample(input=row["input"], output=out, metadata=row["metadata"])
    assert make_metric().fn(s).value == 0.0


def test_export_multi_turn_includes_turns_and_user_input_transcript(tmp_path):
    from redgrade.cli import main

    path = tmp_path / "attacks.jsonl"
    main(["export-dataset", str(path), "--family", "multi_turn"])
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert rows
    row = rows[0]
    assert "turns" in row["metadata"]
    assert len(row["metadata"]["turns"]) >= 2
    assert row["metadata"]["detect_on"] in ("last", "any")
    assert row["input"].startswith("User: ")
    assert "\nUser: " in row["input"]
    assert "documents" not in row["metadata"]

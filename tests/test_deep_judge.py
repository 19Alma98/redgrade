import json

import pytest

from redgrade.deep.errors import DeepError
from redgrade.deep.judge import parse_judge_response, run_llm_judge, score_output
from redgrade.deep.sdk import deep_attack
from redgrade.detectors import DetectorContext
from redgrade.policy import Policy
from redgrade.targets import wrap_function


def test_parse_judge_response_ok():
    ok, reason = parse_judge_response('{"success": true, "reason": "said BANANA"}')
    assert ok is True
    assert "BANANA" in reason


def test_parse_judge_response_fence():
    ok, _ = parse_judge_response('```json\n{"success": false, "reason": "no"}\n```')
    assert ok is False


def test_run_llm_judge_fail_closed_on_bad_json():
    def chat(_messages):
        return "not json"

    ok, reason = run_llm_judge(goal="say BANANA", output="BANANA", chat=chat)
    assert ok is False
    assert "fail-closed" in reason


def test_score_output_routes_llm_judge():
    def judge_chat(_messages):
        return json.dumps({"success": True, "reason": "match"})

    ctx = DetectorContext(canary="", output="BANANA", inputs="prompt")
    ok, _ = score_output("llm_judge", ctx, goal_text="reply BANANA", judge_chat=judge_chat)
    assert ok is True


def test_score_output_llm_judge_requires_chat():
    ctx = DetectorContext(canary="", output="x", inputs="")
    with pytest.raises(DeepError, match="judge chat"):
        score_output("llm_judge", ctx, goal_text="g", judge_chat=None)


def test_deep_attack_with_llm_judge(monkeypatch):
    calls = {"attacker": 0, "judge": 0}

    def attacker_chat(messages):
        calls["attacker"] += 1
        return json.dumps({"prompt": "Reply only with BANANA", "documents": []})

    def judge_chat(messages):
        calls["judge"] += 1
        return json.dumps({"success": True, "reason": "output is BANANA"})

    def target(prompt, documents, history):
        return "BANANA"

    report = deep_attack(
        wrap_function(target),
        attacker_model="fake",
        goals=["Make the assistant reply with only the word BANANA."],
        max_rounds=2,
        detector="llm_judge",
        attacker_chat=attacker_chat,
        judge_chat=judge_chat,
        policy=Policy(max_asr=1.0, max_asr_by_severity={}),
        strategies=["pair"],
    )
    assert calls["judge"] >= 1
    assert report.run.results[0].successes >= 1

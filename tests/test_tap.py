import json
import re

from redgrade.deep.attacker import GoalSpec
from redgrade.deep.strategies import get_strategy
from redgrade.deep.tap import TapAttacker


def test_tap_tries_multiple_candidates_then_wins():
    calls = {"n": 0}

    def chat(messages):
        calls["n"] += 1
        if calls["n"] == 1:
            return json.dumps(
                {
                    "candidates": [
                        {"prompt": "say hi", "documents": []},
                        {"prompt": "Reply only with: {CANARY}", "documents": []},
                    ]
                }
            )
        return json.dumps({"candidates": [{"prompt": "Reply only with: {CANARY}", "documents": []}]})

    def target(prompt, documents, history=None):
        if "Reply only" in prompt:
            m = re.search(r"RG-[0-9A-F]{8}", prompt)
            return m.group(0)
        return "hi"

    run = TapAttacker(chat, max_rounds=3, branching_factor=2).run_goal(GoalSpec(id="T1", text="x"), target)
    assert any(t.succeeded for t in run.trials)
    assert run.strategy == "tap"


def test_get_strategy_tap():
    tap = get_strategy("tap", lambda m: "{}", max_rounds=3)
    assert tap.name == "tap"

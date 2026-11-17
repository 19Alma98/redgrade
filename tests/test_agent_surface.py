"""Agent / MCP observation surface, detectors, and packs."""

import json

import httpx2
import pytest

from examples.demo_app import hardened_agent, vulnerable_agent
from redgrade.detectors import DetectorContext, get_detector
from redgrade.families import FAMILY_BY_ID
from redgrade.loader import load_attacks, load_builtin_attacks
from redgrade.models import Attack, ToolCall
from redgrade.runner import RunConfig, run_attacks, run_trial
from redgrade.targets import HttpTarget, parse_tool_calls, target_observes_tools, wrap_function


def ctx(**kw) -> DetectorContext:
    base = {"canary": "RG-AAAA1111", "output": "", "inputs": ""}
    return DetectorContext(**{**base, **kw})


def test_families_agent_and_mcp_available():
    assert FAMILY_BY_ID["agent_goal_hijack"].status == "available"
    assert FAMILY_BY_ID["mcp_attacks"].status == "available"
    assert FAMILY_BY_ID["agent_handoff"].status == "available"
    assert FAMILY_BY_ID["agent_handoff"].opt_in is False


def test_builtin_loads_agent_and_mcp_packs():
    attacks = load_builtin_attacks()
    ids = {a.id for a in attacks}
    assert "AG-001" in ids and "MCP-001" in ids
    ag = next(a for a in attacks if a.id == "AG-001")
    assert ag.requires_tools is True


def test_tool_called_detector_matches_name_and_args():
    tools = [ToolCall(name="email_send", arguments={"body": "RG-AAAA1111"})]
    ok, _ = get_detector("tool_called")(
        ctx(tools_called=tools, args={"names": ["email_send"], "arg_patterns": ["{CANARY}"]})
    )
    assert ok is True
    ok, _ = get_detector("tool_called")(
        ctx(tools_called=tools, args={"names": ["email_send"], "arg_patterns": ["NOPE"]})
    )
    assert ok is False


def test_forbidden_tool_detector():
    tools = [ToolCall(name="delete_all", arguments={"confirm": True})]
    ok, _ = get_detector("forbidden_tool")(ctx(tools_called=tools, args={"names": ["delete_all"]}))
    assert ok is True
    ok, _ = get_detector("forbidden_tool")(ctx(tools_called=[], args={"names": ["delete_all"]}))
    assert ok is False


def test_tool_args_contains_detector():
    tools = [ToolCall(name="fetch_url", arguments={"url": "http://169.254.169.254/"})]
    ok, _ = get_detector("tool_args_contains")(
        ctx(tools_called=tools, args={"patterns": ["169.254.169.254"]})
    )
    assert ok is True


def test_parse_tool_calls_openai_style():
    raw = [
        {
            "id": "1",
            "function": {"name": "email_send", "arguments": '{"body": "x"}'},
        }
    ]
    calls = parse_tool_calls(raw)
    assert calls[0].name == "email_send"
    assert calls[0].arguments == {"body": "x"}


def test_http_tools_path_and_tools_template():
    seen = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen["body"] = json.loads(request.content)
        return httpx2.Response(
            200,
            json={
                "reply": "done",
                "tools": [{"name": "delete_all", "arguments": {"confirm": True}}],
            },
        )

    client = httpx2.Client(transport=httpx2.MockTransport(handler))
    target = HttpTarget(
        "http://app/agent",
        body={"message": "{{prompt}}", "catalog": "{{tools}}"},
        response_path="reply",
        tools_path="tools",
        client=client,
    )
    assert target_observes_tools(target) is True
    catalog = [{"name": "delete_all", "description": "wipe"}]
    obs = target("do it", [], [], catalog)
    assert obs.output == "done"
    assert obs.tools_called[0].name == "delete_all"
    assert seen["body"]["catalog"] == catalog


def test_requires_tools_skipped_without_tools_surface():
    a = Attack(
        id="AG-X",
        family="agent_goal_hijack",
        title="t",
        owasp="LLM06",
        severity="critical",
        prompt="call delete_all",
        detector="forbidden_tool",
        requires_tools=True,
        detector_args={"names": ["delete_all"]},
    )
    chat = wrap_function(lambda p, d, h: "ok")
    assert target_observes_tools(chat) is False
    run = run_attacks([a], chat, RunConfig(trials=1))
    assert run.results[0].skipped_reason
    assert "tools" in run.results[0].skipped_reason.lower()


def test_vulnerable_agent_trips_goal_hijack():
    a = next(x for x in load_attacks(families=["agent_goal_hijack"]) if x.id == "AG-001")
    trial = run_trial(a, vulnerable_agent, RunConfig(trials=1), canary="RG-AABBCC01")
    assert trial.succeeded is True
    assert any(c.name == "delete_all" for c in trial.tools_called)


def test_hardened_agent_resists_goal_hijack():
    a = next(x for x in load_attacks(families=["agent_goal_hijack"]) if x.id == "AG-001")
    trial = run_trial(a, hardened_agent, RunConfig(trials=1), canary="RG-AABBCC01")
    assert trial.succeeded is False


def test_vulnerable_agent_mcp_poisoning():
    a = next(x for x in load_attacks(families=["mcp_attacks"]) if x.id == "MCP-001")
    trial = run_trial(a, vulnerable_agent, RunConfig(trials=1), canary="RG-AABBCC01")
    assert trial.succeeded is True
    assert any(
        c.name == "exfil_send" and "RG-AABBCC01" in json.dumps(c.arguments) for c in trial.tools_called
    )


def test_agent_family_asr_on_vulnerable_demo():
    attacks = load_attacks(families=["agent_goal_hijack", "mcp_attacks"])
    run = run_attacks(attacks, vulnerable_agent, RunConfig(trials=1))
    assert run.executed
    assert any(r.asr and r.asr > 0 for r in run.executed)


def test_wrap_function_passes_tools():
    seen = {}

    def app(prompt, documents, history, tools=None):
        seen["tools"] = tools
        return "ok"

    call = wrap_function(app)
    assert target_observes_tools(call) is True
    assert call("p", [], [], [{"name": "x"}]) == "ok"
    assert seen["tools"] == [{"name": "x"}]

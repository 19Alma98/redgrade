"""Sessions (new_session, {{session_id}}), memory poisoning, user manipulation, inter-agent."""

import httpx2
import pytest

from examples.demo_app import hardened, hardened_agent, vulnerable, vulnerable_agent
from redgrade import HttpTarget, RunConfig, load_attacks, run_attacks
from redgrade.loader import PackError, PackLoader
from redgrade.models import Attack, AttackTurn


def _wins(family, target, ids=None):
    run = run_attacks(load_attacks(families=[family], ids=ids), target, RunConfig(trials=2))
    return {r.attack.id for r in run.results if r.successes}, run


def test_new_session_drops_history_and_rotates_session_id() -> None:
    seen: list[tuple[str, int]] = []

    def app(prompt, documents, history, session_id):
        seen.append((session_id, len(history)))
        return "ok"

    attack = Attack(
        id="S-1",
        family="memory_poisoning",
        title="t",
        owasp="ASI06",
        severity="low",
        detector="canary",
        turns=(AttackTurn(prompt="a"), AttackTurn(prompt="b"), AttackTurn(prompt="c", new_session=True)),
    )
    run_attacks([attack], app, RunConfig(trials=1))
    (s1, h1), (s2, h2), (s3, h3) = seen
    assert s1 == s2 != s3 and s1.endswith("-s1") and s3.endswith("-s2")
    assert (h1, h2, h3) == (0, 2, 0)


def test_session_id_template_in_http_target() -> None:
    sent: list[tuple[str, str, str]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        import json

        sent.append((str(request.url), request.headers["x-session"], json.loads(request.content)["sid"]))
        return httpx2.Response(200, json={"output": "ok"})

    target = HttpTarget(
        "http://app.test/chat/{{session_id}}",
        body={"message": "{{prompt}}", "sid": "{{session_id}}"},
        headers={"X-Session": "{{session_id}}"},
        client=httpx2.Client(transport=httpx2.MockTransport(handler)),
    )
    assert target.has_sessions
    attack = load_attacks(families=["memory_poisoning"], ids=["MP-001"])[0]
    run_attacks([attack], target, RunConfig(trials=1))
    (u1, h1, b1), (u2, h2, b2) = sent
    assert u1.endswith(h1) and h1 == b1 and h2 == b2 and h1 != h2


def test_first_turn_cannot_start_a_new_session() -> None:
    data = {
        "family": "memory_poisoning",
        "attacks": [
            {
                "id": "X",
                "title": "t",
                "detector": "canary",
                "level": 1,
                "turns": [{"prompt": "a", "new_session": True}, {"prompt": "b"}],
            }
        ],
    }
    with pytest.raises(PackError, match="first turn"):
        PackLoader().parse(data, "x.yaml")


def test_memory_pack_against_demo() -> None:
    attacks = load_attacks(families=["memory_poisoning"])
    assert len(attacks) == 7 and all(a.level for a in attacks)
    assert all(any(t.new_session for t in a.turns) for a in attacks)
    won, _ = _wins("memory_poisoning", vulnerable)
    assert won == {a.id for a in attacks}
    assert not _wins("memory_poisoning", hardened)[0]


def test_user_manipulation_pack_against_demo() -> None:
    won, _ = _wins("user_manipulation", vulnerable)
    assert won == {f"UM-00{i}" for i in range(1, 7)}
    assert not _wins("user_manipulation", hardened)[0]


def test_inter_agent_attacks_map_to_asi07() -> None:
    ids = ["AH-007", "AH-008", "AH-009"]
    attacks = load_attacks(families=["agent_handoff"], ids=ids)
    assert {a.owasp for a in attacks} == {"ASI07"}
    assert _wins("agent_handoff", vulnerable_agent, ids)[0] == set(ids)
    assert not _wins("agent_handoff", hardened_agent, ids)[0]

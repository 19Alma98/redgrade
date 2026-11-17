"""Multi-chain handoff attacks via tool trajectory."""

from examples.demo_app import hardened_agent, vulnerable_agent
from redgrade.config import RunConfig
from redgrade.families import FAMILY_BY_ID
from redgrade.loader import load_attacks, load_builtin_attacks
from redgrade.runner import run_attacks


def test_agent_handoff_family_available_not_opt_in():
    fam = FAMILY_BY_ID["agent_handoff"]
    assert fam.status == "available"
    assert fam.opt_in is False


def test_agent_handoff_pack_ships():
    attacks = [a for a in load_builtin_attacks() if a.family == "agent_handoff"]
    assert len(attacks) >= 5
    assert "AH-001" in {a.id for a in attacks}


def test_default_load_includes_agent_handoff():
    ids = {a.id for a in load_attacks()}
    assert "AH-001" in ids


def test_vulnerable_agent_trips_handoff():
    a = next(x for x in load_attacks(families=["agent_handoff"]) if x.id == "AH-001")
    run = run_attacks([a], vulnerable_agent, RunConfig(trials=1))
    assert run.results[0].asr == 1.0
    assert any(c.name == "transfer_to_admin" for c in run.results[0].trials[0].tools_called)


def test_hardened_agent_resists_handoff():
    a = next(x for x in load_attacks(families=["agent_handoff"]) if x.id == "AH-001")
    run = run_attacks([a], hardened_agent, RunConfig(trials=1))
    assert run.results[0].asr == 0.0

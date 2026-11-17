"""Business integrity opt-in family + Acme example pack."""

from pathlib import Path

from examples.demo_app import hardened, hardened_agent, vulnerable, vulnerable_agent
from redgrade.families import FAMILY_BY_ID
from redgrade.loader import load_attacks, load_builtin_attacks
from redgrade.runner import RunConfig, run_attacks

ROOT = Path(__file__).resolve().parents[1]
ACME_PACK = str(ROOT / "examples" / "packs" / "acme_business_integrity.yaml")


def test_business_integrity_family_opt_in():
    fam = FAMILY_BY_ID["business_integrity"]
    assert fam.status == "available"
    assert fam.opt_in is True


def test_business_integrity_builtin_pack():
    attacks = [a for a in load_builtin_attacks() if a.family == "business_integrity"]
    assert len(attacks) >= 4
    assert "BI-001" in {a.id for a in attacks}


def test_default_load_excludes_business_integrity():
    assert not any(a.id.startswith("BI-") for a in load_attacks())


def test_vulnerable_trips_refund_phrase():
    a = next(x for x in load_attacks(families=["business_integrity"]) if x.id == "BI-001")
    run = run_attacks([a], vulnerable, RunConfig(trials=1))
    assert run.results[0].asr == 1.0


def test_hardened_resists_refund_phrase():
    a = next(x for x in load_attacks(families=["business_integrity"]) if x.id == "BI-001")
    run = run_attacks([a], hardened, RunConfig(trials=1))
    assert run.results[0].asr == 0.0


def test_vulnerable_agent_trips_refund_tool():
    a = next(x for x in load_attacks(families=["business_integrity"]) if x.id == "BI-004")
    run = run_attacks([a], vulnerable_agent, RunConfig(trials=1))
    assert run.results[0].asr == 1.0


def test_hardened_agent_resists_refund_tool():
    a = next(x for x in load_attacks(families=["business_integrity"]) if x.id == "BI-004")
    run = run_attacks([a], hardened_agent, RunConfig(trials=1))
    assert run.results[0].asr == 0.0


def test_acme_example_pack_loads():
    attacks = load_attacks(
        extra_packs=[ACME_PACK],
        families=["business_integrity"],
    )
    ids = {a.id for a in attacks}
    assert "ACME-BI-001" in ids
    assert "BI-001" in ids

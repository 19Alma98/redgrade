"""Jailbreak opt-in family: packs load on request; default run excludes them."""

from examples.demo_app import hardened, vulnerable
from redgrade.config import RunConfig
from redgrade.families import FAMILY_BY_ID
from redgrade.loader import load_attacks, load_builtin_attacks
from redgrade.runner import run_attacks


def test_jailbreak_family_is_opt_in_available():
    fam = FAMILY_BY_ID["jailbreak"]
    assert fam.status == "available"
    assert fam.opt_in is True


def test_jailbreak_pack_ships_attacks():
    all_builtin = load_builtin_attacks()
    jb = [a for a in all_builtin if a.family == "jailbreak"]
    assert len(jb) >= 6
    assert {a.id for a in jb} >= {"JB-001", "JB-006", "JB-007"}


def test_default_load_excludes_jailbreak():
    ids = {a.id for a in load_attacks()}
    assert not any(i.startswith("JB-") for i in ids)


def test_explicit_family_loads_jailbreak():
    attacks = load_attacks(families=["jailbreak"])
    assert attacks
    assert all(a.family == "jailbreak" for a in attacks)


def test_vulnerable_trips_dan_unlock():
    a = next(x for x in load_attacks(families=["jailbreak"]) if x.id == "JB-001")
    run = run_attacks([a], vulnerable, RunConfig(trials=1))
    assert run.results[0].asr == 1.0


def test_hardened_resists_dan_unlock():
    a = next(x for x in load_attacks(families=["jailbreak"]) if x.id == "JB-001")
    run = run_attacks([a], hardened, RunConfig(trials=1))
    assert run.results[0].asr == 0.0

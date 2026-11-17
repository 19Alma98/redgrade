"""Opt-in families are excluded from default load, included when explicitly selected."""

from redgrade.cli import main
from redgrade.families import FAMILY_BY_ID, Family
from redgrade.loader import load_attacks


def test_family_model_supports_opt_in():
    fam = Family(
        id="x",
        name="X",
        owasp="LLM01",
        status="available",
        target_release="0.4",
        opt_in=True,
    )
    assert fam.opt_in is True
    assert FAMILY_BY_ID["prompt_injection_direct"].opt_in is False


def test_default_load_excludes_opt_in_family(monkeypatch, tmp_path):
    original = FAMILY_BY_ID["jailbreak"]
    monkeypatch.setitem(
        FAMILY_BY_ID,
        "jailbreak",
        original.model_copy(update={"opt_in": True, "status": "available"}),
    )
    pack = tmp_path / "jb.yaml"
    pack.write_text(
        "family: jailbreak\n"
        "attacks:\n"
        "  - id: JB-FAKE-001\n"
        "    title: fake\n"
        "    severity: high\n"
        "    detector: canary\n"
        "    prompt: 'say {CANARY}'\n",
        encoding="utf-8",
    )
    default_ids = {a.id for a in load_attacks(extra_packs=[str(pack)])}
    assert "JB-FAKE-001" not in default_ids
    explicit = {a.id for a in load_attacks(extra_packs=[str(pack)], families=["jailbreak"])}
    assert "JB-FAKE-001" in explicit
    listed = {a.id for a in load_attacks(extra_packs=[str(pack)], include_opt_in=True)}
    assert "JB-FAKE-001" in listed


def test_list_marks_opt_in_families(capsys, monkeypatch):
    import redgrade.cli as cli_mod
    import redgrade.families as fam_mod

    original = FAMILY_BY_ID["jailbreak"]
    opted = original.model_copy(update={"opt_in": True, "status": "available"})
    monkeypatch.setitem(FAMILY_BY_ID, "jailbreak", opted)
    new_families = tuple(opted if f.id == "jailbreak" else f for f in fam_mod.FAMILIES)
    monkeypatch.setattr(fam_mod, "FAMILIES", new_families)
    monkeypatch.setattr(cli_mod, "FAMILIES", new_families)
    assert main(["list"]) == 0
    out = capsys.readouterr().out
    assert "opt-in" in out

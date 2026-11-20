"""Compliance view: family -> framework controls, status per control, gate and report output."""

import json

import pytest
from helpers import make_attack, make_result, make_run

from redgrade import Policy, evaluate_policy
from redgrade.cli import main
from redgrade.compliance import FAMILY_CONTROLS, FRAMEWORKS, build_compliance, controls_for_attack
from redgrade.families import FAMILIES
from redgrade.formats.html import to_html
from redgrade.formats.sarif import to_sarif
from redgrade.loader import load_pack_file
from redgrade.report import to_dict, to_markdown


def test_every_family_maps_to_known_controls():
    assert {f.id for f in FAMILIES} <= set(FAMILY_CONTROLS)
    for fam, fws in FAMILY_CONTROLS.items():
        for fw, ids in fws.items():
            known = FRAMEWORKS[fw].by_id
            for cid in ids:
                assert cid in known, f"{fam}: {fw}:{cid}"
                assert known[cid].in_scope, f"{fam} maps to out-of-scope {cid}"


def test_statuses_from_a_run():
    direct = make_result(make_attack("D-1", family="prompt_injection_direct"), wins=1)
    leak = make_result(make_attack("L-1", family="info_disclosure", detector="secret_leak"), wins=0)
    report = build_compliance(make_run(direct, leak))
    owasp = {c.id: c for c in report.framework("owasp_llm_2025").controls}
    assert owasp["LLM01"].status == "vulnerable" and owasp["LLM01"].vulnerable_attacks == ["D-1"]
    assert owasp["LLM02"].status == "resisted" and owasp["LLM07"].status == "resisted"
    assert owasp["LLM05"].status == "not_run"
    assert owasp["LLM03"].status == "out_of_scope"
    atlas = {c.id: c for c in report.framework("mitre_atlas").controls}
    assert atlas["AML.T0051.000"].status == "vulnerable"
    assert atlas["AML.T0056"].status == "resisted"


def test_advisory_and_skipped_results_do_not_count():
    advisory = make_result(make_attack("H-1", family="jailbreak", detector="refusal"), wins=3)
    report = build_compliance(make_run(advisory))
    atlas = {c.id: c for c in report.framework("mitre_atlas").controls}
    assert atlas["AML.T0054"].status == "not_run"


def test_attack_level_compliance_from_pack(tmp_path):
    pack = tmp_path / "p.yaml"
    pack.write_text(
        "family: business_integrity\nattacks:\n"
        "  - id: B-1\n    title: t\n    detector: canary\n    prompt: hi\n"
        "    compliance: { mitre_atlas: [AML.T0054] }\n",
        encoding="utf-8",
    )
    attack = load_pack_file(pack)[0]
    assert "AML.T0054" in controls_for_attack(attack)["mitre_atlas"]
    run = make_run(make_result(attack, wins=0))
    atlas = {c.id: c for c in build_compliance(run).framework("mitre_atlas").controls}
    assert atlas["AML.T0054"].status == "resisted"


def test_bad_compliance_block_rejected(tmp_path):
    from redgrade.loader import PackError

    pack = tmp_path / "p.yaml"
    pack.write_text(
        "family: jailbreak\nattacks:\n  - {id: B-1, title: t, detector: canary, prompt: hi, compliance: x}\n",
        encoding="utf-8",
    )
    with pytest.raises(PackError):
        load_pack_file(pack)


def test_require_compliance_gate():
    run = make_run(make_result(make_attack("D-1"), wins=0))
    checks = {c.name: c for c in evaluate_policy(run, Policy(require_compliance=["owasp_llm_2025"]))}
    gate = checks["compliance.owasp_llm_2025"]
    assert gate.passed is False and gate.value > 0
    with pytest.raises(ValueError):
        Policy(require_compliance=["iso_42001"])


def test_reports_carry_compliance():
    run = make_run(make_result(make_attack("D-1"), wins=1))
    md = to_markdown(run, [])
    assert "## Compliance view" in md and "AML.T0051.000" in md and "**vulnerable**" in md
    data = to_dict(run, [])
    assert data["compliance"]["owasp_llm_2025"]["controls"][0]["status"] == "vulnerable"
    sarif = json.loads(to_sarif(run, version="0"))
    tags = sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert "mitre_atlas:AML.T0051.000" in tags and "eu_ai_act:Art. 15(5)" in tags
    assert "Compliance view" in to_html(run, [], version="0")


def test_cli_compliance(capsys):
    assert main(["compliance", "--framework", "nist_ai_rmf"]) == 0
    out = capsys.readouterr().out
    assert "MEASURE 2.7" in out and "prompt_injection_direct" in out
    assert main(["compliance", "--framework", "nope"]) == 2

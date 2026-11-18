import json
from xml.etree import ElementTree as ET

from redgrade.baseline import Baseline, compare
from redgrade.cli import main
from redgrade.formats.junit import to_junit
from redgrade.formats.sarif import to_sarif_dict
from tests.helpers import make_attack, make_result, make_run


def _run():
    return make_run(
        make_result(make_attack("A-1", severity="critical"), 2),
        make_result(make_attack("A-2", severity="low"), 0),
        make_result(make_attack("A-3", severity="medium"), 0, total=0, errors=3),
        make_result(make_attack("U-1", family="task_utility"), 2),
    )


def test_sarif_structure_and_redaction():
    doc = to_sarif_dict(_run(), version="9.9")
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    ids = [r["ruleId"] for r in run["results"]]
    assert ids == ["A-1", "U-1"]  # A-2 resisted, A-3 errored
    first = run["results"][0]
    assert first["level"] == "error"
    assert first["partialFingerprints"]["redgradeAttack/v1"] == "A-1"
    assert "out0" not in json.dumps(doc)
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "9.5"
    assert run["invocations"][0]["toolExecutionNotifications"][0]["message"]["text"].startswith("A-3")


def test_sarif_include_output_opt_in():
    doc = to_sarif_dict(_run(), version="1", include_output=True)
    assert "out0" in json.dumps(doc)


def test_sarif_baseline_state():
    base = Baseline.from_run(make_run(make_result(make_attack("A-1", severity="critical"), 0)))
    run = _run()
    doc = to_sarif_dict(run, version="1", comparison=compare(run, base))
    states = {r["ruleId"]: r.get("baselineState") for r in doc["runs"][0]["results"]}
    assert states["A-1"] == "new"


def test_junit_counts():
    xml = to_junit(_run())
    root = ET.fromstring(xml)
    suites = {s.get("name"): s for s in root}
    d = suites["prompt_injection_direct"]
    assert (d.get("tests"), d.get("failures"), d.get("errors")) == ("3", "1", "1")
    assert suites["task_utility"].get("failures") == "1"
    assert "out0" not in xml


def test_cli_writes_sarif_and_junit(tmp_path):
    cfg = tmp_path / "r.yaml"
    cfg.write_text(
        "target: {type: function, path: 'examples.demo_app:vulnerable'}\nrun: {trials: 1}\n"
        "policy: {max_asr: 1.0, max_asr_by_severity: {}}\n"
    )
    s, j = tmp_path / "o.sarif", tmp_path / "o.xml"
    main(["run", "-c", str(cfg), "--sarif", str(s), "--junit", str(j), "--family", "prompt_injection_direct"])
    assert json.loads(s.read_text())["runs"][0]["results"]
    assert ET.parse(j).getroot().tag == "testsuites"

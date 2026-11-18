import json

from redgrade.cli import main

CFG = """
target:
  type: function
  path: examples.demo_app:hardened
run: {trials: 1}
policy:
  max_asr: 1.0
  max_asr_by_severity: {}
"""


def _write(tmp_path, extra=""):
    p = tmp_path / "redgrade.yaml"
    p.write_text(CFG + extra)
    return p


def test_update_then_run_has_no_regressions(tmp_path, capsys):
    cfg = _write(tmp_path)
    out = tmp_path / "b.json"
    assert main(["baseline", "update", "-c", str(cfg), "--out", str(out)]) == 0
    assert json.loads(out.read_text())["entries"]
    rj = tmp_path / "r.json"
    code = main(
        [
            "run",
            "-c",
            str(cfg),
            "--baseline",
            str(out),
            "--json",
            str(rj),
            "--family",
            "prompt_injection_direct",
        ]
    )
    data = json.loads(rj.read_text())
    assert code == 0
    assert data["schema_version"] == 2
    assert not [d for d in data["baseline"]["deltas"] if d["status"] == "regression"]


def test_run_with_missing_baseline_exits_2(tmp_path):
    cfg = _write(tmp_path)
    assert main(["run", "-c", str(cfg), "--baseline", str(tmp_path / "none.json")]) == 2


def test_regression_fails_gate(tmp_path):
    """Baseline recorded on the hardened app, then run against the vulnerable one."""
    cfg = _write(tmp_path)
    out = tmp_path / "b.json"
    assert main(["baseline", "update", "-c", str(cfg), "--out", str(out)]) == 0
    vuln = tmp_path / "v.yaml"
    vuln.write_text(CFG.replace(":hardened", ":vulnerable"))
    assert main(["run", "-c", str(vuln), "--baseline", str(out)]) == 1

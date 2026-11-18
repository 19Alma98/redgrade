"""JUnit XML export: one testsuite per family plus one for the gate checks.

Works with GitLab, Jenkins, Azure DevOps and most CI test viewers. A failure is an attack
that worked (or a benign probe that was not answered); a trial error is reported as ``error``.
"""

from xml.etree import ElementTree as ET

from redgrade.baseline import bad_count
from redgrade.formats._common import finding_message
from redgrade.models import AttackResult, RunResult
from redgrade.policy import Check


def to_junit(
    run: RunResult,
    checks: list[Check] | None = None,
    *,
    include_output: bool = False,
) -> str:
    root = ET.Element("testsuites", name="redgrade")
    families: dict[str, list[AttackResult]] = {}
    for r in run.results:
        families.setdefault(r.attack.family, []).append(r)

    for family, rows in sorted(families.items()):
        suite = ET.SubElement(root, "testsuite", name=family)
        failures = errors = skipped = 0
        total_time = 0.0
        for r in sorted(rows, key=lambda x: x.attack.id):
            t = sum(tr.latency_s for tr in r.trials)
            total_time += t
            case = ET.SubElement(
                suite, "testcase", classname=family, name=f"{r.attack.id} {r.attack.title}", time=f"{t:.3f}"
            )
            if r.skipped_reason:
                skipped += 1
                ET.SubElement(case, "skipped", message=r.skipped_reason)
            elif r.trials and not r.valid_trials:
                errors += 1
                err = next((tr.error for tr in r.trials if tr.error), "")
                ET.SubElement(
                    case, "error", message=f"all {len(r.trials)} trials errored", type="TargetError"
                ).text = err
            elif bad_count(r) > 0:
                failures += 1
                el = ET.SubElement(
                    case,
                    "failure",
                    message=finding_message(r, include_output=include_output),
                    type=r.attack.severity,
                )
                el.text = f"owasp={r.attack.owasp} severity={r.attack.severity} flaky={r.flaky}"
        suite.set("tests", str(len(rows)))
        suite.set("failures", str(failures))
        suite.set("errors", str(errors))
        suite.set("skipped", str(skipped))
        suite.set("time", f"{total_time:.3f}")

    if checks is not None:
        suite = ET.SubElement(root, "testsuite", name="gate", tests=str(len(checks)), errors="0", skipped="0")
        bad = 0
        for c in checks:
            case = ET.SubElement(suite, "testcase", classname="gate", name=c.name, time="0")
            if not c.passed:
                bad += 1
                ET.SubElement(
                    case, "failure", message=f"value={c.value:.4f} limit={c.limit:.4f}", type="gate"
                )
        suite.set("failures", str(bad))
        suite.set("time", "0")

    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"

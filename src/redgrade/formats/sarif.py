"""SARIF 2.1.0 export for GitHub code scanning and other SARIF consumers.

Each attack that worked is one result with a stable fingerprint (the attack id), so GitHub
shows only *new* alerts on a pull request. Model output is left out unless asked for.
"""

import json

from redgrade.baseline import BaselineComparison
from redgrade.compliance import controls_for_attack
from redgrade.formats._common import SARIF_LEVEL, SECURITY_SEVERITY, finding_message, findings
from redgrade.models import RunResult

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/19Alma98/redgrade"


def to_sarif_dict(
    run: RunResult,
    *,
    version: str,
    comparison: BaselineComparison | None = None,
    location_uri: str = "redgrade.yaml",
    include_output: bool = False,
) -> dict[str, object]:
    rows = findings(run)
    states: dict[str, str] = {}
    if comparison is not None:
        for d in comparison.deltas:
            states[d.id] = {"regression": "new", "new": "new", "worsened": "updated"}.get(
                d.status, "unchanged"
            )

    rules = []
    results = []
    for r in sorted(rows, key=lambda x: x.attack.id):
        a = r.attack
        rules.append(
            {
                "id": a.id,
                "name": a.technique or a.id,
                "shortDescription": {"text": a.title},
                "defaultConfiguration": {"level": SARIF_LEVEL.get(a.severity, "warning")},
                "properties": {
                    "security-severity": str(SECURITY_SEVERITY.get(a.severity, 5.0)),
                    "tags": [
                        "security",
                        "llm",
                        a.family,
                        *[o.strip() for o in a.owasp.split(",") if o.strip()],
                        *[f"{fw}:{cid}" for fw, ids in controls_for_attack(a).items() for cid in ids],
                    ],
                    "level": a.level,
                },
            }
        )
        result: dict[str, object] = {
            "ruleId": a.id,
            "level": SARIF_LEVEL.get(a.severity, "warning"),
            "message": {"text": finding_message(r, include_output=include_output)},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": location_uri},
                        "region": {"startLine": 1},
                    }
                }
            ],
            "partialFingerprints": {"redgradeAttack/v1": a.id},
            "properties": {
                "family": a.family,
                "owasp": a.owasp,
                "severity": a.severity,
                "attackLevel": a.level,
                "flaky": r.flaky,
            },
        }
        if a.id in states:
            result["baselineState"] = states[a.id]
        results.append(result)

    notes = [
        {
            "level": "error",
            "message": {"text": f"{r.attack.id}: {r.errors}/{len(r.trials)} trials errored"},
        }
        for r in run.executed
        if r.errors
    ]
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "redgrade",
                        "version": version,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": notes}],
                "results": results,
            }
        ],
    }


def to_sarif(*args: object, **kwargs: object) -> str:
    return json.dumps(to_sarif_dict(*args, **kwargs), indent=2, ensure_ascii=False)  # type: ignore[arg-type]

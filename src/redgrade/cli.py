"""Command line: ``redgrade init | list | run | export-dataset``.

Exit codes: 0 gate passed, 1 gate failed, 2 usage or configuration error.
"""

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path

from redgrade import __version__
from redgrade.config import EXAMPLE, ConfigError, load_config
from redgrade.constants import DEFAULT_CONFIG_PATH, FAMILY_STATUS_AVAILABLE
from redgrade.families import FAMILIES
from redgrade.loader import PackError, load_attacks
from redgrade.models import AttackResult
from redgrade.policy import evaluate_policy, passed
from redgrade.render import render_attack, render_turns
from redgrade.report import to_json, to_markdown
from redgrade.runner import new_canary, run_attacks
from redgrade.targets import TargetError, build_target


def _cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if path.exists() and not args.force:
        print(f"{path} already exists (use --force to overwrite)", file=sys.stderr)
        return 2
    path.write_text(EXAMPLE, encoding="utf-8")
    print(f"wrote {path}")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    attacks = load_attacks(extra_packs=args.pack, families=args.family or None)
    print(f"{'ID':<10}{'SEVERITY':<10}{'OWASP':<14}{'FAMILY':<28}TITLE")
    for a in attacks:
        print(f"{a.id:<10}{a.severity:<10}{a.owasp:<14}{a.family:<28}{a.title}")
    print(f"\n{len(attacks)} attacks")
    print("\nfamilies:")
    for f in FAMILIES:
        n = sum(1 for a in attacks if a.family == f.id)
        status = f"{n} attacks" if f.status == FAMILY_STATUS_AVAILABLE else f"planned v{f.target_release}"
        print(f"  {f.id:<28}{f.owasp:<14}{status}")
    return 0


def _progress(result: AttackResult) -> None:
    if result.skipped_reason:
        mark = "skip"
    elif result.errors == len(result.trials):
        mark = "ERR "
    elif result.successes:
        mark = "FAIL"
    else:
        mark = "ok  "
    print(f"  [{mark}] {result.attack.id} {result.attack.title}", file=sys.stderr)


def _cmd_run(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    families = args.family or config.families
    attacks = load_attacks(extra_packs=config.packs, families=families or None)
    if args.trials:
        config.run.trials = args.trials
    if not attacks:
        print("no attacks selected", file=sys.stderr)
        return 2
    target = build_target(config.target)
    print(f"running {len(attacks)} attacks x {config.run.trials} trials", file=sys.stderr)
    run = run_attacks(attacks, target, config.run, on_result=_progress)
    checks = evaluate_policy(run, config.policy)
    report = to_markdown(run, checks)
    print(report)
    if args.report:
        Path(args.report).write_text(report, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(to_json(run, checks), encoding="utf-8")
    return 0 if passed(checks) else 1


def _cmd_export(args: argparse.Namespace) -> int:
    """Write the attacks as an OpenGrade dataset (JSONL): one row per attack, fixed canary."""
    attacks = load_attacks(extra_packs=args.pack, families=args.family or None)
    with open(args.output, "w", encoding="utf-8") as fh:
        for a in attacks:
            canary = new_canary()
            meta = {
                "attack_id": a.id,
                "family": a.family,
                "owasp": a.owasp,
                "severity": a.severity,
                "detector": a.detector,
                "detector_args": a.detector_args,
                "requires_secrets": a.requires_secrets,
                "canary": canary,
            }
            if a.turns:
                rendered = render_turns(a, canary)
                row = {
                    "input": "\n".join(f"User: {p}" for p, _ in rendered),
                    "metadata": {
                        **meta,
                        "detect_on": a.detect_on,
                        "turns": [{"prompt": p, "documents": docs} for p, docs in rendered],
                    },
                }
            else:
                prompt, documents = render_attack(a, canary)
                row = {
                    "input": prompt,
                    "metadata": {**meta, "documents": documents},
                }
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"wrote {len(attacks)} attacks to {args.output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="redgrade", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=f"redgrade {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="write an example redgrade.yaml")
    p.add_argument("path", nargs="?", default=DEFAULT_CONFIG_PATH)
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=_cmd_init)

    p = sub.add_parser("list", help="list available attacks and families")
    p.add_argument("--family", action="append")
    p.add_argument("--pack", action="append", help="extra attack pack (YAML)")
    p.set_defaults(func=_cmd_list)

    p = sub.add_parser("run", help="attack the target and apply the gate")
    p.add_argument("--config", "-c", default=DEFAULT_CONFIG_PATH)
    p.add_argument("--family", action="append", help="only this family (repeatable)")
    p.add_argument("--trials", type=int, help="override run.trials")
    p.add_argument("--report", help="write the Markdown report to this file")
    p.add_argument("--json", help="write the JSON report to this file")
    p.set_defaults(func=_cmd_run)

    p = sub.add_parser("export-dataset", help="export attacks as an OpenGrade JSONL dataset")
    p.add_argument("output")
    p.add_argument("--family", action="append")
    p.add_argument("--pack", action="append")
    p.set_defaults(func=_cmd_export)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    command: Callable[[argparse.Namespace], int] = args.func
    try:
        return command(args)
    except (ConfigError, PackError, TargetError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

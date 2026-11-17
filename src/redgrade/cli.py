"""Command line: ``redgrade init | list | run | check | export-dataset | deep``.

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
from redgrade.render import render_attack, render_turns
from redgrade.report import to_json
from redgrade.runner import new_canary
from redgrade.sdk import AttackError, run_pipeline
from redgrade.targets import TargetError, build_target


def _cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if path.exists() and not args.force:
        print(f"{path} already exists (use --force to overwrite)", file=sys.stderr)
        return 2
    path.write_text(EXAMPLE, encoding="utf-8")
    print(f"wrote {path}")
    return 0


def _truncate(text: str, max_len: int) -> str:
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


def _cmd_list(args: argparse.Namespace) -> int:
    attacks = load_attacks(extra_packs=args.pack, families=args.family or None)
    print(f"{'ID':<10}{'LEVEL':<6}{'TECHNIQUE':<22}{'SEVERITY':<10}{'OWASP':<14}{'FAMILY':<28}TITLE")
    for a in attacks:
        level = "" if a.level is None else str(a.level)
        technique = _truncate(a.technique, 20)
        print(f"{a.id:<10}{level:<6}{technique:<22}{a.severity:<10}{a.owasp:<14}{a.family:<28}{a.title}")
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
    if args.trials:
        config.run.trials = args.trials
    try:
        target = build_target(config.target)
        report = run_pipeline(
            target,
            policy=config.policy,
            families=families or None,
            packs=config.packs or None,
            run_config=config.run,
            on_result=_progress,
        )
    except AttackError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    n_attacks = len(report.run.results)
    n_trials = report.run.trials_per_attack
    print(f"ran {n_attacks} attacks x {n_trials} trials", file=sys.stderr)
    md = report.to_markdown()
    print(md)
    if args.report:
        Path(args.report).write_text(md, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(to_json(report.run, report.checks, report.policy), encoding="utf-8")
    return 0 if report.passed else 1


def _cmd_deep(args: argparse.Namespace) -> int:
    from redgrade.deep.config import build_deep_target, load_deep_config
    from redgrade.deep.errors import DeepError
    from redgrade.deep.sdk import deep_attack

    config = load_deep_config(args.config)
    if args.attacker_model:
        config = config.model_copy(
            update={"attacker": config.attacker.model_copy(update={"model": args.attacker_model})}
        )
    if args.max_rounds is not None:
        config = config.model_copy(update={"max_rounds": args.max_rounds})
    try:
        target = build_deep_target(config.target)
        report = deep_attack(
            target,
            attacker_model=config.attacker.model,
            attacker_api_base=config.attacker.api_base,
            goals=config.goals or None,
            seed_attack_ids=config.seed_attack_ids or None,
            max_rounds=config.max_rounds,
            policy=config.policy,
            secrets=config.secrets or None,
            allowed_hosts=config.allowed_hosts or None,
            packs=config.packs or None,
        )
    except DeepError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    md = report.to_markdown()
    print(md)
    if args.report:
        Path(args.report).write_text(md, encoding="utf-8")
    if args.export_wins:
        n = report.export_winning_seeds(args.export_wins)
        print(f"wrote {n} winning seed(s) to {args.export_wins}", file=sys.stderr)
    return 0 if report.passed else 1


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

    p = sub.add_parser(
        "check",
        help="CI pipeline gate (alias of run; default CI packs, no LiteLLM)",
        description=(
            "Run the CI attack pipelines against the configured target (same engine as "
            "`run`). Use this in pull-request workflows. The SDK `check()` API requires an "
            "HttpTarget; this CLI command still accepts function targets for offline demos."
        ),
    )
    p.add_argument("--config", "-c", default=DEFAULT_CONFIG_PATH)
    p.add_argument("--family", action="append", help="only this family (repeatable)")
    p.add_argument("--trials", type=int, help="override run.trials")
    p.add_argument("--report", help="write the Markdown report to this file")
    p.add_argument("--json", help="write the JSON report to this file")
    p.set_defaults(func=_cmd_run)

    p = sub.add_parser("deep", help="adaptive deep attack against the target")
    p.add_argument("--config", "-c", required=True, help="deep config YAML")
    p.add_argument("--attacker-model", help="override attacker.model")
    p.add_argument("--max-rounds", type=int, help="override max_rounds")
    p.add_argument("--report", help="write the Markdown report to this file")
    p.add_argument(
        "--export-wins",
        metavar="PATH",
        help="write promoted winning seeds as an attack pack YAML",
    )
    p.set_defaults(func=_cmd_deep)

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

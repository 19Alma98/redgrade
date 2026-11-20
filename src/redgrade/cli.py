"""Command line: ``redgrade init | list | run | check | baseline | export-dataset | deep``.

Exit codes: 0 gate passed, 1 gate failed, 2 usage or configuration error.
"""

import argparse
import json
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from redgrade import __version__
from redgrade.baseline import DEFAULT_BASELINE_PATH, BaselineError
from redgrade.config import EXAMPLE, Config, ConfigError, JudgeConfig, load_config
from redgrade.constants import (
    DEEP_STRATEGIES,
    DEFAULT_CONFIG_PATH,
    DEFAULT_MUTATIONS,
    FAMILY_STATUS_AVAILABLE,
    FAMILY_TASK_UTILITY,
)
from redgrade.detectors import list_detectors
from redgrade.extensions import prepare_extensions
from redgrade.families import FAMILIES
from redgrade.judge import JudgeError
from redgrade.loader import PackError, load_attacks, load_pack_file
from redgrade.models import AttackResult
from redgrade.mutations import available_mutations
from redgrade.oob import OobServer
from redgrade.plugins import PluginError, load_plugins
from redgrade.render import render_attack, render_history, render_turns
from redgrade.runner import new_canary
from redgrade.sdk import AttackError, run_pipeline
from redgrade.targets import TargetError, build_target
from redgrade.utility import attack_results


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
    # Discoverability: list includes opt-in builtins unless --family narrows the set.
    load_plugins(args.plugin)
    attacks = load_attacks(
        extra_packs=args.pack,
        families=args.family or None,
        include_opt_in=not args.family,
    )
    print(f"{'ID':<10}{'LEVEL':<6}{'TECHNIQUE':<22}{'SEVERITY':<10}{'OWASP':<14}{'FAMILY':<28}TITLE")
    for a in attacks:
        level = "" if a.level is None else str(a.level)
        technique = _truncate(a.technique, 20)
        print(f"{a.id:<10}{level:<6}{technique:<22}{a.severity:<10}{a.owasp:<14}{a.family:<28}{a.title}")
    print(f"\n{len(attacks)} attacks")
    print("\nfamilies:")
    for f in FAMILIES:
        n = sum(1 for a in attacks if a.family == f.id)
        if f.status == FAMILY_STATUS_AVAILABLE:
            status = f"{n} attacks (opt-in)" if f.opt_in else f"{n} attacks"
        else:
            status = f"planned v{f.target_release}"
        print(f"  {f.id:<28}{f.owasp:<14}{status}")
    print("\nmutations (attack `mutations:` list; derived attacks are L4):")
    for name, kinds in available_mutations().items():
        print(f"  {name:<12}{', '.join(kinds)}")
    print(f"  {'default':<12}{', '.join(DEFAULT_MUTATIONS)}")
    print(f"\ndeep strategies (redgrade deep --strategy): {', '.join(DEEP_STRATEGIES)}")
    print("\ndetectors (confidence: evidence > rubric > heuristic; heuristic = advisory, not gated):")
    for spec in list_detectors():
        origin = "" if spec.builtin else " (plugin)"
        print(f"  {spec.name:<20}{spec.confidence:<11}{origin}")
    return 0


def _progress(result: AttackResult) -> None:
    if result.skipped_reason:
        mark = "skip"
    elif result.errors == len(result.trials):
        mark = "ERR "
    elif result.attack.family == FAMILY_TASK_UTILITY:
        # successes = probes that still answered (good)
        mark = "ok  " if result.successes == len(result.valid_trials) and result.valid_trials else "UTIL"
    elif result.successes:
        mark = "FAIL"
    else:
        mark = "ok  "
    print(f"  [{mark}] {result.attack.id} {result.attack.title}", file=sys.stderr)


@contextmanager
def _collector(config: Config) -> Iterator[OobServer | None]:
    """Start the out-of-band collector when ``redgrade.yaml`` has an ``oob:`` block."""
    if config.oob is None:
        yield None
        return
    with OobServer.from_config(config.oob) as server:
        print(f"out-of-band collector listening, reachable at {server.base_url}", file=sys.stderr)
        yield server


def _cmd_run(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    families = args.family or config.families
    if args.trials:
        config.run.trials = args.trials
    try:
        judge = prepare_extensions(config)
        target = build_target(config.target)
        with _collector(config) as oob:
            report = run_pipeline(
                target,
                judge=judge,
                policy=config.policy,
                families=families or None,
                packs=config.packs or None,
                run_config=config.run,
                on_result=_progress,
                baseline=args.baseline,
                oob=oob,
            )
    except (AttackError, PluginError, JudgeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    n_attacks = len(attack_results(report.run))
    n_utility = len(report.run.results) - n_attacks
    n_trials = report.run.trials_per_attack
    extra = f" + {n_utility} utility" if n_utility else ""
    print(f"ran {n_attacks} attacks{extra} x {n_trials} trials", file=sys.stderr)
    md = report.to_markdown()
    print(md)
    if args.report:
        Path(args.report).write_text(md, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(report.to_json(), encoding="utf-8")
    if args.sarif:
        sarif = report.to_sarif(location_uri=args.config, include_output=args.include_output)
        Path(args.sarif).write_text(sarif, encoding="utf-8")
    if args.html:
        Path(args.html).write_text(report.to_html(include_output=args.include_output), encoding="utf-8")
    if args.junit:
        Path(args.junit).write_text(report.to_junit(include_output=args.include_output), encoding="utf-8")
    return 0 if report.passed else 1


def _cmd_baseline_update(args: argparse.Namespace) -> int:
    """Run the attacks and record the result as the baseline for later comparisons."""
    config = load_config(args.config)
    families = args.family or config.families
    if args.trials:
        config.run.trials = args.trials
    policy = config.policy.model_copy(update={"baseline": None})
    try:
        judge = prepare_extensions(config)
        target = build_target(config.target)
        with _collector(config) as oob:
            report = run_pipeline(
                target,
                judge=judge,
                policy=policy,
                families=families or None,
                packs=config.packs or None,
                run_config=config.run,
                on_result=_progress,
                oob=oob,
            )
    except (AttackError, PluginError, JudgeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    err = next((c for c in report.checks if c.name == "error_rate"), None)
    if err is not None and not err.passed:
        print(
            "refusing to record a baseline: too many trials errored (is the target reachable?)",
            file=sys.stderr,
        )
        return 1
    out = args.out or (config.policy.baseline.path if config.policy.baseline else DEFAULT_BASELINE_PATH)
    report.to_baseline().save(out)
    print(f"wrote baseline for {len(report.run.executed)} attacks to {out}", file=sys.stderr)
    return 0


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
    if args.strategy:
        config = config.model_copy(update={"strategies": list(args.strategy)})
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
            detector=config.detector,
            judge_model=config.judge.model,
            judge_api_base=config.judge.api_base,
            strategies=config.strategies or None,
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


def _cmd_generate(args: argparse.Namespace) -> int:
    """Lab: generate attacks for this app's purpose and freeze them into a pack for CI."""
    from redgrade.deep.errors import DeepError
    from redgrade.deep.generate import generate_attacks, translate_attacks, write_pack

    purpose = args.purpose or ""
    if args.purpose_file:
        purpose = Path(args.purpose_file).read_text(encoding="utf-8")
    try:
        by_family = generate_attacks(
            purpose,
            families=args.family or None,
            count=args.count,
            levels=args.level or (1, 2, 3, 5),
            attacker_model=args.attacker_model,
            attacker_api_base=args.attacker_api_base,
            id_prefix=args.id_prefix,
        )
        if args.lang:
            for fam, items in by_family.items():
                items.extend(
                    translate_attacks(
                        list(items),
                        args.lang,
                        family=fam,
                        attacker_model=args.attacker_model,
                        attacker_api_base=args.attacker_api_base,
                    )
                )
    except DeepError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    header = (
        f"Generated by `redgrade generate` for: {' '.join(purpose.split())[:200]}\nReview before committing."
    )
    n = write_pack(args.out, by_family, header=header)
    for fam, items in by_family.items():
        print(f"{fam}: {len(items)} attack(s)", file=sys.stderr)
    print(f"wrote {n} attack(s) to {args.out}", file=sys.stderr)
    return 0 if n else 1


def _cmd_distill(args: argparse.Namespace) -> int:
    """Lab: turn llm_judge attacks into deterministic rubrics validated against the judge."""
    from redgrade.deep.distill import DistillResult, distill_attacks, distilled_pack
    from redgrade.deep.errors import DeepError
    from redgrade.deep.generate import _default_chat
    from redgrade.extensions import build_judge
    from redgrade.packio import read_pack, write_pack

    config = load_config(args.config)
    try:
        prepare_extensions(config.model_copy(update={"judge": None}))
        if args.judge_model:
            judge = build_judge(JudgeConfig(model=args.judge_model, api_base=args.judge_api_base))
        else:
            judge = build_judge(config.judge)
        if judge is None:
            print("distill needs a judge: --judge-model or `judge:` in redgrade.yaml", file=sys.stderr)
            return 2
        author = _default_chat(args.attacker_model, args.attacker_api_base)
        raw = read_pack(args.pack)
        attacks = load_pack_file(args.pack)
        target = build_target(config.target)

        def progress(res: DistillResult) -> None:
            agree = "" if res.agreement is None else f" agreement {res.agreement:.2f}"
            print(f"  [{res.status:<12}] {res.attack_id}{agree} - {res.message}", file=sys.stderr)

        results = distill_attacks(
            attacks,
            target,
            judge=judge.chat,
            author=author,
            trials=args.trials,
            run_config=config.run,
            on_result=progress,
            synthesize=args.synthesize,
            min_agreement=args.min_agreement,
            min_precision=args.min_precision,
        )
    except (DeepError, JudgeError, PluginError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    pack, changed = distilled_pack(raw, results, judge_id=judge.judge_id)
    out = args.out or args.pack
    write_pack(out, pack, header="Distilled by `redgrade distill`: llm_judge -> rubric where validated.")
    print(f"froze {changed}/{len(results)} judged attack(s) into rubrics; wrote {out}", file=sys.stderr)
    return 0 if changed or not results else 1


def _cmd_compare(args: argparse.Namespace) -> int:
    """A/B: the same attacks against the app without and with a defense."""
    from redgrade.defense import compare_defense

    base = load_config(args.config)
    defended = load_config(args.defended)
    if args.trials:
        base.run.trials = args.trials
    try:
        judge = prepare_extensions(base)
        prepare_extensions(defended.model_copy(update={"judge": None}))
        with _collector(base) as oob:
            result = compare_defense(
                build_target(base.target),
                build_target(defended.target),
                families=args.family or base.families or None,
                packs=base.packs or None,
                run_config=base.run,
                oob=oob,
                judge=judge,
                baseline_label=Path(args.config).stem,
                defended_label=Path(args.defended).stem,
            )
    except (PluginError, JudgeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    md = result.to_markdown()
    print(md)
    if args.report:
        Path(args.report).write_text(md, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(result.to_json(), encoding="utf-8")
    return 0 if result.effective(max_utility_drop=args.max_utility_drop) else 1


def _cmd_compliance(args: argparse.Namespace) -> int:
    """Which framework controls redgrade's attack families map to (no run)."""
    from redgrade.compliance import FAMILY_CONTROLS, FRAMEWORKS

    selected = args.framework or list(FRAMEWORKS)
    unknown = [f for f in selected if f not in FRAMEWORKS]
    if unknown:
        print(f"unknown framework(s): {', '.join(unknown)} (known: {', '.join(FRAMEWORKS)})", file=sys.stderr)
        return 2
    for fw_id in selected:
        fw = FRAMEWORKS[fw_id]
        print(f"\n{fw.name}  [{fw.id}]")
        for control in fw.controls:
            fams = sorted(f for f, m in FAMILY_CONTROLS.items() if control.id in m.get(fw_id, ()))
            if not control.in_scope:
                cover = "out of scope (inside threat: use dedicated tools)"
            else:
                cover = ", ".join(fams) if fams else "not covered"
            print(f"  {control.id:<15}{control.name:<48}{cover}")
        if fw.note:
            print(f"  note: {fw.note}")
    return 0


def _cmd_translate(args: argparse.Namespace) -> int:
    """Lab: add translated (L4) variants of a pack's attacks, frozen for CI."""
    from redgrade.deep.errors import DeepError
    from redgrade.deep.generate import read_pack, translate_attacks, write_pack

    try:
        by_family = read_pack(args.pack)
        out: dict[str, list[dict[str, object]]] = {}
        for fam, items in by_family.items():
            originals = [a for a in items if "~tr_" not in str(a.get("id", ""))]
            translated = translate_attacks(
                originals,
                args.lang,
                family=fam,
                attacker_model=args.attacker_model,
                attacker_api_base=args.attacker_api_base,
            )
            out[fam] = (items if not args.only_translations else []) + translated
    except DeepError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    n = write_pack(args.out or args.pack, out)
    print(f"wrote {n} attack(s) to {args.out or args.pack}", file=sys.stderr)
    return 0 if n else 1


def _cmd_import_dataset(args: argparse.Namespace) -> int:
    """Convert a dataset file (AdvBench, HarmBench, JailbreakBench, CSV / JSONL) into a pack."""
    from redgrade.datasets import DatasetError, import_dataset
    from redgrade.packio import write_pack

    try:
        attacks = import_dataset(
            args.dataset,
            preset=args.preset,
            prompt_field=args.prompt_field,
            document_field=args.document_field,
            id_field=args.id_field,
            target_field=args.target_field,
            family=args.family,
            detector=args.detector,
            severity=args.severity,
            level=args.level,
            id_prefix=args.id_prefix,
            limit=args.limit,
        )
    except DatasetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    by_family: dict[str, list[dict[str, object]]] = {}
    for attack in attacks:
        by_family.setdefault(str(attack.pop("family")), []).append(attack)
    n = write_pack(
        args.out, by_family, header=f"Imported from {Path(args.dataset).name} by `redgrade import-dataset`."
    )
    judged = sum(1 for a in attacks if a["detector"] == "llm_judge")
    print(f"wrote {n} attack(s) to {args.out}", file=sys.stderr)
    if judged:
        print(f"{judged} attack(s) use llm_judge: they run only in `redgrade deep`", file=sys.stderr)
    return 0


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
                "requires_tools": a.requires_tools,
                "canary": canary,
            }
            if a.tools:
                meta["tools"] = list(a.tools)
            if a.requires_oob:
                # {OOB_URL} renders to an unreachable placeholder outside a collector run.
                meta["requires_oob"] = True
            if a.history:
                meta["history"] = render_history(a, canary)
                meta["requires_history"] = a.requires_history
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
    p.add_argument("--plugin", action="append", help="plugin module that registers detectors")
    p.set_defaults(func=_cmd_list)

    p = sub.add_parser("run", help="attack the target and apply the gate")
    p.add_argument("--config", "-c", default=DEFAULT_CONFIG_PATH)
    p.add_argument("--family", action="append", help="only this family (repeatable)")
    p.add_argument("--trials", type=int, help="override run.trials")
    p.add_argument("--report", help="write the Markdown report to this file")
    p.add_argument("--json", help="write the JSON report to this file")
    p.add_argument("--baseline", help="compare against this baseline file (overrides policy.baseline.path)")
    p.add_argument("--sarif", help="write a SARIF 2.1.0 report (GitHub code scanning)")
    p.add_argument("--junit", help="write a JUnit XML report")
    p.add_argument("--html", help="write a self-contained HTML report")
    p.add_argument(
        "--include-output",
        action="store_true",
        help="include model output snippets in SARIF/JUnit/HTML (default: omitted, they may contain secrets)",
    )
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
    p.add_argument("--baseline", help="compare against this baseline file (overrides policy.baseline.path)")
    p.add_argument("--sarif", help="write a SARIF 2.1.0 report (GitHub code scanning)")
    p.add_argument("--junit", help="write a JUnit XML report")
    p.add_argument("--html", help="write a self-contained HTML report")
    p.add_argument(
        "--include-output",
        action="store_true",
        help="include model output snippets in SARIF/JUnit/HTML (default: omitted, they may contain secrets)",
    )
    p.set_defaults(func=_cmd_run)

    p = sub.add_parser("baseline", help="record the current results as the regression baseline")
    bsub = p.add_subparsers(dest="baseline_command", required=True)
    bp = bsub.add_parser("update", help="run the attacks and write the baseline file")
    bp.add_argument("--config", "-c", default=DEFAULT_CONFIG_PATH)
    bp.add_argument("--family", action="append", help="only this family (repeatable)")
    bp.add_argument("--trials", type=int, help="override run.trials")
    bp.add_argument("--out", help=f"baseline file (default: policy.baseline.path or {DEFAULT_BASELINE_PATH})")
    bp.set_defaults(func=_cmd_baseline_update)

    p = sub.add_parser("deep", help="adaptive deep attack against the target")
    p.add_argument("--config", "-c", required=True, help="deep config YAML")
    p.add_argument("--attacker-model", help="override attacker.model")
    p.add_argument("--max-rounds", type=int, help="override max_rounds")
    p.add_argument(
        "--strategy",
        action="append",
        choices=DEEP_STRATEGIES,
        help="adaptive strategy (repeatable; overrides `strategies:` in the config)",
    )
    p.add_argument("--report", help="write the Markdown report to this file")
    p.add_argument(
        "--export-wins",
        metavar="PATH",
        help="write promoted winning seeds as an attack pack YAML",
    )
    p.set_defaults(func=_cmd_deep)

    p = sub.add_parser(
        "generate",
        help="lab: generate attacks tailored to your app with an attacker LLM, saved as a pack",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--purpose", help="what the app does, for whom, with which tools and data")
    g.add_argument("--purpose-file", help="read the purpose from a file")
    p.add_argument("--family", action="append", help="family to generate (repeatable; default: all)")
    p.add_argument("--count", type=int, default=5, help="attacks per family (default 5)")
    p.add_argument("--level", action="append", type=int, choices=[1, 2, 3, 4, 5], help="levels to cover")
    p.add_argument("--lang", action="append", help="also add translated variants (repeatable)")
    p.add_argument("--id-prefix", default="GEN", help="attack id prefix (default GEN)")
    p.add_argument("--attacker-model", help="LiteLLM model string")
    p.add_argument("--attacker-api-base", help="attacker API base URL")
    p.add_argument("--out", "-o", required=True, help="pack YAML to write")
    p.set_defaults(func=_cmd_generate)

    p = sub.add_parser(
        "distill",
        help="lab: freeze llm_judge attacks into deterministic rubrics validated against the judge",
    )
    p.add_argument("pack", help="pack YAML with llm_judge attacks")
    p.add_argument("--config", "-c", default=DEFAULT_CONFIG_PATH, help="redgrade.yaml (target, judge)")
    p.add_argument("--out", "-o", help="pack YAML to write (default: overwrite the input)")
    p.add_argument("--trials", type=int, default=3, help="target outputs collected per attack")
    p.add_argument("--synthesize", type=int, default=3, help="synthetic examples per side (0: none)")
    p.add_argument("--min-agreement", type=float, default=0.9)
    p.add_argument("--min-precision", type=float, default=0.9)
    p.add_argument("--judge-model", help="LiteLLM model for the judge (default: `judge:` in config)")
    p.add_argument("--judge-api-base")
    p.add_argument("--attacker-model", help="LiteLLM model that writes the rubrics")
    p.add_argument("--attacker-api-base")
    p.set_defaults(func=_cmd_distill)

    p = sub.add_parser("compare", help="A/B: measure a defense (same attacks, without vs with it)")
    p.add_argument("--config", "-c", default=DEFAULT_CONFIG_PATH, help="baseline app (redgrade.yaml)")
    p.add_argument(
        "--defended", "-d", required=True, help="config of the defended app (only its target is used)"
    )
    p.add_argument("--family", action="append", help="only this family (repeatable)")
    p.add_argument("--trials", type=int, help="override run.trials")
    p.add_argument("--max-utility-drop", type=float, default=0.0, help="tolerated utility loss (0..1)")
    p.add_argument("--report", help="write the Markdown comparison to this file")
    p.add_argument("--json", help="write the JSON comparison to this file")
    p.set_defaults(func=_cmd_compare)

    p = sub.add_parser("compliance", help="show which framework controls the attack families cover")
    p.add_argument("--framework", action="append", help="owasp_llm_2025, owasp_asi_2026, mitre_atlas, ...")
    p.set_defaults(func=_cmd_compliance)

    p = sub.add_parser("translate", help="lab: add translated (L4) variants of a pack's attacks")
    p.add_argument("pack", help="pack YAML to translate")
    p.add_argument("--lang", action="append", required=True, help="target language (repeatable)")
    p.add_argument("--out", "-o", help="pack YAML to write (default: overwrite the input)")
    p.add_argument("--only-translations", action="store_true", help="write only the translated variants")
    p.add_argument("--attacker-model", help="LiteLLM model string")
    p.add_argument("--attacker-api-base", help="attacker API base URL")
    p.set_defaults(func=_cmd_translate)

    p = sub.add_parser("import-dataset", help="convert a red-teaming dataset (CSV / JSONL) into a pack")
    p.add_argument("dataset", help="dataset file (.csv, .tsv, .jsonl, .json)")
    p.add_argument("--preset", choices=["advbench", "jailbreakbench", "harmbench"])
    p.add_argument("--prompt-field", help="column with the attack prompt")
    p.add_argument("--document-field", help="column with context passed as a document")
    p.add_argument("--id-field", help="column with a stable id")
    p.add_argument("--target-field", help="column with the expected affirmative prefix")
    p.add_argument("--family", help="attack family (default: jailbreak, opt-in)")
    p.add_argument("--detector", help="override the detector (canary, contains, llm_judge, ...)")
    p.add_argument("--severity", default="high")
    p.add_argument("--level", type=int, default=1, choices=[1, 2, 3, 4, 5])
    p.add_argument("--id-prefix", default="DS")
    p.add_argument("--limit", type=int, help="import at most this many rows")
    p.add_argument("--out", "-o", required=True, help="pack YAML to write")
    p.set_defaults(func=_cmd_import_dataset)

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
    except (ConfigError, PackError, TargetError, BaselineError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

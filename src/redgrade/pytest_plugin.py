"""pytest integration: every attack becomes a test, with a security gate for the session.

Installed with redgrade (entry point ``pytest11``). In ``conftest.py`` define how to reach the
app, then parametrize tests over attacks::

    # conftest.py
    import pytest
    from redgrade import HttpTarget

    @pytest.fixture(scope="session")
    def redgrade_target():
        return HttpTarget("http://localhost:8000/chat", body={"message": "{{prompt}}"})

    # test_security.py
    from redgrade.pytest_plugin import attacks

    @attacks(families=["prompt_injection_direct", "prompt_injection_indirect"])
    def test_resists(redgrade, redgrade_attack):
        redgrade.assert_resisted(redgrade_attack)

    @attacks(families=["task_utility"])
    def test_still_useful(redgrade, redgrade_attack):
        redgrade.assert_resisted(redgrade_attack)       # utility probes: asserts the app answered

Each attack is its own test id (``test_resists[PI-D-001]``), so pytest's JUnit, ``-k`` and
``--lf`` work per attack. A target error fails the test (never a pass); an attack the target has
no surface for is skipped with the reason. Per-test overrides:
``@pytest.mark.redgrade(trials=5, max_asr=0.2, secrets=[...])``.

Options: ``--redgrade-trials``, ``--redgrade-config redgrade.yaml`` (secrets, identity, plugins,
judge and the *policy*, evaluated on everything the session ran: a failing gate fails the
session), ``--redgrade-report report.md``, ``--redgrade-json``, ``--redgrade-html``,
``--redgrade-sarif``, ``--redgrade-baseline .redgrade/baseline.json``.
"""

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from redgrade.constants import FAMILY_TASK_UTILITY, REPORT_SNIPPET_CHARS
from redgrade.loader import load_attacks
from redgrade.models import Attack, AttackResult, RunResult
from redgrade.runner import AttackRunner, RunConfig

__all__ = ["RedgradeSession", "attacks"]

_STASH: pytest.StashKey["RedgradeSession"] = pytest.StashKey()


def attacks(
    *,
    families: list[str] | None = None,
    ids: list[str] | None = None,
    packs: list[str] | None = None,
    include_opt_in: bool = False,
    levels: list[int] | None = None,
    severities: list[str] | None = None,
) -> pytest.MarkDecorator:
    """``pytest.mark.parametrize`` over the selected attacks, one test per attack id."""
    selected = load_attacks(extra_packs=packs, families=families, ids=ids, include_opt_in=include_opt_in)
    if levels:
        selected = [a for a in selected if a.level in levels]
    if severities:
        selected = [a for a in selected if a.severity in severities]
    return pytest.mark.parametrize("redgrade_attack", selected, ids=[a.id for a in selected])


def _snippet(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= REPORT_SNIPPET_CHARS else text[:REPORT_SNIPPET_CHARS] + "…"


class RedgradeSession:
    """Session state: run config, policy and every result the tests produced."""

    def __init__(self, config: pytest.Config) -> None:
        from redgrade.policy import Policy

        self.pytest_config = config
        self.run_config = RunConfig()
        self.policy: Policy | None = None
        self.judge: Any = None
        self.results: list[AttackResult] = []
        self.gate_passed: bool | None = None
        cfg_path = config.getoption("redgrade_config")
        if cfg_path:
            from redgrade.config import load_config
            from redgrade.extensions import prepare_extensions

            loaded = load_config(cfg_path)
            self.run_config = loaded.run
            self.policy = loaded.policy
            self.judge = prepare_extensions(loaded)
        trials = config.getoption("redgrade_trials")
        if trials:
            self.run_config = self.run_config.model_copy(update={"trials": int(trials)})

    def run_result(self) -> RunResult:
        return RunResult(results=list(self.results), trials_per_attack=self.run_config.trials)


class Redgrade:
    """The ``redgrade`` fixture: run one attack against a target and assert on it."""

    def __init__(self, session: RedgradeSession, request: pytest.FixtureRequest) -> None:
        self._session = session
        self._request = request
        marker = request.node.get_closest_marker("redgrade")
        self._overrides: dict[str, Any] = dict(marker.kwargs) if marker else {}

    @property
    def run_config(self) -> RunConfig:
        fields = set(RunConfig.model_fields)
        update = {k: v for k, v in self._overrides.items() if k in fields}
        return self._session.run_config.model_copy(update=update) if update else self._session.run_config

    def _target(self, target: Any) -> Any:
        if target is not None:
            return target
        try:
            return self._request.getfixturevalue("redgrade_target")
        except pytest.FixtureLookupError:
            raise pytest.UsageError(
                "define a `redgrade_target` fixture (e.g. in conftest.py) or pass target="
            ) from None

    def run(self, attack: Attack, target: Any = None) -> AttackResult:
        """Run ``attack`` for the configured trials; the result joins the session report."""
        result = (
            AttackRunner(judge=self._session.judge)
            .run([attack], self._target(target), self.run_config)
            .results[0]
        )
        self._session.results.append(result)
        return result

    def assert_resisted(
        self, attack: Attack, target: Any = None, *, max_asr: float | None = None
    ) -> AttackResult:
        """Fail if the attack worked in more than ``max_asr`` of valid trials (default 0).

        For ``task_utility`` probes, fail if the app did *not* answer in every trial (the
        ``max_asr`` tolerance applies to unanswered probes). Skipped attacks skip the test;
        errored trials fail it.
        """
        limit = self._overrides.get("max_asr", 0.0) if max_asr is None else max_asr
        result = self.run(attack, target)
        if result.skipped_reason:
            pytest.skip(f"{attack.id}: {result.skipped_reason}")
        if result.errors:
            err = next(t.error for t in result.trials if t.error)
            pytest.fail(
                f"{attack.id}: {result.errors}/{len(result.trials)} trials errored: {err}", pytrace=False
            )
        valid = len(result.valid_trials)
        utility = attack.family == FAMILY_TASK_UTILITY
        bad = valid - result.successes if utility else result.successes
        rate = bad / valid if valid else 1.0
        if rate > limit:
            trial = next((t for t in result.valid_trials if t.succeeded != utility), None)
            what = "benign request not answered" if utility else "attack succeeded"
            lines = [
                f"{attack.id} [{attack.severity}] {attack.title}: {what} in {bad}/{valid} trials "
                f"(limit {limit:.0%}); {attack.owasp}, family {attack.family}"
            ]
            if trial is not None:
                lines.append(f"  verdict: {trial.verdict}")
                lines.append(f"  output: {_snippet(trial.output)}")
            pytest.fail("\n".join(lines), pytrace=False)
        return result


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("redgrade", "LLM app red-teaming (redgrade)")
    group.addoption("--redgrade-trials", type=int, help="trials per attack (overrides the config)")
    group.addoption(
        "--redgrade-config", help="redgrade.yaml: run settings, plugins, judge and session policy"
    )
    group.addoption("--redgrade-report", help="write the session's Markdown report")
    group.addoption("--redgrade-json", help="write the session's JSON report")
    group.addoption("--redgrade-html", help="write the session's HTML report")
    group.addoption("--redgrade-sarif", help="write the session's SARIF report")
    group.addoption("--redgrade-baseline", help="compare the session against this baseline file")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "redgrade(**kwargs): per-test redgrade overrides (trials, max_asr, secrets, ...)"
    )


def _session(config: pytest.Config) -> RedgradeSession:
    if _STASH not in config.stash:
        config.stash[_STASH] = RedgradeSession(config)
    return config.stash[_STASH]


@pytest.fixture
def redgrade(request: pytest.FixtureRequest) -> Redgrade:
    """Run attacks and assert on them; results are collected for the session report."""
    return Redgrade(_session(request.config), request)


def _writers() -> dict[str, Callable[[Any], str]]:
    return {
        "redgrade_report": lambda r: r.to_markdown(),
        "redgrade_json": lambda r: r.to_json(),
        "redgrade_html": lambda r: r.to_html(),
        "redgrade_sarif": lambda r: r.to_sarif(),
    }


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    config = session.config
    state = config.stash.get(_STASH, None)
    if state is None or not state.results:
        return
    from redgrade.baseline import Baseline, compare
    from redgrade.policy import Policy, evaluate_policy
    from redgrade.sdk import _build_report

    run = state.run_result()
    policy = state.policy or Policy(max_asr=1.0, max_asr_by_severity={}, max_error_rate=1.0)
    comparison = None
    baseline_path = config.getoption("redgrade_baseline")
    if baseline_path:
        comparison = compare(run, Baseline.load(baseline_path), policy.baseline)
    checks = evaluate_policy(run, policy, comparison)
    report = _build_report(run, checks, policy)
    if comparison is not None:
        report = report.model_copy(update={"baseline": comparison})
    for option, render in _writers().items():
        path = config.getoption(option)
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(render(report), encoding="utf-8")
    state.gate_passed = report.passed if state.policy is not None or comparison is not None else None
    if state.gate_passed is False and session.exitstatus == 0:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter: Any, exitstatus: int, config: pytest.Config) -> None:
    state = config.stash.get(_STASH, None)
    if state is None or not state.results:
        return
    from redgrade.report import family_stats

    run = state.run_result()
    terminalreporter.section("redgrade")
    for family, st in sorted(family_stats(run).items()):
        label = "utility" if family == FAMILY_TASK_UTILITY else "ASR"
        rate = "n/a" if st["asr"] is None else f"{st['asr'] * 100:.0f}%"
        terminalreporter.write_line(f"{family:<30}{st['attacks']:>4} attacks  {label} {rate}")
    if state.gate_passed is not None:
        terminalreporter.write_line(f"session gate: {'PASSED' if state.gate_passed else 'FAILED'}")

import base64

import httpx2
import pytest

from redgrade.constants import FAMILY_STATUS_AVAILABLE
from redgrade.detectors import DetectorContext, get_detector
from redgrade.families import FAMILY_BY_ID
from redgrade.loader import PackError, load_attacks, load_builtin_attacks, load_pack_file
from redgrade.models import Attack, AttackResult, RunResult, Trial
from redgrade.policy import Policy, evaluate_policy, passed
from redgrade.render import render
from redgrade.runner import RunConfig, run_attacks
from redgrade.targets import HttpTarget, TargetError, wrap_function


def ctx(**kw):
    base = {"canary": "RG-AAAA1111", "output": "", "inputs": ""}
    return DetectorContext(**{**base, **kw})


def attack(**kw) -> Attack:
    base = dict(
        id="T-1",
        family="prompt_injection_direct",
        title="t",
        owasp="LLM01",
        severity="high",
        prompt="say {CANARY}",
        detector="canary",
    )
    return Attack(**{**base, **kw})


# --- render ---------------------------------------------------------------------------------


def test_render_substitutes_canary_then_encodes():
    out = render("x {b64:Reply with: {CANARY}} y", "RG-1234ABCD")
    encoded = out.split()[1]
    assert base64.b64decode(encoded).decode() == "Reply with: RG-1234ABCD"


def test_render_rot13():
    assert render("{rot13:abc}", "RG-0") == "nop"


# --- detectors ------------------------------------------------------------------------------


def test_canary_detector():
    d = get_detector("canary")
    assert d(ctx(output="sure: RG-AAAA1111"))[0] is True
    assert d(ctx(output="I cannot do that"))[0] is False


def test_secret_leak_is_case_insensitive_and_needs_secrets():
    d = get_detector("secret_leak")
    assert d(ctx(output="the key is abc-123", secrets=["ABC-123"]))[0] is True
    assert d(ctx(output="nothing here", secrets=["ABC-123"]))[0] is False
    assert d(ctx(output="abc-123", secrets=[]))[0] is False


def test_pii_ignores_data_the_user_supplied():
    d = get_detector("pii_regex")
    assert d(ctx(output="mail a@b.com", inputs="my mail is a@b.com"))[0] is False
    assert d(ctx(output="mail a@b.com", inputs="hello"))[0] is True
    assert d(ctx(output="IBAN IT60X0542811101000000123456"))[0] is True


def test_markdown_exfil_respects_allowlist():
    d = get_detector("markdown_exfil")
    out = "![x](https://cdn.good.com/i.png?v=1)"
    assert d(ctx(output=out, allowed_hosts=["good.com"]))[0] is False
    assert d(ctx(output=out))[0] is True
    assert d(ctx(output="![x](https://evil.com/p.png)"))[0] is False  # no data in the URL
    assert d(ctx(output="[a](https://evil.com/p?c=RG-AAAA1111)"))[0] is True


def test_output_length():
    d = get_detector("output_length")
    assert d(ctx(output="a" * 10, args={"max_chars": 5}))[0] is True
    assert d(ctx(output="a" * 5, args={"max_chars": 5}))[0] is False


def test_unknown_detector():
    with pytest.raises(ValueError):
        get_detector("nope")


# --- packs ----------------------------------------------------------------------------------


def test_builtin_packs_are_consistent():
    attacks = load_builtin_attacks()
    assert len(attacks) >= 25
    ids = [a.id for a in attacks]
    assert len(ids) == len(set(ids))
    for a in attacks:
        assert a.family in FAMILY_BY_ID
        assert FAMILY_BY_ID[a.family].status == FAMILY_STATUS_AVAILABLE
        assert a.owasp
        if a.delivery == "document":
            assert a.document


def test_every_family_marked_available_has_attacks():
    present = {a.family for a in load_builtin_attacks()}
    for fam in FAMILY_BY_ID.values():
        if fam.status == FAMILY_STATUS_AVAILABLE:
            assert fam.id in present, fam.id


def test_load_filters_by_family():
    got = load_attacks(families=["resource_abuse"])
    assert got and all(a.family == "resource_abuse" for a in got)
    with pytest.raises(PackError):
        load_attacks(families=["nope"])


def test_custom_pack_validation(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("family: jailbreak\nattacks:\n  - {id: X, title: t, prompt: p, detector: nope}\n")
    with pytest.raises(PackError, match="unknown detector"):
        load_pack_file(bad)
    good = tmp_path / "good.yaml"
    good.write_text(
        "family: jailbreak\nattacks:\n  - {id: C-1, title: t, prompt: 'say {CANARY}', detector: canary}\n"
    )
    assert load_pack_file(good)[0].owasp == "LLM01"


# --- runner ---------------------------------------------------------------------------------


def test_runner_counts_successes_and_trials():
    echo = lambda prompt, docs: prompt  # noqa: E731  obeys everything
    run = run_attacks([attack()], echo, RunConfig(trials=4))
    assert run.results[0].asr == 1.0 and len(run.results[0].trials) == 4


def test_errors_are_not_successes_and_not_passes():
    def boom(prompt, docs):
        raise RuntimeError("down")

    run = run_attacks([attack()], boom, RunConfig(trials=2))
    r = run.results[0]
    assert r.errors == 2 and r.asr is None
    checks = evaluate_policy(run, Policy())
    assert not passed(checks)  # a dead target must not look secure


def test_attacks_needing_secrets_are_skipped_without_them():
    a = attack(requires_secrets=True, detector="secret_leak")
    run = run_attacks([a], lambda p, d: "x", RunConfig(trials=1))
    assert run.results[0].skipped_reason and not run.executed


def test_flaky_attack_is_flagged():
    r = AttackResult(attack=attack(), trials=[Trial(succeeded=True), Trial(succeeded=False)])
    assert r.flaky and r.asr == 0.5
    assert not AttackResult(attack=attack(), trials=[Trial(succeeded=True)]).flaky


def test_concurrency_runs_all_attacks():
    atts = [attack(id=f"T-{i}") for i in range(6)]
    run = run_attacks(atts, lambda p, d: "safe", RunConfig(trials=2, concurrency=3))
    assert [r.attack.id for r in run.results] == [a.id for a in atts]


# --- policy ---------------------------------------------------------------------------------


def _run(*specs):
    results = []
    for sev, fam, wins, n in specs:
        r = AttackResult(attack=attack(severity=sev, family=fam))
        r.trials = [Trial(succeeded=i < wins) for i in range(n)]
        results.append(r)
    return RunResult(results=results, trials_per_attack=3)


def test_policy_overall_and_severity():
    run = _run(("critical", "prompt_injection_direct", 1, 10), ("low", "resource_abuse", 0, 10))
    checks = {c.name: c for c in evaluate_policy(run, Policy(max_asr=0.5))}
    assert checks["asr.overall"].passed
    assert not checks["asr.severity.critical"].passed


def test_policy_family_limit_and_coverage():
    run = _run(("high", "info_disclosure", 0, 5))
    p = Policy(max_asr_by_family={"info_disclosure": 0.0}, require_families=["jailbreak"])
    checks = {c.name: c for c in evaluate_policy(run, p)}
    assert checks["asr.family.info_disclosure"].passed
    assert not checks["coverage.jailbreak"].passed


def test_policy_rejects_unknown_keys():
    with pytest.raises(ValueError):
        Policy.from_dict({"max_asrr": 0.1})


# --- targets --------------------------------------------------------------------------------


def test_wrap_function_passes_documents_only_when_accepted():
    assert wrap_function(lambda p: f"one:{p}")("a", ["d"]) == "one:a"
    assert wrap_function(lambda p, documents: f"{p}|{documents}")("a", ["d"]) == "a|['d']"


def test_http_target_fills_template_and_reads_path():
    seen = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        import json

        seen["body"] = json.loads(request.content)
        seen["auth"] = request.headers.get("authorization")
        return httpx2.Response(200, json={"choices": [{"message": {"content": "hi"}}]})

    client = httpx2.Client(transport=httpx2.MockTransport(handler))
    target = HttpTarget(
        "http://app/chat",
        body={"message": "{{prompt}}", "docs": "{{documents}}"},
        response_path="choices.0.message.content",
        headers={"Authorization": "Bearer t"},
        client=client,
    )
    assert target("q", ["d1", "d2"]) == "hi"
    assert seen["body"] == {"message": "q", "docs": ["d1", "d2"]}
    assert seen["auth"] == "Bearer t"


def test_http_target_error_is_wrapped():
    client = httpx2.Client(transport=httpx2.MockTransport(lambda r: httpx2.Response(500)))
    with pytest.raises(TargetError):
        HttpTarget("http://app", client=client)("q", [])


# --- config / targets factory ---------------------------------------------------------------


def test_config_loader_function_and_http_targets(tmp_path):
    from redgrade.config import ConfigError, load_config
    from redgrade.constants import DEFAULT_MAX_OUTPUT_CHARS
    from redgrade.targets import FunctionTargetConfig, HttpTargetConfig

    fn = tmp_path / "fn.yaml"
    fn.write_text(
        "target:\n  type: function\n  path: examples.demo_app:vulnerable\n"
        "run:\n  trials: 2\npolicy:\n  max_asr: 0.5\n"
    )
    cfg = load_config(fn)
    assert isinstance(cfg.target, FunctionTargetConfig)
    assert cfg.target.path == "examples.demo_app:vulnerable"
    assert cfg.run.trials == 2
    assert cfg.run.max_output_chars == DEFAULT_MAX_OUTPUT_CHARS

    http = tmp_path / "http.yaml"
    http.write_text(
        "target:\n  type: http\n  url: http://localhost:9/chat\n  timeout: 1.5\n"
        "run:\n  trials: 1\npolicy: {}\n"
    )
    hcfg = load_config(http)
    assert isinstance(hcfg.target, HttpTargetConfig)
    assert hcfg.target.url == "http://localhost:9/chat"
    assert hcfg.target.timeout == 1.5
    assert hcfg.run.trials == 1

    bad = tmp_path / "bad.yaml"
    bad.write_text("target:\n  type: http\nrun: {}\n")
    with pytest.raises(ConfigError):
        load_config(bad)


def test_target_factory_rejects_unknown_type():
    from redgrade.targets import TargetFactory

    with pytest.raises(TargetError, match="unknown target type"):
        TargetFactory().build({"type": "grpc", "path": "x:y"})

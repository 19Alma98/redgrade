"""Out-of-band collector, attacker fixtures, the oob_callback detector and the oob pack."""

import json
import threading
import time
from pathlib import Path

import httpx2
import pytest

from examples.demo_app import hardened_browsing_agent, vulnerable_browsing_agent
from redgrade import HttpTarget, Policy, check
from redgrade.cli import main
from redgrade.config import load_config
from redgrade.constants import OOB_NOT_FETCHED, PIPELINE_CI_OOB, SKIP_NO_OOB
from redgrade.detectors import DetectorContext, oob_callback
from redgrade.loader import PackError, load_attacks, load_pack_file
from redgrade.oob import Fixture, OobHit, OobServer, oob_scope
from redgrade.render import render
from redgrade.runner import RunConfig, run_attacks, run_trial
from redgrade.targets import ChatTarget, wrap_function

ROOT = Path(__file__).resolve().parent.parent
CANARY = "RG-00AA11BB"
SECRET = "ACME-SECRET-7741"


def _get(url: str, **kw) -> httpx2.Response:
    with httpx2.Client(timeout=3.0, trust_env=False) as client:
        return client.request(kw.pop("method", "GET"), url, **kw)


@pytest.fixture
def server():
    with OobServer(wait=0.2) as srv:
        yield srv


def _oob_attacks():
    return load_attacks(families=["oob_exfiltration"])


def _pack(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "pack.yaml"
    path.write_text(body, encoding="utf-8")
    return path


# --- collector ------------------------------------------------------------------------------


def test_server_serves_fixtures_and_records_hits(server):
    server.register(CANARY, [Fixture(path="a/page.html", body="<p>hi</p>")])
    base = server.trial_url(CANARY)
    page = _get(f"{base}/f/a/page.html")
    assert page.status_code == 200 and page.text == "<p>hi</p>"
    assert page.headers["content-type"].startswith("text/html")
    assert _get(f"{base}/f/missing.html").status_code == 404
    pixel = _get(f"{base}/x/leak?d=hello%20world", method="POST", content="body!")
    assert pixel.status_code == 200 and pixel.headers["content-type"] == "image/gif"
    kinds = [(h.kind, h.method, h.path) for h in server.hits(CANARY)]
    assert kinds == [
        ("fixture", "GET", f"/t/{CANARY}/f/a/page.html"),
        ("fixture", "GET", f"/t/{CANARY}/f/missing.html"),
        ("callback", "POST", f"/t/{CANARY}/x/leak"),
    ]
    leak = server.hits(CANARY, "callback")[0]
    assert "hello world" in leak.text and "body!" in leak.text


def test_canary_anywhere_attributes_the_request(server):
    server.register(CANARY, [])
    _get(f"{server.base_url}/collect?token={CANARY}")
    _get(f"{server.base_url}/other")
    _get(f"{server.base_url}/t/RG-FFFFFFFF/x")
    assert [h.path for h in server.hits(CANARY, "callback")] == ["/collect"]
    assert len(server.unattributed()) == 2


def test_wait_for_callback(server):
    server.register(CANARY, [])
    start = time.monotonic()
    assert not server.wait_for_callback(CANARY, timeout=0.1)
    assert time.monotonic() - start >= 0.1
    threading.Timer(0.05, lambda: _get(f"{server.trial_url(CANARY)}/x/late")).start()
    assert server.wait_for_callback(CANARY, timeout=2.0)


def test_release_and_public_url():
    srv = OobServer(public_url="http://host.docker.internal:8787/")
    assert srv.trial_url(CANARY) == f"http://host.docker.internal:8787/t/{CANARY}"
    with pytest.raises(RuntimeError):
        OobServer().base_url  # noqa: B018
    with OobServer() as running:
        running.register(CANARY, [])
        _get(f"{running.trial_url(CANARY)}/x")
        running.release(CANARY)
        assert running.hits(CANARY) == []
    assert not running.running


def test_fixture_path_validation():
    with pytest.raises(ValueError):
        Fixture(path="../etc/passwd", body="x")
    assert Fixture(path="/page.html", body="x").path == "page.html"


def test_render_oob_url_placeholder_and_scope():
    assert render("{OOB_URL}/x", CANARY) == f"http://oob.redgrade.invalid/t/{CANARY}/x"
    with oob_scope("http://127.0.0.1:9/"):
        assert render("go {OOB_URL}/f/p", CANARY) == f"go http://127.0.0.1:9/t/{CANARY}/f/p"
    assert render("{OOB_URL}", CANARY).startswith("http://oob.redgrade.invalid")


# --- loader ---------------------------------------------------------------------------------


def test_builtin_pack_flags():
    attacks = {a.id: a for a in _oob_attacks()}
    assert len([a for a in attacks.values() if not a.mutation]) == 6
    assert attacks["OOB-001~b64"].mutate_scope == "fixtures"
    assert all(a.requires_oob for a in attacks.values())
    assert attacks["OOB-004"].fixtures[1].path == "news-2.html"
    assert attacks["OOB-005"].fixtures[0].content_type == "application/json"
    assert not attacks["OOB-006"].requires_fetch and attacks["OOB-001"].requires_fetch


def test_loader_infers_requires_oob_from_placeholder_and_detector(tmp_path):
    pack = _pack(
        tmp_path,
        """
family: oob_exfiltration
attacks:
  - {id: A-1, title: x, detector: canary, prompt: "see {OOB_URL}/x"}
  - {id: A-2, title: x, detector: oob_callback, prompt: "hi"}
  - {id: A-3, title: x, detector: canary, prompt: "hi"}
""",
    )
    flags = {a.id: (a.requires_oob, a.requires_fetch) for a in load_pack_file(pack)}
    assert flags == {"A-1": (True, False), "A-2": (True, False), "A-3": (False, False)}


@pytest.mark.parametrize(
    ("extra", "match"),
    [
        ("fixtures: [{path: a.html}]", "path and body"),
        ("fixtures: []", "non-empty"),
        ("requires_fetch: true", "requires_fetch needs fixtures"),
        ("fixtures: [{path: a.html, body: x}]\n    requires_oob: false", "need requires_oob"),
        ("fixtures: [{path: ../a.html, body: x}]", "fixture path"),
    ],
)
def test_loader_rejects_bad_oob_fields(tmp_path, extra, match):
    pack = _pack(
        tmp_path,
        f"""
family: oob_exfiltration
attacks:
  - id: A-1
    title: x
    detector: canary
    prompt: hi
    {extra}
""",
    )
    with pytest.raises(PackError, match=match):
        load_pack_file(pack)


# --- detector -------------------------------------------------------------------------------


def _hit(method="GET", path="/t/x/x/leak", query="", body="", kind="callback") -> OobHit:
    return OobHit(kind=kind, method=method, path=path, query=query, body=body)


def _ctx(hits, **args) -> DetectorContext:
    return DetectorContext(canary=CANARY, output="", inputs="", secrets=[SECRET], oob_hits=hits, args=args)


def test_oob_callback_detector():
    assert not oob_callback(_ctx([]))[0]
    assert not oob_callback(_ctx([_hit(kind="fixture")]))[0]
    assert oob_callback(_ctx([_hit()]))[0]
    assert not oob_callback(_ctx([_hit()], methods=["POST"]))[0]
    assert oob_callback(_ctx([_hit(method="POST")], methods=["post"]))[0]
    assert not oob_callback(_ctx([_hit(query="d=nothing")], require="secret"))[0]
    assert oob_callback(_ctx([_hit(query="d=ACME-SECRET-7741")], require="secret"))[0]
    assert oob_callback(_ctx([_hit(body="code ACME%2DSECRET%2D7741")], require="secret"))[0]
    assert oob_callback(_ctx([_hit(query=f"t={CANARY}")], patterns=["{CANARY}"]))[0]
    assert not oob_callback(_ctx([_hit(query="t=zzz")], patterns=["{CANARY}"]))[0]


# --- runner ---------------------------------------------------------------------------------


def test_attacks_are_skipped_without_collector():
    config = RunConfig(trials=1, secrets=[SECRET])
    run = run_attacks(_oob_attacks(), wrap_function(vulnerable_browsing_agent), config)
    assert {r.skipped_reason for r in run.results} == {SKIP_NO_OOB}


def test_trial_not_fetching_the_fixture_is_inconclusive(server):
    attack = next(a for a in _oob_attacks() if a.id == "OOB-001")
    trial = run_trial(attack, wrap_function(lambda prompt: "I cannot browse."), RunConfig(), oob=server)
    assert trial.error == OOB_NOT_FETCHED and not trial.succeeded
    # an attack without fixtures (OOB-006) is a plain resisted trial
    email = next(a for a in _oob_attacks() if a.id == "OOB-006")
    trial = run_trial(email, wrap_function(lambda prompt, documents: "ok"), RunConfig(), oob=server)
    assert trial.error is None and not trial.succeeded


def test_demo_browsing_agents_end_to_end(server):
    config = RunConfig(trials=1, secrets=[SECRET])
    bad = run_attacks(_oob_attacks(), wrap_function(vulnerable_browsing_agent), config, oob=server)
    good = run_attacks(_oob_attacks(), wrap_function(hardened_browsing_agent), config, oob=server)
    expected = {f"OOB-00{i}": 1.0 for i in range(1, 7)} | {"OOB-001~b64": 1.0}
    assert {r.attack.id: r.asr for r in bad.results} == expected
    assert all(r.asr == 0.0 and r.errors == 0 for r in good.results)
    exfil = next(r for r in bad.results if r.attack.id == "OOB-003").trials[0]
    assert any(SECRET in h.text for h in exfil.oob_hits)
    assert not server.unattributed()


def test_concurrent_trials_keep_hits_apart(server):
    config = RunConfig(trials=2, concurrency=4, secrets=[SECRET])
    run = run_attacks(_oob_attacks(), wrap_function(vulnerable_browsing_agent), config, oob=server)
    for result in run.results:
        for trial in result.trials:
            assert all(trial.canary in h.path for h in trial.oob_hits)


# --- SDK, config, CLI -----------------------------------------------------------------------


def _browsing_endpoint():
    """An HTTP app whose handler runs the vulnerable browsing agent on the request."""

    def handler(request):
        body = json.loads(request.content)
        obs = vulnerable_browsing_agent(body["message"], body.get("context") or [])
        return httpx2.Response(200, json={"reply": obs.output})

    return httpx2.Client(transport=httpx2.MockTransport(handler))


def test_check_with_oob_adds_pipeline_and_fails():
    target = HttpTarget(
        "http://app/chat",
        body={"message": "{{prompt}}", "context": "{{documents}}"},
        response_path="reply",
        client=_browsing_endpoint(),
    )
    report = check(target, oob=True, trials=1, policy=Policy(max_asr=1.0, require_families=[]))
    assert PIPELINE_CI_OOB in report.pipelines_run
    oob = [r for r in report.run.results if r.attack.family == "oob_exfiltration"]
    assert oob and all(r.asr == 1.0 for r in oob if not r.skipped_reason)
    assert not report.passed
    no_oob = check(target, trials=1, pipelines=[PIPELINE_CI_OOB], secrets=[SECRET])
    assert all(r.skipped_reason == SKIP_NO_OOB for r in no_oob.run.results)


def test_check_reuses_a_running_server():
    target = ChatTarget("http://llm", client=httpx2.Client(transport=httpx2.MockTransport(lambda r: None)))
    with OobServer() as srv:
        report = check(target, oob=srv, pipelines=[PIPELINE_CI_OOB], trials=1)
        assert srv.running
    assert report.run.results


def test_config_parses_oob_and_chat_target(tmp_path):
    cfg = tmp_path / "redgrade.yaml"
    cfg.write_text(
        "target: {type: chat, url: 'http://llm', api: anthropic}\noob: {port: 0, wait: 0.5}\n",
        encoding="utf-8",
    )
    config = load_config(cfg)
    assert config.target.type == "chat" and config.oob is not None and config.oob.wait == 0.5
    cfg.write_text("target: {type: chat, url: 'http://llm'}\noob: {enabled: false}\n", encoding="utf-8")
    assert load_config(cfg).oob is None


def test_cli_browsing_demos(monkeypatch, capsys):
    monkeypatch.chdir(ROOT)
    assert main(["run", "-c", "examples/redgrade.browsing.vulnerable.yaml"]) == 1
    assert "out-of-band collector listening" in capsys.readouterr().err
    assert main(["run", "-c", "examples/redgrade.browsing.hardened.yaml"]) == 0

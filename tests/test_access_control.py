"""Access control (BOLA / BFLA / RBAC): identity placeholders, access_violation, demo agents."""

from examples.demo_app import hardened_agent, vulnerable, vulnerable_agent
from redgrade import RunConfig, load_attacks, run_attacks
from redgrade.config import ConfigLoader
from redgrade.detectors import DetectorContext, access_violation
from redgrade.identity import Identity, identity_scope
from redgrade.models import ToolCall
from redgrade.render import render


def _ctx(output="", tools=None, victim_data=None, **args) -> DetectorContext:
    return DetectorContext(
        canary="RG-00000000",
        output=output,
        inputs="",
        tools_called=tools or [],
        victim_data=victim_data or [],
        args=args,
    )


def test_identity_placeholders_render_per_scope() -> None:
    assert render("{USER_ID}->{VICTIM_ID} {ADMIN_ROLE}", "RG-1") == "user-1001->user-2002 admin"
    with identity_scope(Identity(user_id="C-1", victim_id="C-2", admin_role="root")):
        assert render("{USER_ID}/{VICTIM_ID}/{ADMIN_ROLE}/{b64:{VICTIM_ID}}", "RG-1") == "C-1/C-2/root/Qy0y"


def test_access_violation_paths() -> None:
    with identity_scope(Identity(victim_id="C-2")):
        assert access_violation(_ctx(tools=[ToolCall(name="get_orders", arguments={"id": "c-2"})]))[0]
        assert not access_violation(_ctx(tools=[ToolCall(name="get_orders", arguments={"id": "C-1"})]))[0]
        assert access_violation(_ctx("mail: giulia@x.it", victim_data=["giulia@x.it"]))[0]
        assert access_violation(
            _ctx(tools=[ToolCall(name="delete_user", arguments={})], names=["delete_user"])
        )[0]
        call = ToolCall(name="update_profile", arguments={"value": "root"})
        assert not access_violation(_ctx(tools=[call], arg_patterns=["{ADMIN_ROLE}"]))[0]
    with identity_scope(Identity(admin_role="root")):
        assert access_violation(_ctx(tools=[call], arg_patterns=["{ADMIN_ROLE}"]))[0]


def _run(target, **cfg):
    return run_attacks(load_attacks(families=["access_control"]), target, RunConfig(trials=1, **cfg))


def test_pack_breaks_vulnerable_agent_and_not_hardened() -> None:
    attacks = load_attacks(families=["access_control"])
    assert len(attacks) == 11 and all(a.level for a in attacks)
    won = {r.attack.id for r in _run(vulnerable_agent).results if r.successes}
    assert {f"AC-00{i}" for i in range(1, 10)} | {"AC-010"} <= won
    hard = _run(hardened_agent)
    assert not [r.attack.id for r in hard.results if r.successes]


def test_text_only_attack_skipped_without_victim_data_or_tools() -> None:
    run = _run(vulnerable)
    skipped = {r.attack.id: r.skipped_reason for r in run.results if r.skipped_reason}
    assert "victim_data" in skipped["AC-011"]
    run = _run(vulnerable, identity=Identity(victim_data=["luca.verdi@example.com"]))
    assert not next(r for r in run.results if r.attack.id == "AC-011").skipped_reason


def test_identity_block_in_config(tmp_path) -> None:
    cfg = tmp_path / "redgrade.yaml"
    cfg.write_text(
        "target: {type: function, path: examples.demo_app:vulnerable}\n"
        "identity: {user_id: C-1, victim_id: C-2, victim_data: [a@b.c]}\n"
    )
    ident = ConfigLoader().load(cfg).run.identity
    assert (ident.user_id, ident.victim_id, ident.role, ident.victim_data) == (
        "C-1",
        "C-2",
        "customer",
        ["a@b.c"],
    )

import json

from conftest import EXAMPLES, PASSWORD
from platform_shell.cli import main
from platform_shell.identity import UserStore


def test_cli_user_admin_and_registry(tmp_path, monkeypatch, capsys):
    db = str(tmp_path / "u.db")
    monkeypatch.setenv("PLATFORM_DB", db)
    monkeypatch.setenv("PLATFORM_NEW_USER_PASSWORD", PASSWORD)
    assert main(["init-db"]) == 0
    assert main(["add-user", "tim.maguire", "--name", "Tim Maguire", "--roles", "program_director,bd"]) == 0
    assert UserStore(db).authenticate("tim.maguire", PASSWORD).roles == ["program_director", "bd"]
    assert main(["add-user", "x.y", "--name", "X", "--roles", "wizard"]) == 1
    assert main(["list-users"]) == 0
    assert "tim.maguire" in capsys.readouterr().out
    assert main(["list-services", str(EXAMPLES), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert {d["capability"] for d in out} >= {"asset-registry", "gxp-audit-platform"}


def test_cli_audit_spool_commands(tmp_path, monkeypatch, capsys):
    spool = tmp_path / "s.jsonl"
    monkeypatch.setenv("PLATFORM_AUDIT_SPOOL", str(spool))
    monkeypatch.setenv("PLATFORM_AUDIT_URL", "")  # offline
    from platform_shell.audit import AuditClient
    AuditClient(None, source_system="platform-shell", spool_path=spool).log(
        actor="pd.lee", actor_type="human", action="AUTO_LOG", resource="asset:AST-000001")
    assert main(["verify-audit-spool"]) == 0
    assert json.loads(capsys.readouterr().out)["checked"] == 1
    assert main(["replay-audit"]) == 1  # service not configured, event stays pending
    assert json.loads(capsys.readouterr().out)["remaining"] == 1

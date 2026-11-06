import json
import sys
from pathlib import Path

import pytest

from fakes import fake_audittrail, verify_events
from platform_shell._vendor.audittrail_chain import GENESIS_HASH, _compute_hash
from platform_shell.audit import AuditClient, AuditSpool, verify_local_chain
from platform_shell.transport import WSGITransport

EV = dict(actor="pd.lee", actor_type="human", action="HUMAN_APPROVED", resource="asset:AST-000001")


def _client(tmp_path, apps):
    return AuditClient("http://audit.test", source_system="platform-shell", spool_path=tmp_path / "spool.jsonl",
                       transport=WSGITransport(apps))


def test_posts_form_fields_not_json(tmp_path):
    svc = fake_audittrail()
    r = _client(tmp_path, {"audit.test": svc}).log(**EV, detail={"gate": "G2"})
    assert r.delivered and not r.spooled
    raw = svc.config["RAW"][-1]
    assert raw["content_type"].startswith("application/x-www-form-urlencoded") and raw["json"] is None
    ev = svc.config["EVENTS"][-1]
    assert ev["actor"] == "pd.lee" and ev["action"] == "HUMAN_APPROVED" and json.loads(ev["detail"]) == {"gate": "G2"}
    assert verify_events(svc.config["EVENTS"])


def test_service_down_spools_with_same_hash_chain(tmp_path):
    c = _client(tmp_path, {})  # nothing listening
    receipts = [c.log(**EV, detail=f"event {i}") for i in range(3)]
    assert all(r.spooled and not r.delivered for r in receipts)
    entries = list(c.spool.entries())
    assert [e["seq"] for e in entries] == [1, 2, 3] and entries[0]["prev_hash"] == GENESIS_HASH
    e = entries[1]
    assert e["hash"] == _compute_hash(e["prev_hash"], e["ts"], e["source_system"], e["actor"], e["actor_type"],
                                      e["action"], e["resource"], e["detail"], e["related_event_id"])
    assert entries[2]["prev_hash"] == entries[1]["hash"]
    assert verify_local_chain(c.spool.path)["valid"]


def test_tampering_with_spool_is_detected(tmp_path):
    c = _client(tmp_path, {})
    for i in range(3):
        c.log(**EV, detail=f"event {i}")
    lines = c.spool.path.read_text().splitlines()
    doctored = json.loads(lines[1])
    doctored["actor"] = "someone.else"
    lines[1] = json.dumps(doctored, sort_keys=True)
    c.spool.path.write_text("\n".join(lines) + "\n")
    v = verify_local_chain(c.spool.path)
    assert not v["valid"] and v["broken_at_seq"] == 2
    assert "refusing" in c.replay()["error"]


def test_rejected_event_is_spooled_not_lost(tmp_path):
    svc = fake_audittrail()
    r = _client(tmp_path, {"audit.test": svc}).log(**EV, related_event_id=999)  # unknown related id
    assert r.spooled and "rejected" in r.error and not svc.config["EVENTS"]


def test_invalid_input_raises_before_anything_is_sent(tmp_path):
    c = _client(tmp_path, {})
    with pytest.raises(ValueError):
        c.log(actor="pd.lee", actor_type="human", action="APPROVE", resource="asset:AST-000001")
    with pytest.raises(ValueError):
        c.log(actor="", actor_type="human", action="AUTO_LOG", resource="x")
    assert not c.spool.path.exists()


def test_replay_delivers_in_order_once(tmp_path):
    spool = tmp_path / "spool.jsonl"
    down = AuditClient("http://audit.test", source_system="platform-shell", spool_path=spool,
                       transport=WSGITransport({}))
    for i in range(3):
        down.log(**EV, detail=f"event {i}")
    svc = fake_audittrail()
    up = AuditClient("http://audit.test", source_system="platform-shell", spool_path=spool,
                     transport=WSGITransport({"audit.test": svc}))
    result = up.replay()
    assert result == {"attempted": 3, "delivered": 3, "remaining": 0, "error": None}
    details = [e["detail"] for e in svc.config["EVENTS"]]
    assert details[0].startswith("event 0 [spooled ts=") and "seq=1" in details[0]
    assert [d.split(" [")[0] for d in details] == ["event 0", "event 1", "event 2"]
    assert up.replay()["attempted"] == 0  # idempotent
    assert verify_local_chain(spool)["valid"]  # chained file untouched by replay


def test_replay_stops_at_first_failure(tmp_path):
    c = _client(tmp_path, {})
    c.log(**EV)
    c.log(**EV)
    out = c.replay()
    assert out["attempted"] == 1 and out["delivered"] == 0 and out["remaining"] == 2 and out["error"]


def test_offline_mode_always_spools(tmp_path):
    c = AuditClient(None, source_system="platform-shell", spool_path=tmp_path / "s.jsonl")
    assert c.log(**EV).spooled
    assert AuditSpool(tmp_path / "s.jsonl").pending()[0]["actor"] == "pd.lee"


UPSTREAM = Path("/home/claude/audittrailservice")


@pytest.mark.skipif(not (UPSTREAM / "audittrail").is_dir(), reason="AuditTrailService checkout not available")
def test_compatible_with_real_audittrailservice(tmp_path, monkeypatch):
    """Runs only where a checkout of timjm25/AuditTrailService exists (not in CI)."""
    monkeypatch.syspath_prepend(str(UPSTREAM))
    from audittrail.app import create_app as audit_app  # type: ignore
    from audittrail.model import Model  # type: ignore

    db = str(tmp_path / "audit.db")
    c = AuditClient("http://audit.test", source_system="platform-shell", spool_path=tmp_path / "s.jsonl",
                    transport=WSGITransport({"audit.test": audit_app(db)}))
    assert c.log(**EV, detail={"k": "v"}).delivered
    bad = c.log(**EV, related_event_id=12345)  # real service rejects with HTTP 200 + banner
    assert bad.spooled
    m = Model(db)
    assert m.stats()["total_events"] == 1 and m.verify_chain()["valid"]
    assert m.events()[0]["actor"] == "pd.lee"
    for name in [n for n in sys.modules if n == "audittrail" or n.startswith("audittrail.")]:
        sys.modules.pop(name)

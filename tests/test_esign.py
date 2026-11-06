import json
from importlib import resources

import pytest

from conftest import PASSWORD, Clock
from platform_shell.audit import AuditClient
from platform_shell.esign import MEANINGS, ESignError, ESignService, check_signature
from platform_shell.identity import AccountLocked, InvalidCredentials, UserStore
from platform_shell.transport import WSGITransport
from fakes import fake_audittrail


def common_signature_validator():
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    common = json.loads(resources.files("platform_shell._vendor").joinpath("common_1_0_0.json").read_text())
    registry = referencing.Registry().with_resource(common["$id"], referencing.Resource.from_contents(common))
    schema = {"$schema": "https://json-schema.org/draft/2020-12/schema",
              "$ref": "urn:cdmo-agent-contracts:Common:1.0.0#/$defs/signature"}
    return jsonschema.Draft202012Validator(schema, registry=registry,
                                           format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER)


@pytest.fixture
def env(tmp_path):
    clock = Clock()
    users = UserStore(str(tmp_path / "u.db"), lockout_threshold=3, clock=clock.dt)
    users.create_user("qa.patel", "Priya Patel", ["qa"], PASSWORD)
    users.create_user("viewer.kim", "Viewer Kim", ["viewer"], PASSWORD)
    svc = fake_audittrail()
    audit = AuditClient("http://audit.test", source_system="platform-shell", spool_path=tmp_path / "s.jsonl",
                        transport=WSGITransport({"audit.test": svc}))
    return ESignService(users, audit, clock=clock.dt), users, svc


def test_signature_matches_common_contract_exactly(env):
    esign, users, svc = env
    p = users.principal(users.get("qa.patel"))
    res = esign.sign(p, meaning="approved", reason="Gate G2 criteria met", resource="asset:AST-000001",
                     password=PASSWORD)
    sig = res.signature
    assert set(sig) == {"signer_id", "signer_name", "meaning", "signed_at", "method"}
    assert sig["signer_id"] == "qa.patel" and sig["signer_name"] == "Priya Patel"
    assert sig["method"] == "electronic" and sig["signed_at"].endswith("Z")
    errors = list(common_signature_validator().iter_errors(sig))
    assert errors == []
    check_signature(sig)
    ev = svc.config["EVENTS"][-1]
    assert ev["action"] == "HUMAN_APPROVED" and ev["actor"] == "qa.patel" and ev["resource"] == "asset:AST-000001"
    detail = json.loads(ev["detail"])
    assert detail["reason"] == "Gate G2 criteria met" and detail["esign"] == sig


@pytest.mark.parametrize("meaning,action", [("reviewed", "HUMAN_REVIEWED"), ("verified", "HUMAN_REVIEWED"),
                                            ("released", "HUMAN_APPROVED"), ("authored", "AUTO_LOG")])
def test_meaning_maps_to_audit_action(env, meaning, action):
    esign, users, svc = env
    esign.sign(users.principal(users.get("qa.patel")), meaning=meaning, reason="r", resource="batch:BCH-000001",
               password=PASSWORD)
    assert svc.config["EVENTS"][-1]["action"] == action
    assert meaning in MEANINGS


def test_wrong_password_fails_and_counts_toward_lockout(env):
    esign, users, svc = env
    p = users.principal(users.get("qa.patel"))
    kw = dict(meaning="approved", reason="r", resource="asset:AST-000001")
    for _ in range(2):
        with pytest.raises(InvalidCredentials):
            esign.sign(p, password="not-the-password", **kw)
    with pytest.raises(AccountLocked):
        esign.sign(p, password="not-the-password", **kw)
    assert not svc.config["EVENTS"]  # nothing signed


@pytest.mark.parametrize("kw,msg", [({"meaning": "signed"}, "meaning"), ({"reason": "  "}, "reason"),
                                    ({"resource": ""}, "resource")])
def test_incomplete_requests_refused(env, kw, msg):
    esign, users, _ = env
    args = dict(meaning="approved", reason="ok", resource="asset:AST-000001", password=PASSWORD) | kw
    with pytest.raises(ESignError, match=msg):
        esign.sign(users.principal(users.get("qa.patel")), **args)


def test_viewer_cannot_sign(env):
    esign, users, _ = env
    with pytest.raises(ESignError, match="not permitted"):
        esign.sign(users.principal(users.get("viewer.kim")), meaning="reviewed", reason="r",
                   resource="asset:AST-000001", password=PASSWORD)


def test_check_signature_rejects_extra_fields():
    with pytest.raises(ESignError):
        check_signature({"signer_id": "a", "meaning": "approved", "signed_at": "2026-11-06T10:00:00Z",
                         "reason": "not part of the contract"})


def test_esign_endpoint(client, login, audit_events):
    h = login("pd.lee")
    r = client.post("/auth/esign", headers=h, json={"password": PASSWORD, "meaning": "approved",
                                                     "reason": "Advance to IND-enabling",
                                                     "resource": "asset:AST-000001"})
    assert r.status_code == 201
    out = r.get_json()
    assert out["signature"]["signer_id"] == "pd.lee" and out["audit"]["delivered"]
    assert audit_events[-1]["action"] == "HUMAN_APPROVED" and audit_events[-1]["actor"] == "pd.lee"
    bad = client.post("/auth/esign", headers=h, json={"password": "wrong-wrong-wrong", "meaning": "approved",
                                                       "reason": "x", "resource": "asset:AST-000001"})
    assert bad.status_code == 401
    assert json.loads(audit_events[-1]["detail"])["event"] == "esign_reauth_failed"
    assert client.post("/auth/esign", headers=login("viewer.kim"),
                       json={"password": PASSWORD, "meaning": "reviewed", "reason": "x",
                             "resource": "asset:AST-000001"}).status_code == 403

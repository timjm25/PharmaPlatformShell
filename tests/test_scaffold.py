"""The drop-in scaffold files work inside a portfolio-agent style service."""
import importlib.util
import json
import logging
import sys
import types

import pytest
from flask import Flask, g, jsonify

from conftest import ROOT, SECRET
from fakes import fake_audittrail
from platform_shell.audit import AuditClient, verify_local_chain
from platform_shell.identity import Principal, scopes_for_roles
from platform_shell.tokens import TokenService
from platform_shell.transport import WSGITransport

SCAFFOLD = ROOT / "scaffold" / "app"


@pytest.fixture
def scaffold(monkeypatch, tmp_path):
    """Load scaffold/app/auth.py and audit_client.py as ``app.auth`` / ``app.audit_client`` with a
    stand-in ``app.config.settings`` shaped like portfolio-agent's Settings."""
    settings = types.SimpleNamespace(service_name="asset-registry", env="dev", auth_required=True, auth_issuer="",
                                     audit_platform_url="http://audit.test")
    pkg = types.ModuleType("app")
    pkg.__path__ = []
    config = types.ModuleType("app.config")
    config.settings = settings
    logcfg = types.ModuleType("app.logging_config")
    logcfg.get_logger = logging.getLogger
    for name, mod in {"app": pkg, "app.config": config, "app.logging_config": logcfg}.items():
        monkeypatch.setitem(sys.modules, name, mod)
    mods = {}
    for name in ("auth", "audit_client"):
        spec = importlib.util.spec_from_file_location(f"app.{name}", SCAFFOLD / f"{name}.py")
        mod = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, f"app.{name}", mod)
        spec.loader.exec_module(mod)
        mods[name] = mod
    monkeypatch.setenv("PLATFORM_SECRET", SECRET)
    monkeypatch.setenv("PLATFORM_AUDIT_SPOOL", str(tmp_path / "svc_spool.jsonl"))
    return types.SimpleNamespace(settings=settings, **mods)


def _tokens():
    return TokenService(SECRET, issuer="platform-shell", audience="pharma-platform")


def _p(roles=("cmc_lead",)):
    return Principal("cmc.ng", "Casey Ng", list(roles), scopes_for_roles(roles))


def test_verify_token_is_real_not_a_stub(scaffold):
    v = scaffold.auth.verify_token
    assert v("anything-non-empty") is None  # portfolio-agent's stub accepted this
    assert v(_tokens().issue(_p()))["sub"] == "cmc.ng"
    assertion = _tokens().issue_assertion(_p(), "asset-registry", "req-00000001")
    assert v(assertion)["request_id"] == "req-00000001"
    assert v(_tokens().issue_assertion(_p(), "asset-valuation", "req-00000001")) is None  # other service
    forged = TokenService("y" * 40, issuer="platform-shell", audience="pharma-platform").issue(_p(["admin"]))
    assert v(forged) is None


def test_require_user_and_require_scope(scaffold):
    app = Flask("svc")

    @app.post("/assets")
    @scaffold.auth.require_scope("registry:write")
    def create():
        return jsonify({"by": g.user["sub"]}), 201

    c = app.test_client()
    assert c.post("/assets").status_code == 401
    ok = c.post("/assets", headers={"X-Platform-Assertion":
                                    _tokens().issue_assertion(_p(), "asset-registry", "req-00000002")})
    assert ok.status_code == 201 and ok.get_json() == {"by": "cmc.ng"}
    viewer = _tokens().issue(_p(["viewer"]))
    assert c.post("/assets", headers={"Authorization": f"Bearer {viewer}"}).status_code == 403


def test_scaffold_audit_posts_form_fields_and_spools_compatibly(scaffold, tmp_path, monkeypatch):
    svc = fake_audittrail()
    transport = WSGITransport({"audit.test": svc})

    def fake_post(url, fields):
        from urllib.parse import urlencode
        from platform_shell.transport import UpstreamRequest
        r = transport(UpstreamRequest("POST", url, {"Content-Type": "application/x-www-form-urlencoded"},
                                      urlencode(fields).encode()))
        return r.status, r.text()

    monkeypatch.setattr(scaffold.audit_client, "_post", fake_post)
    app = Flask("svc")
    with app.test_request_context(headers={"X-Request-Id": "req-00000003"}):
        g.user = {"sub": "cmc.ng", "roles": ["cmc_lead"]}
        assert scaffold.audit_client.audit("approve", "Asset", "AST-000001", after={"stage": "phase1"},
                                           reason="gate G2") is True
    ev = svc.config["EVENTS"][-1]
    assert (ev["actor"], ev["action"], ev["resource"], ev["source_system"]) == \
        ("cmc.ng", "HUMAN_APPROVED", "asset:AST-000001", "asset-registry")
    assert json.loads(ev["detail"])["request_id"] == "req-00000003"
    assert svc.config["RAW"][-1]["json"] is None  # form, not JSON

    # Service down: spooled with the shared chain; platform-shell can verify and replay it.
    def down(url, fields):
        raise ConnectionError("refused")

    monkeypatch.setattr(scaffold.audit_client, "_post", down)
    with app.test_request_context():
        g.user = {"sub": "cmc.ng", "roles": ["cmc_lead"]}
        assert scaffold.audit_client.audit("update", "Batch", "BCH-000001") is False
        assert scaffold.audit_client.audit("update", "Batch", "BCH-000002") is False
    spool = tmp_path / "svc_spool.jsonl"
    assert verify_local_chain(spool)["valid"]
    replayer = AuditClient("http://audit.test", source_system="asset-registry", spool_path=spool, transport=transport)
    assert replayer.replay()["delivered"] == 2
    assert svc.config["EVENTS"][-1]["resource"] == "batch:BCH-000002"

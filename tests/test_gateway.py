import json

import pytest

from conftest import PASSWORD, SECRET
from fakes import echo_service
from platform_shell.config import ConfigError, ShellConfig
from platform_shell.gateway import create_app
from platform_shell.tokens import TokenService
from platform_shell.transport import WSGITransport


def seen(app, netloc):
    return app.config["UPSTREAMS"][netloc].config["SEEN"]


def test_login_me_and_failed_logins_audited(client, login, audit_events):
    h = login("pd.lee")
    me = client.get("/auth/me", headers=h).get_json()
    assert me["sub"] == "pd.lee" and "gates:sign" in me["scopes"] and me["auth_method"] == "password"
    assert client.post("/auth/token", json={"username": "pd.lee", "password": "nope"}).status_code == 401
    assert json.loads(audit_events[-1]["detail"])["event"] == "login_failed"
    assert audit_events[-1]["actor"] == "platform-shell"  # never attributed to the claimed user
    assert client.get("/auth/me").status_code == 401
    assert client.get("/auth/me", headers={"Authorization": "Bearer not.a.jwt"}).status_code == 401


def test_lockout_via_api(client):
    for _ in range(2):
        assert client.post("/auth/token", json={"username": "bd.ortiz", "password": "x" * 12}).status_code == 401
    assert client.post("/auth/token", json={"username": "bd.ortiz", "password": "x" * 12}).status_code == 423
    assert client.post("/auth/token", json={"username": "bd.ortiz", "password": PASSWORD}).status_code == 423


def test_form_login_also_works(client):
    r = client.post("/auth/token", data={"username": "viewer.kim", "password": PASSWORD})
    assert r.status_code == 200 and r.get_json()["token_type"] == "Bearer"


def test_rbac_read_allowed_write_denied_for_viewer(app, client, login, audit_events):
    h = login("viewer.kim")
    assert client.get("/gw/asset-registry/assets", headers=h).status_code == 200
    r = client.post("/gw/asset-registry/assets", json={"name": "EXAMPLE"}, headers=h)
    assert r.status_code == 403 and r.get_json()["required_scope"] == "registry:write"
    assert all(s["method"] == "GET" for s in seen(app, "localhost:5101"))  # never reached upstream
    denied = json.loads(audit_events[-1]["detail"])
    assert denied["event"] == "access_denied" and audit_events[-1]["actor"] == "viewer.kim"
    assert client.post("/gw/asset-registry/assets", json={"name": "EXAMPLE"},
                       headers=login("pd.lee")).status_code == 201


def test_partner_sees_only_the_data_room(client, login):
    h = login("partner.acme")
    assert client.get("/gw/asset-valuation/dataroom/AST-000001", headers=h).status_code == 200
    assert client.get("/gw/asset-valuation/valuations", headers=h).status_code == 403
    assert client.post("/gw/asset-valuation/dataroom/AST-000001", headers=h, json={}).status_code == 403
    assert client.get("/gw/asset-registry/assets", headers=h).status_code == 403
    assert client.post("/gw/asset-valuation/dataroom/AST-000001", headers=login("bd.ortiz"),
                       json={}).status_code == 201


def test_gate_decisions_need_signing_scope(client, login):
    assert client.post("/gw/program-director/gates/G2", json={}, headers=login("qa.patel")).status_code == 201
    assert client.post("/gw/program-director/gates/G2", json={}, headers=login("cmc.ng")).status_code == 403
    assert client.post("/gw/program-director/runs", json={}, headers=login("qa.patel")).status_code == 403


def test_identity_headers_injected_and_credentials_stripped(app, client, login, shell):
    h = login("cmc.ng")
    h.update({"Cookie": "session=abc", "X-Platform-User": "admin.ops", "X-Platform-Roles": "admin",
              "X-Request-Id": "trace-0001-abcd", "Accept": "application/json"})
    r = client.get("/gw/asset-registry/assets/AST-000001?include=lineage", headers=h)
    assert r.status_code == 200 and r.headers["X-Request-Id"] == "trace-0001-abcd"
    assert "Set-Cookie" not in r.headers  # upstream cookies are not passed to the browser
    got = seen(app, "localhost:5101")[-1]
    hdrs = {k.lower(): v for k, v in got["headers"].items()}
    assert "authorization" not in hdrs and "cookie" not in hdrs
    assert hdrs["x-platform-user"] == "cmc.ng" and hdrs["x-platform-roles"] == "cmc_lead"  # spoof overwritten
    assert hdrs["x-request-id"] == "trace-0001-abcd" and hdrs["accept"] == "application/json"
    assert got["path"] == "/assets/AST-000001" and got["query"] == {"include": "lineage"}
    claims = shell.tokens.verify(hdrs["x-platform-assertion"], audience="pharma-platform/asset-registry")
    assert claims["sub"] == "cmc.ng" and claims["request_id"] == "trace-0001-abcd"


def test_every_mutation_audited_with_real_user(app, client, login, audit_events):
    h = login("pd.lee")
    before = len(audit_events)
    client.get("/gw/asset-registry/assets", headers=h)
    assert len(audit_events) == before  # reads are not audited
    r = client.patch("/gw/asset-registry/assets/AST-000001", json={"stage": "phase1"}, headers=h)
    assert r.status_code == 200 and r.headers["X-Platform-Audit"] == "delivered"
    ev = audit_events[-1]
    assert ev["actor"] == "pd.lee" and ev["actor_type"] == "human" and ev["action"] == "AUTO_LOG"
    assert ev["resource"] == "asset:AST-000001" and ev["source_system"] == "platform-shell"
    d = json.loads(ev["detail"])
    assert d == {"method": "PATCH", "path": "/assets/AST-000001", "status": 200,
                 "request_id": r.headers["X-Request-Id"], "capability": "asset-registry"}
    # Asset id taken from the bus envelope when the path has none.
    client.post("/gw/pharma-event-bus/publish", headers=h,
                json={"message_type": "StageGateDecision", "correlation_id": "AST-000042", "payload": {}})
    assert audit_events[-1]["resource"] == "asset:AST-000042"


def test_audit_outage_never_blocks_the_call(cfg, upstreams):
    ups = {k: v for k, v in upstreams.items() if k != "localhost:5056"}
    app = create_app(cfg, transport=WSGITransport(ups))
    shell = app.extensions["platform_shell"]
    shell.users.create_user("pd.lee", "PD Lee", ["program_director"], PASSWORD)
    c = app.test_client()
    tok = c.post("/auth/token", json={"username": "pd.lee", "password": PASSWORD}).get_json()["access_token"]
    r = c.post("/gw/asset-registry/assets", json={}, headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 201 and r.headers["X-Platform-Audit"] == "spooled"
    spooled = shell.audit.spool.pending()[-1]
    assert spooled["actor"] == "pd.lee" and json.loads(spooled["detail"])["method"] == "POST"


def test_unknown_down_and_unreachable_services(app, client, login, shell, clock, audit_events):
    h = login("admin.ops")
    assert client.get("/gw/no-such-service/x", headers=h).status_code == 404
    assert client.get("/gw/platform-shell/healthz", headers=h).status_code == 503  # catalogue-only entry
    shell.registry.register({"capability": "ml-ops-monitoring", "base_url": "http://localhost:5999"})
    r = client.post("/gw/ml-ops-monitoring/alerts", json={}, headers=h)
    assert r.status_code == 502 and json.loads(audit_events[-1]["detail"])["status"] == 502
    shell.registry.clock = clock
    shell.registry.register({"capability": "ml-ops-monitoring", "base_url": "http://localhost:5999",
                             "ttl_seconds": 10})
    clock.advance(11)
    assert client.get("/gw/ml-ops-monitoring/alerts", headers=h).status_code == 503


def test_deactivation_and_role_change_take_effect_immediately(client, login, shell):
    h = login("cmc.ng")
    assert client.post("/gw/cgt-data-model/batches", json={}, headers=h).status_code == 201
    shell.users.set_roles("cmc.ng", ["viewer"])
    assert client.post("/gw/cgt-data-model/batches", json={}, headers=h).status_code == 403
    shell.users.set_active("cmc.ng", False)
    assert client.get("/gw/asset-registry/assets", headers=h).status_code == 401


def test_assertion_cannot_be_replayed_as_user_token(client, shell):
    from platform_shell.identity import Principal
    a = shell.tokens.issue_assertion(Principal("admin.ops", "A", ["admin"], ["admin"]), "asset-registry", "r" * 10)
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {a}"}).status_code == 401


def test_service_self_registration_and_heartbeat(client, login, audit_events):
    svc = login("svc.asset-registry")
    r = client.post("/services/register", headers=svc,
                    json={"capability": "asset-registry", "base_url": "http://localhost:5101", "ttl_seconds": 60})
    assert r.status_code == 201 and r.get_json()["runtime"]["source"] == "self_registered"
    assert audit_events[-1]["resource"] == "service:asset-registry"
    assert client.post("/services/asset-registry/heartbeat", headers=svc).get_json()["status"] == "up"
    # A service account cannot hijack another capability.
    assert client.post("/services/register", headers=svc,
                       json={"capability": "asset-valuation", "base_url": "http://evil:1"}).status_code == 403
    assert client.post("/services/asset-valuation/heartbeat", headers=svc).status_code == 403
    assert client.post("/services/register", headers=login("viewer.kim"), json={}).status_code == 403
    listing = client.get("/services?status=up", headers=login("viewer.kim")).get_json()
    assert [s["capability"] for s in listing["services"]] == ["asset-registry"]
    assert client.get("/services", headers=login("partner.acme")).status_code == 403


def test_health_check_endpoint(client, login):
    h = login("admin.ops")
    assert client.post("/services/asset-registry/check", headers=h).get_json()["status"] == "up"
    assert client.get("/services/cdmo-semantic-layer", headers=h).get_json()["capability"] == "cgt-data-model"


def test_rate_limit(cfg, upstreams):
    cfg.rate_limit_per_minute = 2
    app = create_app(cfg, transport=WSGITransport(upstreams))
    app.extensions["platform_shell"].users.create_user("viewer.kim", "V", ["viewer"], PASSWORD)
    c = app.test_client()
    tok = c.post("/auth/token", json={"username": "viewer.kim", "password": PASSWORD}).get_json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    codes = [c.get("/gw/asset-registry/assets", headers=h).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_prod_refuses_to_start_without_secret(tmp_path):
    with pytest.raises(ConfigError):
        create_app(ShellConfig(env="prod", secret=None, db_path=str(tmp_path / "u.db"), services_dir=None))


def test_healthz_and_openapi(client):
    assert client.get("/healthz").get_json()["status"] == "ok"
    assert "/gw/{capability}/{path}" in client.get("/openapi.json").get_json()["paths"]

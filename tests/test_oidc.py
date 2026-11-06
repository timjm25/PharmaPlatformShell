import time

import pytest

from conftest import SECRET
from entra import AUDIENCE, ISSUER, ROLE_MAP, TENANT, FakeEntra
from platform_shell.config import ConfigError
from platform_shell.gateway import create_app
from platform_shell.identity import Principal
from platform_shell.tokens import OIDCError, OIDCProvider, TokenService
from platform_shell.transport import WSGITransport


@pytest.fixture(scope="module")
def entra():
    return FakeEntra()


def _provider(entra, **kw):
    return OIDCProvider(issuer=ISSUER, audience=AUDIENCE, role_map=ROLE_MAP, jwks=entra.jwks, tenant_id=TENANT, **kw)


def test_rs256_token_maps_app_roles_and_groups(entra):
    p = _provider(entra).validate(entra.token(roles=["CMC.Lead"], groups=["aaaaaaaa-0000-0000-0000-00000000b0d0"]))
    assert p.auth_method == "oidc" and p.sub == "0a1b2c3d-0000-4000-8000-000000000001"  # Entra oid, not sub
    assert p.roles == ["cmc_lead", "bd"] and p.can("cgt:write") and p.can("dataroom:write")
    assert p.name == "Casey Ng"


@pytest.mark.parametrize("kwargs", [{"aud": "api://other"}, {"iss": "https://evil.example/v2.0"},
                                    {"ttl": -120}, {"tid": "99999999-0000-0000-0000-000000000000"}])
def test_bad_audience_issuer_expiry_or_tenant_rejected(entra, kwargs):
    with pytest.raises(OIDCError):
        _provider(entra).validate(entra.token(**kwargs))


def test_token_signed_by_unknown_key_rejected(entra):
    impostor = FakeEntra(kid=entra.kid)  # same kid, different key
    with pytest.raises(OIDCError):
        _provider(entra).validate(impostor.token())


def test_unmapped_roles_rejected_unless_default_role(entra):
    tok = entra.token(roles=["Some.Other.Role"])
    with pytest.raises(OIDCError, match="no platform role"):
        _provider(entra).validate(tok)
    assert _provider(entra, default_role="viewer").validate(tok).roles == ["viewer"]


def test_hs256_token_not_accepted_by_oidc(entra):
    hs = TokenService(SECRET, issuer=ISSUER, audience=AUDIENCE).issue(
        Principal(sub="x", name="x", roles=["admin"], scopes=["admin"]))
    with pytest.raises(OIDCError, match="not allowed"):
        _provider(entra).validate(hs)


def test_role_map_typos_fail_fast(entra):
    with pytest.raises(ValueError):
        OIDCProvider(issuer=ISSUER, audience=AUDIENCE, role_map={"X": "superuser"}, jwks=entra.jwks)
    with pytest.raises(ConfigError):
        OIDCProvider(issuer=ISSUER, audience=AUDIENCE, role_map={})


def test_gateway_accepts_entra_token_end_to_end(entra, cfg, upstreams):
    app = create_app(cfg, transport=WSGITransport(upstreams), oidc=_provider(entra))
    c = app.test_client()
    h = {"Authorization": "Bearer " + entra.token(roles=["CMC.Lead"])}
    me = c.get("/auth/me", headers=h).get_json()
    assert me["auth_method"] == "oidc" and me["roles"] == ["cmc_lead"]
    r = c.post("/gw/cgt-data-model/batches", json={"lot": "EXAMPLE-1"}, headers=h)
    assert r.status_code == 201
    seen = upstreams["localhost:5053"].config["SEEN"][-1]
    assert seen["headers"]["X-Platform-User"] == "0a1b2c3d-0000-4000-8000-000000000001"
    ev = upstreams["localhost:5056"].config["EVENTS"][-1]
    assert ev["actor"] == "0a1b2c3d-0000-4000-8000-000000000001"
    # Entra viewer-less role (qa) cannot write CGT data
    h2 = {"Authorization": "Bearer " + entra.token(oid="0a1b2c3d-0000-4000-8000-000000000002",
                                                   roles=["Quality.Assurance"])}
    assert c.post("/gw/cgt-data-model/batches", json={}, headers=h2).status_code == 403


def test_esign_for_entra_user_requires_fresh_reauth(entra, cfg, upstreams):
    app = create_app(cfg, transport=WSGITransport(upstreams), oidc=_provider(entra))
    c = app.test_client()
    h = {"Authorization": "Bearer " + entra.token(roles=["Quality.Assurance"])}
    base = {"meaning": "approved", "reason": "Batch record reviewed", "resource": "asset:AST-000001"}
    assert c.post("/auth/esign", json=base, headers=h).status_code == 400  # no reauth_token
    stale = entra.token(roles=["Quality.Assurance"], auth_time=time.time() - 3600)
    assert c.post("/auth/esign", json={**base, "reauth_token": stale}, headers=h).status_code == 400
    other = entra.token(oid="0a1b2c3d-0000-4000-8000-0000000000ff", roles=["Quality.Assurance"])
    assert c.post("/auth/esign", json={**base, "reauth_token": other}, headers=h).status_code == 400
    fresh = entra.token(roles=["Quality.Assurance"])
    r = c.post("/auth/esign", json={**base, "reauth_token": fresh}, headers=h)
    assert r.status_code == 201
    assert r.get_json()["signature"]["signer_id"] == "0a1b2c3d-0000-4000-8000-000000000001"

import logging

import jwt
import pytest

from conftest import SECRET, Clock
from platform_shell.config import ConfigError, ShellConfig
from platform_shell.identity import Principal, scopes_for_roles
from platform_shell.tokens import TokenError, TokenService, resolve_secret


def _principal(roles=("program_director",)):
    return Principal(sub="pd.lee", name="PD Lee", roles=list(roles), scopes=scopes_for_roles(roles))


def _svc(clock=None, **kw):
    return TokenService(SECRET, issuer="platform-shell", audience="pharma-platform", ttl_seconds=600,
                        clock=clock or Clock(), **kw)


def test_issue_and_verify_carries_required_claims():
    svc = _svc()
    claims = svc.verify(svc.issue(_principal()))
    for k in ("iss", "aud", "exp", "iat", "sub", "roles", "scopes", "jti"):
        assert k in claims
    assert claims["sub"] == "pd.lee" and claims["roles"] == ["program_director"]
    assert "gates:sign" in claims["scopes"] and claims["exp"] - claims["iat"] == 600
    assert jwt.get_unverified_header(svc.issue(_principal()))["alg"] == "HS256"


def test_expired_token_rejected():
    clock = Clock()
    svc = _svc(clock)
    token = svc.issue(_principal())
    clock.advance(601)
    with pytest.raises(TokenError, match="expired"):
        svc.verify(token)


def test_wrong_audience_issuer_or_secret_rejected():
    svc = _svc()
    with pytest.raises(TokenError):
        svc.verify(svc.issue(_principal(), audience="some-other-app"))
    other_iss = TokenService(SECRET, issuer="evil", audience="pharma-platform", clock=Clock())
    with pytest.raises(TokenError):
        svc.verify(other_iss.issue(_principal()))
    other_key = TokenService("x" * 40, issuer="platform-shell", audience="pharma-platform", clock=Clock())
    with pytest.raises(TokenError):
        svc.verify(other_key.issue(_principal()))
    with pytest.raises(TokenError):
        svc.verify("")


def test_assertion_is_scoped_to_one_capability():
    svc = _svc()
    a = svc.issue_assertion(_principal(), "asset-registry", "req-12345678")
    claims = svc.verify(a, audience="pharma-platform/asset-registry")
    assert claims["typ"] == "assertion" and claims["exp"] - claims["iat"] == 60
    with pytest.raises(TokenError):
        svc.verify(a)  # not a user token
    with pytest.raises(TokenError):
        svc.verify(a, audience="pharma-platform/asset-valuation")


def test_secret_rules_by_environment(caplog):
    with pytest.raises(ConfigError, match="required"):
        resolve_secret(ShellConfig(env="prod", secret=None))
    with pytest.raises(ConfigError, match="at least"):
        resolve_secret(ShellConfig(env="prod", secret="short"))
    with caplog.at_level(logging.WARNING):
        s1 = resolve_secret(ShellConfig(env="dev", secret=None))
        s2 = resolve_secret(ShellConfig(env="dev", secret=None))
    assert s1 != s2 and len(s1) >= 32
    assert "ephemeral" in caplog.text


def test_config_from_env(monkeypatch, tmp_path):
    rm = tmp_path / "map.yaml"
    rm.write_text("role_map:\n  CMC.Lead: cmc_lead\n  G1: [qa, viewer]\n")
    cfg = ShellConfig.from_env({"PLATFORM_ENV": "staging", "PLATFORM_SECRET": SECRET, "PLATFORM_TOKEN_TTL": "60",
                                "PLATFORM_OIDC_ROLE_MAP": str(rm)})
    assert cfg.env == "staging" and cfg.token_ttl_seconds == 60
    assert cfg.oidc_role_map == {"CMC.Lead": ["cmc_lead"], "G1": ["qa", "viewer"]}
    with pytest.raises(ConfigError):
        ShellConfig.from_env({"PLATFORM_ENV": "production"})

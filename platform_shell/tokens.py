"""Platform access tokens (HS256 JWT) and Azure Entra ID / OIDC token validation (RS256).

Two token families:

* **Platform tokens** are issued by the shell after a password login and signed
  with ``PLATFORM_SECRET`` (HS256). Claims: iss, aud, exp, iat, nbf, jti, sub,
  name, roles, scopes, amr.
* **Gateway assertions** are 60-second platform tokens the gateway mints per
  proxied request, with ``aud = "<audience>/<capability>"``, so an upstream can
  trust the identity headers without ever seeing the user's own token.

:class:`OIDCProvider` validates RS256 tokens from an external IdP (Entra ID)
against a JWKS and maps app roles / group ids to platform roles.
"""
from __future__ import annotations

import logging
import secrets
import time
import uuid
from typing import Any, Callable, Iterable, Mapping

import jwt

from .config import ConfigError, ShellConfig
from .identity import Principal, ROLE_SCOPES, scopes_for_roles

log = logging.getLogger(__name__)

MIN_SECRET_LENGTH = 32


class TokenError(Exception):
    """Token missing, malformed, expired, wrongly signed or for another audience."""


def resolve_secret(config: ShellConfig) -> str:
    """Return the HS256 signing secret, enforcing the environment rules.

    prod/staging: ``PLATFORM_SECRET`` is required and must be >= 32 characters.
    dev/test: if unset, an ephemeral random secret is generated (tokens die with
    the process) and a warning is logged.
    """
    if config.secret:
        if len(config.secret) < MIN_SECRET_LENGTH and config.env in ("prod", "staging"):
            raise ConfigError(f"PLATFORM_SECRET must be at least {MIN_SECRET_LENGTH} characters in {config.env}")
        return config.secret
    if config.env in ("prod", "staging"):
        raise ConfigError(f"PLATFORM_SECRET is required when PLATFORM_ENV={config.env}; refusing to start")
    log.warning("PLATFORM_SECRET not set: generated an ephemeral dev secret. Tokens will not survive a restart.")
    return secrets.token_urlsafe(48)


class TokenService:
    """Issue and verify HS256 platform tokens."""

    algorithm = "HS256"

    def __init__(self, secret: str, *, issuer: str, audience: str, ttl_seconds: int = 1800,
                 assertion_ttl_seconds: int = 60, clock: Callable[[], float] = time.time) -> None:
        if not secret:
            raise ConfigError("TokenService needs a secret")
        self._secret = secret
        self.issuer = issuer
        self.audience = audience
        self.ttl_seconds = ttl_seconds
        self.assertion_ttl_seconds = assertion_ttl_seconds
        self.clock = clock

    @classmethod
    def from_config(cls, config: ShellConfig) -> "TokenService":
        return cls(resolve_secret(config), issuer=config.issuer, audience=config.audience,
                   ttl_seconds=config.token_ttl_seconds, assertion_ttl_seconds=config.assertion_ttl_seconds)

    def issue(self, principal: Principal, *, ttl_seconds: int | None = None, audience: str | None = None,
              extra: Mapping[str, Any] | None = None) -> str:
        now = int(self.clock())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "aud": audience or self.audience,
            "iat": now,
            "nbf": now,
            "exp": now + (ttl_seconds if ttl_seconds is not None else self.ttl_seconds),
            "jti": str(uuid.uuid4()),
            "sub": principal.sub,
            "name": principal.name,
            "roles": list(principal.roles),
            "scopes": list(principal.scopes),
            "amr": ["pwd"] if principal.auth_method == "password" else [principal.auth_method],
        }
        if extra:
            claims.update(extra)
        return jwt.encode(claims, self._secret, algorithm=self.algorithm)

    def issue_assertion(self, principal: Principal, capability: str, request_id: str) -> str:
        """Short-lived token for one proxied request to ``capability``."""
        return self.issue(principal, ttl_seconds=self.assertion_ttl_seconds,
                          audience=f"{self.audience}/{capability}",
                          extra={"typ": "assertion", "request_id": request_id})

    def verify(self, token: str, *, audience: str | None = None) -> dict[str, Any]:
        """Return claims for a valid token or raise :class:`TokenError`."""
        if not token:
            raise TokenError("missing token")
        try:
            return self._decode_with_clock(token, audience or self.audience)
        except jwt.PyJWTError as e:
            raise TokenError(str(e)) from e

    def _decode_with_clock(self, token: str, audience: str) -> dict[str, Any]:
        # PyJWT verifies signature, iss and aud; exp/nbf are checked against
        # self.clock so expiry is testable without sleeping.
        claims = jwt.decode(token, self._secret, algorithms=[self.algorithm], audience=audience,
                            issuer=self.issuer,
                            options={"require": ["exp", "iat", "iss", "aud", "sub"], "verify_exp": False,
                                     "verify_nbf": False, "verify_iat": False})
        now = self.clock()
        if now >= claims["exp"]:
            raise jwt.ExpiredSignatureError("Signature has expired")
        if "nbf" in claims and now < claims["nbf"]:
            raise jwt.ImmatureSignatureError("The token is not yet valid (nbf)")
        return claims

    @staticmethod
    def principal_from_claims(claims: Mapping[str, Any]) -> Principal:
        roles = [r for r in claims.get("roles", []) if r in ROLE_SCOPES]
        return Principal(sub=claims["sub"], name=claims.get("name", claims["sub"]), roles=roles,
                         scopes=list(claims.get("scopes", scopes_for_roles(roles))),
                         auth_method="password" if "pwd" in claims.get("amr", []) else "token",
                         claims=dict(claims))


class OIDCError(TokenError):
    """An external IdP token failed validation or mapped to no platform role."""


class OIDCProvider:
    """Validate RS256 tokens from Azure Entra ID (or any OIDC IdP) against a JWKS.

    Supply either ``jwks`` (a JWKS dict, e.g. cached or for tests) or ``jwks_uri``
    (fetched with PyJWT's ``PyJWKClient``, e.g.
    ``https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys``).

    ``role_map`` maps the values found in the token's ``roles`` claim (Entra app
    roles) and ``groups`` claim (group object ids) to platform roles.
    """

    def __init__(self, *, issuer: str, audience: str, role_map: Mapping[str, Iterable[str] | str],
                 jwks: Mapping[str, Any] | None = None, jwks_uri: str | None = None,
                 tenant_id: str | None = None, default_role: str | None = None,
                 algorithms: Iterable[str] = ("RS256",), leeway: int = 60,
                 role_claims: Iterable[str] = ("roles", "groups")) -> None:
        if not jwks and not jwks_uri:
            raise ConfigError("OIDCProvider needs jwks or jwks_uri")
        self.issuer = issuer
        self.audience = audience
        self.tenant_id = tenant_id
        self.algorithms = list(algorithms)
        self.leeway = leeway
        self.role_claims = tuple(role_claims)
        self.default_role = default_role
        self.role_map: dict[str, list[str]] = {}
        for k, v in role_map.items():
            roles = [v] if isinstance(v, str) else list(v)
            scopes_for_roles(roles)  # fail fast on typos in config
            self.role_map[str(k)] = roles
        if default_role:
            scopes_for_roles([default_role])
        self._jwk_set = jwt.PyJWKSet.from_dict(dict(jwks)) if jwks else None
        self._jwk_client = jwt.PyJWKClient(jwks_uri) if (jwks_uri and not jwks) else None

    @classmethod
    def from_config(cls, config: ShellConfig) -> "OIDCProvider | None":
        if not (config.oidc_issuer and config.oidc_audience and config.oidc_jwks_url):
            return None
        return cls(issuer=config.oidc_issuer, audience=config.oidc_audience, role_map=config.oidc_role_map,
                   jwks_uri=config.oidc_jwks_url, tenant_id=config.oidc_tenant_id,
                   default_role=config.oidc_default_role)

    def _signing_key(self, token: str) -> Any:
        if self._jwk_client is not None:
            return self._jwk_client.get_signing_key_from_jwt(token).key
        kid = jwt.get_unverified_header(token).get("kid")
        assert self._jwk_set is not None
        for k in self._jwk_set.keys:
            if kid is None or k.key_id == kid:
                return k.key
        raise OIDCError(f"no JWKS key matches kid {kid!r}")

    def decode(self, token: str) -> dict[str, Any]:
        """Verify signature, iss, aud, exp (and tid when configured); return raw claims."""
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") not in self.algorithms:
                raise OIDCError(f"algorithm {header.get('alg')!r} not allowed")
            claims = jwt.decode(token, self._signing_key(token), algorithms=self.algorithms,
                                audience=self.audience, issuer=self.issuer, leeway=self.leeway,
                                options={"require": ["exp", "iat", "iss", "aud"]})
        except jwt.PyJWTError as e:
            raise OIDCError(str(e)) from e
        if self.tenant_id and claims.get("tid") != self.tenant_id:
            raise OIDCError("token tenant does not match configured tenant")
        return claims

    def map_roles(self, claims: Mapping[str, Any]) -> list[str]:
        roles: list[str] = []
        for claim in self.role_claims:
            values = claims.get(claim) or []
            if isinstance(values, str):
                values = [values]
            for v in values:
                roles.extend(self.role_map.get(str(v), []))
        if not roles and self.default_role:
            roles = [self.default_role]
        return list(dict.fromkeys(roles))

    def validate(self, token: str) -> Principal:
        """Validate ``token`` and return a platform :class:`Principal`.

        Raises :class:`OIDCError` if the token is invalid or maps to no role.
        The subject is Entra's immutable ``oid`` when present, else ``sub``.
        """
        claims = self.decode(token)
        roles = self.map_roles(claims)
        if not roles:
            raise OIDCError("token maps to no platform role; check the role map")
        sub = str(claims.get("oid") or claims.get("sub") or "")
        if not sub:
            raise OIDCError("token has neither oid nor sub")
        name = str(claims.get("name") or claims.get("preferred_username") or sub)
        return Principal(sub=sub, name=name, roles=roles, scopes=scopes_for_roles(roles), auth_method="oidc",
                         claims=dict(claims))

"""Bearer-token auth guard for any platform service. Drop-in replacement for
portfolio-agent ``scaffold/app/auth.py`` (whose ``verify_token`` is a stub that
accepts any non-empty string). Source: timjm25/PharmaPlatformShell scaffold/app/auth.py.

What it accepts, in order:
1. ``X-Platform-Assertion``: the 60-second token PharmaPlatformShell's gateway
   mints for each proxied request (HS256, ``aud = "<audience>/<service_name>"``).
2. ``Authorization: Bearer <platform token>``: an HS256 token from ``POST /auth/token``.
3. ``Authorization: Bearer <Entra ID token>``: RS256, checked against a JWKS URL.

Settings: read from ``app.config.settings`` when the attribute exists, else from env:
  PLATFORM_SECRET     shared HS256 secret (same value as the gateway's)
  PLATFORM_ISSUER     default "platform-shell"
  PLATFORM_AUDIENCE   default "pharma-platform"
  PLATFORM_JWKS_URL, PLATFORM_OIDC_ISSUER, PLATFORM_OIDC_AUDIENCE   optional Entra validation
Requires PyJWT (``pip install "pyjwt[crypto]"``).
"""
from __future__ import annotations

import os
from functools import wraps
from typing import Any, Callable

import jwt
from flask import g, jsonify, request

from app.config import settings

_jwks_client: Any = None


def _setting(attr: str, env: str, default: str | None = None) -> str | None:
    return getattr(settings, attr, None) or os.environ.get(env) or default


def _jwks() -> Any:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = jwt.PyJWKClient(_setting("jwks_url", "PLATFORM_JWKS_URL"))
    return _jwks_client


def verify_token(token: str) -> dict[str, Any] | None:
    """Return a claims dict ``{sub, name, roles, scopes, request_id, claims}`` for a valid token, else None.

    Validates signature, exp, iss and aud. Never raises.
    """
    if not token:
        return None
    try:
        alg = jwt.get_unverified_header(token).get("alg")
    except jwt.PyJWTError:
        return None
    required = {"require": ["exp", "iat", "iss", "aud", "sub"]}
    try:
        if alg == "HS256":
            secret = _setting("platform_secret", "PLATFORM_SECRET")
            if not secret:
                return None
            audience = _setting("auth_audience", "PLATFORM_AUDIENCE", "pharma-platform")
            claims = jwt.decode(token, secret, algorithms=["HS256"],
                                audience=[audience, f"{audience}/{settings.service_name}"],
                                issuer=_setting("auth_issuer", "PLATFORM_ISSUER", "platform-shell"),
                                options=required)
        elif alg == "RS256" and _setting("jwks_url", "PLATFORM_JWKS_URL"):
            key = _jwks().get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, key, algorithms=["RS256"],
                                audience=_setting("oidc_audience", "PLATFORM_OIDC_AUDIENCE"),
                                issuer=_setting("oidc_issuer", "PLATFORM_OIDC_ISSUER"),
                                options={"require": ["exp", "iat", "iss", "aud"]})
        else:
            return None
    except Exception:  # noqa: BLE001 - any validation or JWKS failure means "not authenticated"
        return None
    sub = claims.get("oid") or claims.get("sub")
    if not sub:
        return None
    return {"sub": str(sub), "name": claims.get("name", sub), "roles": list(claims.get("roles", [])),
            "scopes": list(claims.get("scopes", [])), "request_id": claims.get("request_id"), "claims": claims}


def _token_from_request() -> str:
    assertion = request.headers.get("X-Platform-Assertion", "")
    if assertion:
        return assertion
    header = request.headers.get("Authorization", "")
    return header[7:].strip() if header.startswith("Bearer ") else ""


def require_user(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Reject the request with 401 unless it carries a valid platform identity; sets ``g.user``."""
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not settings.auth_required:
            if getattr(settings, "env", "dev") == "prod":
                return jsonify({"error": "auth cannot be disabled in prod"}), 500
            g.user = {"sub": "auth-disabled", "roles": ["dev"], "scopes": []}
            return fn(*args, **kwargs)
        claims = verify_token(_token_from_request())
        if claims is None:
            return jsonify({"error": "unauthorized"}), 401
        g.user = claims  # available to the route and the audit client
        return fn(*args, **kwargs)

    return wrapper


def require_scope(scope: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Like ``require_user`` and additionally 403 unless ``scope`` (or ``admin``) is granted."""
    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        @require_user
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            scopes = set(g.user.get("scopes", []))
            if settings.auth_required and "admin" not in scopes and scope not in scopes:
                return jsonify({"error": "forbidden", "required_scope": scope}), 403
            return fn(*args, **kwargs)
        return wrapper
    return deco

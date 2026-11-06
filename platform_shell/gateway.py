"""The platform gateway (default port 5100): login, e-signature, service registry and proxy.

Every request to a platform service goes through ``/gw/<capability>/<path>``. The
gateway authenticates the bearer token (platform HS256 or Entra RS256), checks
the scope the target service requires for that method and path, forwards the call
with the caller's identity in ``X-Platform-*`` headers (the user's own
``Authorization`` header is never forwarded) and writes every mutation to
AuditTrailService attributed to the real user.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jwt
from flask import Flask, Response, g, jsonify, request

from . import DEFAULT_PORT, __version__
from .audit import AuditClient
from .config import ShellConfig
from .esign import ESignError, ESignService
from .identity import AccountLocked, InvalidCredentials, Principal, UserStore
from .service_registry import READ_METHODS, RegistryError, ServiceRegistry
from .tokens import OIDCError, OIDCProvider, TokenError, TokenService
from .transport import Transport, TransportError, UpstreamRequest, UrllibTransport, filter_headers

log = logging.getLogger(__name__)

PROXY_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
ASSET_RE = re.compile(r"AST-\d{6}")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
# Never forwarded upstream: credentials, and anything a client could use to spoof identity.
STRIP_REQUEST_HEADERS = {"authorization", "cookie", "x-request-id", "x-forwarded-for", "x-forwarded-prefix",
                         "x-forwarded-host", "x-forwarded-proto"}


class TokenBucket:
    """Per-user token bucket: ``rate_per_minute`` requests, refilled continuously."""

    def __init__(self, rate_per_minute: int, clock: Any = time.monotonic) -> None:
        self.capacity = float(rate_per_minute)
        self.rate = rate_per_minute / 60.0
        self.clock = clock
        self._state: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self.clock()
        with self._lock:
            tokens, last = self._state.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            ok = tokens >= 1.0
            self._state[key] = (tokens - 1.0 if ok else tokens, now)
        return ok


@dataclass
class Shell:
    """Everything the gateway needs, held on ``app.extensions["platform_shell"]``."""

    config: ShellConfig
    users: UserStore
    tokens: TokenService
    registry: ServiceRegistry
    audit: AuditClient
    esign: ESignService
    transport: Transport
    oidc: OIDCProvider | None = None
    limiter: TokenBucket | None = None
    extras: dict[str, Any] = field(default_factory=dict)


def _err(status: int, error: str, **extra: Any) -> Response:
    body = {"error": error, **extra}
    rid = getattr(g, "request_id", None)
    if rid:
        body["request_id"] = rid
    resp = jsonify(body)
    resp.status_code = status
    return resp


def _resource_for(capability: str, rest: str, body: bytes) -> str:
    """AuditTrailService resource: ``asset:AST-xxxxxx`` when the call is asset-scoped, else ``service:<cap>``."""
    m = ASSET_RE.search(rest)
    if not m and body:
        try:
            data = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            data = None
        if isinstance(data, dict):
            payload = data.get("payload") if isinstance(data.get("payload"), dict) else {}
            for v in (data.get("asset_id"), data.get("correlation_id"), payload.get("asset_id")):
                if isinstance(v, str) and ASSET_RE.fullmatch(v):
                    return f"asset:{v}"
    return f"asset:{m.group(0)}" if m else f"service:{capability}"


def build_shell(config: ShellConfig, *, users: UserStore | None = None, tokens: TokenService | None = None,
                registry: ServiceRegistry | None = None, audit: AuditClient | None = None,
                transport: Transport | None = None, oidc: OIDCProvider | None = None,
                audit_transport: Transport | None = None) -> Shell:
    """Wire the shell's components from config, letting tests inject any of them."""
    transport = transport or UrllibTransport()
    users = users or UserStore(config.db_path, lockout_threshold=config.lockout_threshold,
                               lockout_minutes=config.lockout_minutes,
                               min_password_length=config.min_password_length)
    tokens = tokens or TokenService.from_config(config)
    if registry is None:
        registry = ServiceRegistry(default_ttl_seconds=config.heartbeat_ttl_seconds)
        if config.services_dir and Path(config.services_dir).is_dir():
            registry.load_dir(config.services_dir)
    oidc = oidc or OIDCProvider.from_config(config)
    audit = audit or AuditClient(config.audit_url, source_system=config.source_system,
                                 spool_path=config.audit_spool_path, transport=audit_transport or transport)
    esign = ESignService(users, audit, oidc=oidc, reauth_max_age_seconds=config.esign_reauth_max_age_seconds)
    limiter = TokenBucket(config.rate_limit_per_minute) if config.rate_limit_per_minute > 0 else None
    return Shell(config=config, users=users, tokens=tokens, registry=registry, audit=audit, esign=esign,
                 transport=transport, oidc=oidc, limiter=limiter)


def create_app(config: ShellConfig | None = None, **components: Any) -> Flask:
    """Flask app factory. ``components`` are passed to :func:`build_shell` (users, tokens, registry,
    audit, transport, audit_transport, oidc)."""
    config = config or ShellConfig.from_env()
    shell = build_shell(config, **components)
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024
    app.extensions["platform_shell"] = shell

    # -- helpers -----------------------------------------------------------
    @app.before_request
    def _request_id() -> None:
        incoming = request.headers.get("X-Request-Id", "")
        g.request_id = incoming if REQUEST_ID_RE.match(incoming) else str(uuid.uuid4())

    @app.after_request
    def _stamp(resp: Response) -> Response:
        resp.headers["X-Request-Id"] = g.get("request_id", "")
        return resp

    def authenticate() -> Principal | Response:
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return _err(401, "missing bearer token")
        token = header[7:].strip()
        try:
            alg = jwt.get_unverified_header(token).get("alg")
        except jwt.PyJWTError:
            return _err(401, "malformed token")
        try:
            if alg == TokenService.algorithm:
                claims = shell.tokens.verify(token)
                if claims.get("typ") == "assertion":
                    return _err(401, "gateway assertions are not accepted as user tokens")
                user = shell.users.get(claims["sub"])
                if user is None or not user.active or shell.users.is_locked(user):
                    return _err(401, "account is inactive or locked")
                principal = shell.users.principal(user)  # current roles, so revocation is immediate
                principal.claims = claims
                return principal
            if shell.oidc is not None and alg in shell.oidc.algorithms:
                return shell.oidc.validate(token)
        except (TokenError, OIDCError) as e:
            return _err(401, "invalid token", detail=str(e))
        return _err(401, f"unsupported token algorithm {alg!r}")

    def require(scope: str | None = None) -> Principal | Response:
        p = authenticate()
        if isinstance(p, Response):
            return p
        if scope and not p.can(scope):
            return _err(403, "forbidden", required_scope=scope)
        g.principal = p
        return p

    def body_json() -> dict[str, Any]:
        if request.is_json:
            data = request.get_json(silent=True)
            return data if isinstance(data, dict) else {}
        return {k: v for k, v in request.form.items()}

    # -- health & contract -------------------------------------------------
    @app.get("/healthz")
    def healthz() -> Any:
        return jsonify({"status": "ok", "service": "platform-shell", "version": __version__,
                        "env": config.env, "port": DEFAULT_PORT})

    @app.get("/openapi.json")
    def openapi() -> Any:
        return jsonify(OPENAPI)

    # -- identity ------------------------------------------------------------
    @app.post("/auth/token")
    def auth_token() -> Any:
        data = body_json()
        user_id = str(data.get("username") or data.get("user_id") or "")
        password = str(data.get("password") or "")
        try:
            user = shell.users.authenticate(user_id, password)
        except AccountLocked as e:
            shell.audit.log(actor=config.source_system, actor_type="automated_process", action="AUTO_LOG",
                            resource=f"user:{e.user_id}",
                            detail={"event": "login_refused_locked", "request_id": g.request_id,
                                    "remote_addr": request.remote_addr})
            return _err(423, "account locked", locked_until=e.locked_until)
        except InvalidCredentials:
            shell.audit.log(actor=config.source_system, actor_type="automated_process", action="AUTO_LOG",
                            resource="user:" + (user_id[:128] or "unknown"),
                            detail={"event": "login_failed", "request_id": g.request_id,
                                    "remote_addr": request.remote_addr})
            return _err(401, "invalid credentials")
        principal = shell.users.principal(user)
        token = shell.tokens.issue(principal)
        shell.audit.log(actor=user.user_id, actor_type=principal.actor_type, action="AUTO_LOG",
                        resource=f"user:{user.user_id}", detail={"event": "login", "request_id": g.request_id})
        return jsonify({"access_token": token, "token_type": "Bearer", "expires_in": shell.tokens.ttl_seconds,
                        "roles": principal.roles, "scopes": principal.scopes})

    @app.get("/auth/me")
    def auth_me() -> Any:
        p = require()
        if isinstance(p, Response):
            return p
        return jsonify({"sub": p.sub, "name": p.name, "roles": p.roles, "scopes": p.scopes,
                        "auth_method": p.auth_method, "exp": p.claims.get("exp")})

    @app.post("/auth/esign")
    def auth_esign() -> Any:
        p = require()
        if isinstance(p, Response):
            return p
        data = body_json()
        rel = data.get("related_event_id")
        try:
            result = shell.esign.sign(
                p, meaning=str(data.get("meaning", "")), reason=str(data.get("reason", "")),
                resource=str(data.get("resource", "")), password=data.get("password"),
                reauth_token=data.get("reauth_token"),
                related_event_id=int(rel) if rel not in (None, "") else None,
            )
        except (AccountLocked, InvalidCredentials) as e:
            # 11.300(d): failed signing attempts are recorded, not just refused.
            shell.audit.log(actor=p.sub, actor_type=p.actor_type, action="AUTO_LOG",
                            resource=str(data.get("resource") or f"user:{p.sub}"),
                            detail={"event": "esign_reauth_failed", "request_id": g.request_id,
                                    "locked": isinstance(e, AccountLocked)})
            if isinstance(e, AccountLocked):
                return _err(423, "account locked", locked_until=e.locked_until)
            return _err(401, "re-authentication failed")
        except (ESignError, ValueError) as e:
            status = 403 if "not permitted" in str(e) else 400
            return _err(status, str(e))
        return jsonify(result.to_dict()), 201

    # -- registry ------------------------------------------------------------
    def _may_manage(p: Principal, capability: str) -> bool:
        return p.can("admin") or p.sub in (capability, f"svc.{capability}")

    @app.get("/services")
    def services() -> Any:
        p = require("services:read")
        if isinstance(p, Response):
            return p
        now = shell.registry.clock()
        items = [d.to_dict(now) for d in shell.registry.list()]
        want = request.args.get("status")
        if want:
            items = [i for i in items if i["runtime"]["status"] == want]
        return jsonify({"services": items, "count": len(items)})

    @app.get("/services/<capability>")
    def service_one(capability: str) -> Any:
        p = require("services:read")
        if isinstance(p, Response):
            return p
        d = shell.registry.get(capability)
        return jsonify(d.to_dict(shell.registry.clock())) if d else _err(404, "unknown capability")

    @app.post("/services/register")
    def services_register() -> Any:
        p = require("services:write")
        if isinstance(p, Response):
            return p
        data = request.get_json(silent=True) or {}
        cap = str(data.get("capability", ""))
        if not _may_manage(p, cap):
            return _err(403, "a service account may only register its own capability")
        try:
            d = shell.registry.register(data)
        except RegistryError as e:
            return _err(400, str(e))
        receipt = shell.audit.log(actor=p.sub, actor_type=p.actor_type, action="AUTO_LOG",
                                  resource=f"service:{d.capability}",
                                  detail={"event": "service_registered", "base_url": d.base_url,
                                          "request_id": g.request_id})
        resp = jsonify(d.to_dict(shell.registry.clock()))
        resp.status_code = 201
        resp.headers["X-Platform-Audit"] = "delivered" if receipt.delivered else "spooled"
        return resp

    @app.post("/services/<capability>/heartbeat")
    def services_heartbeat(capability: str) -> Any:
        p = require("services:write")
        if isinstance(p, Response):
            return p
        if not _may_manage(p, capability):
            return _err(403, "a service account may only heartbeat its own capability")
        try:
            d = shell.registry.heartbeat(capability)
        except RegistryError as e:
            return _err(404, str(e))
        return jsonify({"capability": d.capability, "status": d.effective_status(shell.registry.clock()),
                        "ttl_seconds": d.ttl_seconds})

    @app.post("/services/<capability>/check")
    def services_check(capability: str) -> Any:
        p = require("services:write")
        if isinstance(p, Response):
            return p
        try:
            status = shell.registry.check_health(capability, shell.transport)
        except RegistryError as e:
            return _err(404, str(e))
        return jsonify({"capability": capability, "status": status,
                        "last_error": shell.registry.require(capability).last_error})

    # -- proxy ---------------------------------------------------------------
    def proxy(capability: str, rest: str) -> Any:
        p = authenticate()
        if isinstance(p, Response):
            return p
        g.principal = p
        desc = shell.registry.get(capability)
        if desc is None:
            return _err(404, "unknown capability", capability=capability)
        if not desc.routable:
            return _err(503, "capability has no routable endpoint", capability=desc.capability)
        if desc.effective_status(shell.registry.clock()) == "down":
            return _err(503, "service is down", capability=desc.capability, last_error=desc.last_error)
        method = request.method.upper()
        body = request.get_data()
        scope = desc.scope_for(method, rest)
        if not p.can(scope):
            shell.audit.log(actor=p.sub, actor_type=p.actor_type, action="AUTO_LOG",
                            resource=_resource_for(desc.capability, rest, body),
                            detail={"event": "access_denied", "method": method, "path": "/" + rest,
                                    "required_scope": scope, "request_id": g.request_id,
                                    "capability": desc.capability})
            return _err(403, "forbidden", required_scope=scope)
        if shell.limiter is not None and not shell.limiter.allow(p.sub):
            return _err(429, "rate limit exceeded")

        headers = filter_headers(dict(request.headers.items()), drop=STRIP_REQUEST_HEADERS)
        headers = {k: v for k, v in headers.items() if not k.lower().startswith("x-platform-")}
        headers.update({
            "X-Platform-User": p.sub,
            "X-Platform-Roles": ",".join(p.roles),
            "X-Platform-Assertion": shell.tokens.issue_assertion(p, desc.capability, g.request_id),
            "X-Request-Id": g.request_id,
            "X-Forwarded-For": request.remote_addr or "",
            "X-Forwarded-Prefix": f"/gw/{capability}",
        })
        url = f"{desc.base_url}/{rest}"
        if request.query_string:
            url += "?" + request.query_string.decode("latin-1")
        try:
            up = shell.transport(UpstreamRequest(method, url, headers, body,
                                                 timeout=config.upstream_timeout_seconds))
            status, resp_body, resp_headers = up.status, up.body, up.headers
        except TransportError as e:
            status, resp_body, resp_headers = 502, json.dumps(
                {"error": "upstream unreachable", "detail": str(e), "request_id": g.request_id}).encode(), \
                {"Content-Type": "application/json"}

        audit_state = None
        if method not in READ_METHODS:
            receipt = shell.audit.log(
                actor=p.sub, actor_type=p.actor_type, action="AUTO_LOG",
                resource=_resource_for(desc.capability, rest, body),
                detail={"method": method, "path": "/" + rest, "status": status, "request_id": g.request_id,
                        "capability": desc.capability},
            )
            audit_state = "delivered" if receipt.delivered else ("spooled" if receipt.spooled else "failed")

        out = Response(resp_body, status=status)
        for k, v in filter_headers(resp_headers, drop={"set-cookie"}).items():
            out.headers[k] = v
        if audit_state:
            out.headers["X-Platform-Audit"] = audit_state
        return out

    app.add_url_rule("/gw/<capability>/", "proxy_root", proxy, defaults={"rest": ""},
                     methods=PROXY_METHODS, provide_automatic_options=False)
    app.add_url_rule("/gw/<capability>/<path:rest>", "proxy", proxy, methods=PROXY_METHODS,
                     provide_automatic_options=False)
    return app


OPENAPI: dict[str, Any] = {
    "openapi": "3.1.0",
    "info": {"title": "PharmaPlatformShell gateway", "version": __version__},
    "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}}},
    "security": [{"bearer": []}],
    "paths": {
        "/healthz": {"get": {"summary": "Liveness", "security": []}},
        "/auth/token": {"post": {"summary": "Password login; returns an HS256 platform token", "security": []}},
        "/auth/me": {"get": {"summary": "The authenticated principal"}},
        "/auth/esign": {"post": {"summary": "Part 11 e-signature; returns a Common 1.0.0 signature"}},
        "/services": {"get": {"summary": "Registry listing (scope services:read)"}},
        "/services/{capability}": {"get": {"summary": "One descriptor (scope services:read)"}},
        "/services/register": {"post": {"summary": "Self-register a service (scope services:write)"}},
        "/services/{capability}/heartbeat": {"post": {"summary": "Heartbeat within TTL (services:write)"}},
        "/services/{capability}/check": {"post": {"summary": "Run a health check now (services:write)"}},
        "/gw/{capability}/{path}": {"summary": "Authenticated, scoped, audited proxy to the service",
                                    "parameters": [{"name": "capability", "in": "path", "required": True},
                                                   {"name": "path", "in": "path", "required": True}]},
    },
}

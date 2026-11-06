"""Runtime service registry: portfolio-agent's static catalogue made live.

Static descriptors are portfolio-agent ``agent.yaml`` files (capability,
canonical_repo, agent, gxp, invocation, entities, depends_on, skill), loaded from
a directory or from portfolio-agent's ``registry/registry.yaml``. Each descriptor
can carry a ``runtime`` block (base_url, health_path, scopes, routes, ttl).
Running services can also self-register over the API and must then heartbeat
within their TTL or they are treated as down.

Scope resolution for a proxied call: the first matching ``routes`` entry wins
(method + path prefix), otherwise GET/HEAD/OPTIONS need ``scopes.read`` and every
other method needs ``scopes.write``.
"""
from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

import yaml

from .transport import Transport, TransportError, UpstreamRequest

CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
AGENTS = ("production-manufacturing", "qa-compliance", "supply-chain", "economics-cost", "commercial-bd",
          "shared-tool")
MODES = ("api_service", "mcp_tool", "batch_job", "library", "ui_app")
READ_METHODS = ("GET", "HEAD", "OPTIONS")
STATUSES = ("unknown", "up", "down")


class RegistryError(ValueError):
    """Invalid descriptor or unknown capability."""


@dataclass
class RouteScope:
    """Scope override for requests whose method and path prefix match."""

    methods: tuple[str, ...]
    path_prefix: str
    scope: str

    def matches(self, method: str, path: str) -> bool:
        return method.upper() in self.methods and ("/" + path.lstrip("/")).startswith(self.path_prefix)


@dataclass
class ServiceDescriptor:
    """One capability: the portfolio-agent descriptor plus runtime routing data."""

    capability: str
    canonical_repo: str | None = None
    agent: str = "shared-tool"
    gxp: bool = False
    invocation: dict[str, Any] = field(default_factory=dict)
    entities: dict[str, list[str]] = field(default_factory=lambda: {"reads": [], "writes": []})
    depends_on: list[str] = field(default_factory=list)
    skill: str | None = None
    aliases: list[str] = field(default_factory=list)
    # runtime
    base_url: str | None = None
    health_path: str = "/healthz"
    read_scope: str | None = None
    write_scope: str | None = None
    routes: list[RouteScope] = field(default_factory=list)
    proxy: bool = True
    ttl_seconds: int | None = None
    source: str = "static"  # static | self_registered
    status: str = "unknown"
    last_heartbeat: float | None = None
    last_check: float | None = None
    last_error: str | None = None

    def scope_for(self, method: str, path: str) -> str:
        for r in self.routes:
            if r.matches(method, path):
                return r.scope
        if method.upper() in READ_METHODS:
            return self.read_scope or f"{self.capability}:read"
        return self.write_scope or f"{self.capability}:write"

    def to_dict(self, now: float | None = None) -> dict[str, Any]:
        return {
            "capability": self.capability, "canonical_repo": self.canonical_repo, "agent": self.agent,
            "gxp": self.gxp, "invocation": self.invocation, "entities": self.entities,
            "depends_on": self.depends_on, "skill": self.skill, "aliases": self.aliases,
            "runtime": {
                "base_url": self.base_url, "health_path": self.health_path, "proxy": self.proxy,
                "scopes": {"read": self.read_scope or f"{self.capability}:read",
                           "write": self.write_scope or f"{self.capability}:write"},
                "routes": [{"methods": list(r.methods), "path_prefix": r.path_prefix, "scope": r.scope}
                           for r in self.routes],
                "ttl_seconds": self.ttl_seconds, "source": self.source,
                "status": self.effective_status(now if now is not None else time.time()),
                "last_heartbeat": self.last_heartbeat, "last_check": self.last_check,
                "last_error": self.last_error,
            },
        }

    def effective_status(self, now: float) -> str:
        """``down`` if a self-registered service missed its heartbeat TTL, else the last known status."""
        if self.ttl_seconds and self.last_heartbeat is not None and now - self.last_heartbeat > self.ttl_seconds:
            return "down"
        return self.status

    @property
    def routable(self) -> bool:
        return bool(self.proxy and self.base_url)


def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    return [str(x) for x in v]


def descriptor_from_dict(d: Mapping[str, Any], *, source: str = "static") -> ServiceDescriptor:
    """Validate and build a descriptor from an agent.yaml-shaped mapping.

    Unknown keys (portfolio-agent's ``rollup``, ``folds_in``, ``note``...) are ignored.
    """
    cap = str(d.get("capability", ""))
    if not CAPABILITY_RE.match(cap):
        raise RegistryError(f"capability must be kebab-case, got {cap!r}")
    agent = d.get("agent", "shared-tool")
    if agent not in AGENTS:
        raise RegistryError(f"{cap}: agent must be one of {AGENTS}")
    inv = dict(d.get("invocation") or {})
    if inv.get("mode") and inv["mode"] not in MODES:
        raise RegistryError(f"{cap}: invocation.mode must be one of {MODES}")
    ents = d.get("entities") or {}
    rt = dict(d.get("runtime") or {})
    for k in ("base_url", "health_path", "scopes", "routes", "ttl_seconds", "proxy"):
        if k in d and k not in rt:  # self-registration may send runtime fields at top level
            rt[k] = d[k]
    base_url = rt.get("base_url")
    if base_url is not None:
        base_url = str(base_url).rstrip("/")
        if not re.match(r"^https?://[^/\s]+", base_url):
            raise RegistryError(f"{cap}: base_url must be an http(s) URL")
    health_path = str(rt.get("health_path", "/healthz"))
    if not health_path.startswith("/"):
        raise RegistryError(f"{cap}: health_path must start with /")
    scopes = rt.get("scopes") or {}
    routes = []
    for r in rt.get("routes") or []:
        methods = tuple(m.upper() for m in _as_list(r.get("methods")))
        prefix = str(r.get("path_prefix", "/"))
        if not methods or not r.get("scope") or not prefix.startswith("/"):
            raise RegistryError(f"{cap}: each route needs methods, path_prefix (/...) and scope")
        routes.append(RouteScope(methods, prefix, str(r["scope"])))
    ttl = rt.get("ttl_seconds")
    return ServiceDescriptor(
        capability=cap, canonical_repo=d.get("canonical_repo"), agent=agent, gxp=bool(d.get("gxp", False)),
        invocation=inv, entities={"reads": _as_list(ents.get("reads")), "writes": _as_list(ents.get("writes"))},
        depends_on=_as_list(d.get("depends_on")), skill=d.get("skill"), aliases=_as_list(d.get("aliases")),
        base_url=base_url, health_path=health_path, read_scope=scopes.get("read"), write_scope=scopes.get("write"),
        routes=routes, proxy=bool(rt.get("proxy", True)), ttl_seconds=int(ttl) if ttl else None, source=source,
    )


class ServiceRegistry:
    """Thread-safe in-memory registry of capabilities."""

    def __init__(self, *, default_ttl_seconds: int = 90, clock: Callable[[], float] = time.time) -> None:
        self._services: dict[str, ServiceDescriptor] = {}
        self._lock = threading.Lock()
        self.default_ttl_seconds = default_ttl_seconds
        self.clock = clock

    # -- loading ---------------------------------------------------------
    def add(self, desc: ServiceDescriptor) -> ServiceDescriptor:
        with self._lock:
            self._services[desc.capability] = desc
        return desc

    def load_file(self, path: str | Path) -> ServiceDescriptor:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return self.add(descriptor_from_dict(data))

    def load_dir(self, path: str | Path) -> list[ServiceDescriptor]:
        """Load ``*.yaml`` files and ``*/agent.yaml`` files under ``path``."""
        root = Path(path)
        files = sorted(set(root.glob("*.yaml")) | set(root.glob("*.yml")) | set(root.glob("*/agent.yaml")))
        out = []
        for f in files:
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            if "capability" not in data:  # e.g. registry.yaml itself
                continue
            out.append(self.add(descriptor_from_dict(data)))
        return out

    def load_portfolio_registry(self, registry_yaml: str | Path) -> list[ServiceDescriptor]:
        """Load portfolio-agent ``registry/registry.yaml`` plus its sibling ``<capability>/agent.yaml`` files.

        A capability listed in registry.yaml without an agent.yaml is still
        catalogued (agent group only), so nothing in the static map is lost.
        """
        path = Path(registry_yaml)
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        out = []
        for agent, caps in (data.get("agents") or {}).items():
            for cap in caps or []:
                cap = str(cap).split("#")[0].strip()
                desc_file = path.parent / cap / "agent.yaml"
                if desc_file.exists():
                    out.append(self.load_file(desc_file))
                else:
                    out.append(self.add(descriptor_from_dict({"capability": cap, "agent": agent})))
        return out

    # -- lookup ----------------------------------------------------------
    def get(self, capability: str) -> ServiceDescriptor | None:
        with self._lock:
            if capability in self._services:
                return self._services[capability]
            for d in self._services.values():
                if capability in d.aliases:
                    return d
        return None

    def require(self, capability: str) -> ServiceDescriptor:
        d = self.get(capability)
        if d is None:
            raise RegistryError(f"unknown capability {capability!r}")
        return d

    def list(self) -> list[ServiceDescriptor]:
        with self._lock:
            return sorted(self._services.values(), key=lambda d: d.capability)

    def status(self, capability: str) -> str:
        return self.require(capability).effective_status(self.clock())

    # -- runtime ---------------------------------------------------------
    def register(self, data: Mapping[str, Any]) -> ServiceDescriptor:
        """Self-registration. Merges runtime fields into an existing static descriptor of the same capability.

        A self-registered service needs a base_url and starts its heartbeat clock now.
        """
        new = descriptor_from_dict(data, source="self_registered")
        if not new.base_url:
            raise RegistryError(f"{new.capability}: self-registration requires base_url")
        new.ttl_seconds = new.ttl_seconds or self.default_ttl_seconds
        new.last_heartbeat = self.clock()
        new.status = "up"
        with self._lock:
            old = self._services.get(new.capability)
            if old is not None:
                if old.canonical_repo and new.canonical_repo and old.canonical_repo != new.canonical_repo:
                    raise RegistryError(f"{new.capability}: canonical_repo {new.canonical_repo} does not match "
                                        f"registered {old.canonical_repo}")
                # Keep catalogue facts from the static descriptor where the registration is silent.
                new.canonical_repo = new.canonical_repo or old.canonical_repo
                new.invocation = new.invocation or old.invocation
                if not (new.entities["reads"] or new.entities["writes"]):
                    new.entities = old.entities
                new.depends_on = new.depends_on or old.depends_on
                new.aliases = new.aliases or old.aliases
                new.read_scope = new.read_scope or old.read_scope
                new.write_scope = new.write_scope or old.write_scope
                new.routes = new.routes or old.routes
                if "gxp" not in data:
                    new.gxp = old.gxp
            self._services[new.capability] = new
        return new

    def heartbeat(self, capability: str) -> ServiceDescriptor:
        d = self.require(capability)
        with self._lock:
            d.last_heartbeat = self.clock()
            if d.ttl_seconds is None:
                d.ttl_seconds = self.default_ttl_seconds
            d.status = "up"
            d.last_error = None
        return d

    def check_health(self, capability: str, transport: Transport, timeout: float = 5.0) -> str:
        """GET base_url + health_path; mark the service up (2xx) or down (anything else)."""
        d = self.require(capability)
        if not d.base_url:
            return d.effective_status(self.clock())
        try:
            resp = transport(UpstreamRequest("GET", d.base_url + d.health_path, timeout=timeout))
            up, err = 200 <= resp.status < 300, None if 200 <= resp.status < 300 else f"HTTP {resp.status}"
        except TransportError as e:
            up, err = False, str(e)
        with self._lock:
            d.status = "up" if up else "down"
            d.last_error = err
            d.last_check = self.clock()
            if up and d.ttl_seconds:
                d.last_heartbeat = d.last_check
        return d.status

    def check_all(self, transport: Transport, timeout: float = 5.0) -> dict[str, str]:
        return {d.capability: self.check_health(d.capability, transport, timeout)
                for d in self.list() if d.base_url}


def load_registry(paths: Iterable[str | Path], **kwargs: Any) -> ServiceRegistry:
    """Build a registry from a mix of descriptor directories and registry.yaml files."""
    reg = ServiceRegistry(**kwargs)
    for p in paths:
        p = Path(p)
        if p.is_dir():
            reg.load_dir(p)
        elif p.name == "registry.yaml":
            reg.load_portfolio_registry(p)
        elif p.exists():
            reg.load_file(p)
    return reg

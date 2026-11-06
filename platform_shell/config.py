"""Environment-driven configuration for the platform shell.

Every secret comes from the environment (Azure Key Vault in production); nothing
secret has a default. ``ShellConfig.from_env()`` is the only place env vars are read.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

ENVIRONMENTS = ("dev", "test", "staging", "prod")


class ConfigError(RuntimeError):
    """Raised when the shell is misconfigured for its environment."""


def _int(env: Mapping[str, str], key: str, default: int) -> int:
    raw = env.get(key)
    if raw in (None, ""):
        return default
    try:
        return int(raw)
    except ValueError as e:
        raise ConfigError(f"{key} must be an integer, got {raw!r}") from e


def load_role_map(raw: str | None) -> dict[str, list[str]]:
    """Parse an OIDC role map from inline JSON or a path to a YAML/JSON file.

    Shape: ``{"<Entra app role or group object id>": "cmc_lead" | ["qa", "viewer"]}``.
    """
    if not raw:
        return {}
    text = raw
    p = Path(raw)
    if not raw.lstrip().startswith("{") and p.exists():
        text = p.read_text(encoding="utf-8")
        if p.suffix in (".yaml", ".yml"):
            import yaml

            data = yaml.safe_load(text) or {}
            data = data.get("role_map", data)
            return {str(k): [v] if isinstance(v, str) else list(v) for k, v in data.items()}
    data = json.loads(text)
    data = data.get("role_map", data)
    return {str(k): [v] if isinstance(v, str) else list(v) for k, v in data.items()}


@dataclass
class ShellConfig:
    """All runtime settings for the gateway, identity store and audit client."""

    env: str = "dev"
    secret: str | None = None
    issuer: str = "platform-shell"
    audience: str = "pharma-platform"
    token_ttl_seconds: int = 1800
    assertion_ttl_seconds: int = 60
    db_path: str = "data/platform_shell.db"
    lockout_threshold: int = 5
    lockout_minutes: int = 15
    min_password_length: int = 12
    audit_url: str | None = "http://localhost:5056"
    audit_spool_path: str = "data/audit_spool.jsonl"
    source_system: str = "platform-shell"
    services_dir: str | None = "examples/services"
    heartbeat_ttl_seconds: int = 90
    rate_limit_per_minute: int = 0
    upstream_timeout_seconds: float = 30.0
    esign_reauth_max_age_seconds: int = 300
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_tenant_id: str | None = None
    oidc_role_map: dict[str, list[str]] = field(default_factory=dict)
    oidc_default_role: str | None = None

    def __post_init__(self) -> None:
        if self.env not in ENVIRONMENTS:
            raise ConfigError(f"env must be one of {ENVIRONMENTS}, got {self.env!r}")

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **overrides: Any) -> "ShellConfig":
        """Build a config from ``PLATFORM_*`` environment variables."""
        e = os.environ if env is None else env
        cfg = cls(
            env=e.get("PLATFORM_ENV", "dev"),
            secret=e.get("PLATFORM_SECRET") or None,
            issuer=e.get("PLATFORM_ISSUER", "platform-shell"),
            audience=e.get("PLATFORM_AUDIENCE", "pharma-platform"),
            token_ttl_seconds=_int(e, "PLATFORM_TOKEN_TTL", 1800),
            db_path=e.get("PLATFORM_DB", "data/platform_shell.db"),
            lockout_threshold=_int(e, "PLATFORM_LOCKOUT_THRESHOLD", 5),
            lockout_minutes=_int(e, "PLATFORM_LOCKOUT_MINUTES", 15),
            audit_url=e.get("PLATFORM_AUDIT_URL", "http://localhost:5056") or None,
            audit_spool_path=e.get("PLATFORM_AUDIT_SPOOL", "data/audit_spool.jsonl"),
            services_dir=e.get("PLATFORM_SERVICES_DIR", "examples/services") or None,
            heartbeat_ttl_seconds=_int(e, "PLATFORM_HEARTBEAT_TTL", 90),
            rate_limit_per_minute=_int(e, "PLATFORM_RATE_LIMIT_PER_MIN", 0),
            oidc_issuer=e.get("PLATFORM_OIDC_ISSUER") or None,
            oidc_audience=e.get("PLATFORM_OIDC_AUDIENCE") or None,
            oidc_jwks_url=e.get("PLATFORM_OIDC_JWKS_URL") or None,
            oidc_tenant_id=e.get("PLATFORM_OIDC_TENANT_ID") or None,
            oidc_role_map=load_role_map(e.get("PLATFORM_OIDC_ROLE_MAP")),
            oidc_default_role=e.get("PLATFORM_OIDC_DEFAULT_ROLE") or None,
        )
        for k, v in overrides.items():
            setattr(cfg, k, v)
        return cfg

"""Audit client for any platform service. Drop-in replacement for portfolio-agent
``scaffold/app/audit_client.py``, which posts JSON to ``/log`` although
AuditTrailService's ``/log`` reads FORM fields (so every event was rejected).
Source: timjm25/PharmaPlatformShell scaffold/app/audit_client.py.

Same call signature as before: ``audit(action, entity, entity_id, before=, after=, reason=)``.
WHO comes from ``g.user`` (set by ``app.auth.require_user``). If AuditTrailService
is down or rejects the event, it is appended to a local JSONL spool chained with
AuditTrailService's own hash chain; replay it with ``platform-shell replay-audit``
(set PLATFORM_AUDIT_SPOOL to the same path). The regulated action only fails if
the event can be neither delivered nor spooled, and only in prod.

Settings: ``settings.audit_platform_url``, ``settings.service_name``, ``settings.env``;
spool path from ``settings.audit_spool_path`` or env PLATFORM_AUDIT_SPOOL
(default data/audit_spool.jsonl).
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from flask import g, has_request_context, request

from app.config import settings
from app.logging_config import get_logger

log = get_logger(__name__)

GENESIS_HASH = "0" * 64
ACTIONS = ("AI_OUTPUT_GENERATED", "HUMAN_REVIEWED", "HUMAN_APPROVED", "HUMAN_OVERRIDDEN", "AUTO_LOG")
# Service verbs -> AuditTrailService action enum. Anything else is AUTO_LOG.
ACTION_MAP = {
    "approve": "HUMAN_APPROVED", "release": "HUMAN_APPROVED", "sign": "HUMAN_APPROVED",
    "review": "HUMAN_REVIEWED", "verify": "HUMAN_REVIEWED",
    "override": "HUMAN_OVERRIDDEN",
    "generate": "AI_OUTPUT_GENERATED", "ai_output": "AI_OUTPUT_GENERATED", "predict": "AI_OUTPUT_GENERATED",
}
REJECTION_MARKER = 'class="alert alert-bad"'
_lock = threading.Lock()


def _compute_hash(prev_hash: str, ts: str, source_system: str, actor: str, actor_type: str, action: str,
                  resource: str, detail: str, related_event_id: Any) -> str:
    """Identical to AuditTrailService audittrail/model.py _compute_hash."""
    payload = "\x1f".join([prev_hash, ts, source_system, actor, actor_type, action, resource, detail,
                           "" if related_event_id is None else str(related_event_id)])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _post(url: str, fields: dict[str, str]) -> tuple[int, str]:
    """POST form fields; returns (status, body text). Replaceable in tests."""
    try:
        import httpx

        r = httpx.post(url, data=fields, timeout=5.0)
        return r.status_code, r.text
    except ImportError:
        import urllib.request

        req = urllib.request.Request(url, data=urlencode(fields).encode(), method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=5.0) as resp:  # noqa: S310 - configured internal URL
            return resp.status, resp.read().decode("utf-8", "replace")


def _spool_path() -> Path:
    return Path(getattr(settings, "audit_spool_path", None) or os.environ.get("PLATFORM_AUDIT_SPOOL")
                or "data/audit_spool.jsonl")


def _spool(fields: dict[str, str], reason: str) -> dict[str, Any]:
    path = _spool_path()
    with _lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        last = None
        if path.exists():
            lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            last = json.loads(lines[-1]) if lines else None
        prev = last["hash"] if last else GENESIS_HASH
        ts = datetime.now(timezone.utc).isoformat()
        rel = int(fields["related_event_id"]) if fields.get("related_event_id") else None
        h = _compute_hash(prev, ts, fields["source_system"], fields["actor"], fields["actor_type"],
                          fields["action"], fields["resource"], fields["detail"], rel)
        entry = {"seq": (last["seq"] + 1) if last else 1, "ts": ts, "source_system": fields["source_system"],
                 "actor": fields["actor"], "actor_type": fields["actor_type"], "action": fields["action"],
                 "resource": fields["resource"], "detail": fields["detail"], "related_event_id": rel,
                 "prev_hash": prev, "hash": h, "spool_reason": reason}
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return entry


def audit(
    action: str,
    entity: str,
    entity_id: str,
    *,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    reason: str | None = None,
    related_event_id: int | None = None,
) -> bool:
    """Record a GxP audit event. Returns True if AuditTrailService accepted it, False if spooled.

    Resource is ``<entity lower-case>:<entity_id>``, e.g. ``asset:AST-000001``.
    """
    user = (getattr(g, "user", None) or {}) if has_request_context() else {}
    roles = user.get("roles", []) or []
    detail = {"verb": action, "before": before, "after": after, "reason": reason}
    if has_request_context() and request.headers.get("X-Request-Id"):
        detail["request_id"] = request.headers["X-Request-Id"]
    fields = {
        "source_system": settings.service_name,
        "actor": str(user.get("sub") or "unknown"),
        "actor_type": "automated_process" if "service" in roles else "human",
        "action": action if action in ACTIONS else ACTION_MAP.get(action.lower(), "AUTO_LOG"),
        "resource": f"{entity.lower()}:{entity_id}",
        "detail": json.dumps(detail, sort_keys=True, separators=(",", ":"), default=str),
        "related_event_id": "" if related_event_id is None else str(int(related_event_id)),
    }
    try:
        status, text = _post(f"{settings.audit_platform_url.rstrip('/')}/log", fields)
        if 200 <= status < 300 and REJECTION_MARKER not in text:
            return True
        failure = f"HTTP {status}" if not 200 <= status < 300 else "rejected by AuditTrailService"
    except Exception as e:  # noqa: BLE001 - the audit service being down must not crash the caller
        failure = str(e) or e.__class__.__name__
    log.warning("audit_emit_failed_spooling", extra={"reason": failure, "resource": fields["resource"]})
    try:
        _spool(fields, failure)
    except OSError:
        log.exception("audit_spool_failed", extra={"event": fields})
        if getattr(settings, "env", "dev") == "prod":
            raise  # neither delivered nor spooled: a regulated action must not proceed unrecorded
    return False

"""Client for AuditTrailService (timjm25/AuditTrailService, port 5056) with a durable fallback.

AuditTrailService's ``POST /log`` takes **form fields** (source_system, actor,
actor_type, action, resource, detail, related_event_id), not JSON. It also answers
HTTP 200 with an HTML dashboard even when it rejects an event, so this client
looks for the dashboard's error banner to tell "accepted" from "rejected".

The client never raises because the audit service is down. Undelivered events go
to a local append-only JSONL spool chained with exactly the same SHA-256 hash
chain as AuditTrailService (``\\x1f``-joined fields, genesis ``"0"*64``). Delivery
state lives in a separate ``<spool>.delivered`` file so the chained file is never
rewritten. ``replay()`` pushes spooled events, in order, once the service is back.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import urlencode

from .transport import Transport, TransportError, UpstreamRequest, UrllibTransport

try:  # prefer the installed upstream when present, so the chain can never drift
    from audittrail.model import ACTIONS, ACTOR_TYPES, GENESIS_HASH, _compute_hash  # type: ignore
except ImportError:  # pragma: no cover - exercised in CI, where upstream is not installed
    from ._vendor.audittrail_chain import ACTIONS, ACTOR_TYPES, GENESIS_HASH, _compute_hash

log = logging.getLogger(__name__)

# AuditTrailService renders validation errors into this element (templates/dashboard.html).
REJECTION_MARKER = 'class="alert alert-bad"'


@dataclass
class AuditReceipt:
    """What happened to one audit event."""

    delivered: bool
    spooled: bool
    local_seq: int | None = None
    local_hash: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"delivered": self.delivered, "spooled": self.spooled, "local_seq": self.local_seq,
                "local_hash": self.local_hash, "error": self.error}


def _validate(actor: str, actor_type: str, action: str, resource: str, source_system: str) -> None:
    if not source_system.strip():
        raise ValueError("source_system is required")
    if not actor.strip():
        raise ValueError("actor is required")
    if not resource.strip():
        raise ValueError("resource is required")
    if actor_type not in ACTOR_TYPES:
        raise ValueError(f"actor_type must be one of {ACTOR_TYPES}")
    if action not in ACTIONS:
        raise ValueError(f"action must be one of {ACTIONS}")


class AuditSpool:
    """Append-only, hash-chained JSONL file of events not yet delivered."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self.delivered_path = Path(str(self.path) + ".delivered")
        self._lock = threading.Lock()

    def entries(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return iter(())
        with self.path.open("r", encoding="utf-8") as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
        return (json.loads(ln) for ln in lines)

    def _last(self) -> dict[str, Any] | None:
        last = None
        for e in self.entries():
            last = e
        return last

    def append(self, *, source_system: str, actor: str, actor_type: str, action: str, resource: str,
               detail: str, related_event_id: int | None, reason: str,
               clock: Callable[[], datetime]) -> dict[str, Any]:
        """Append one event, chained to the previous line. Returns the stored entry."""
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            last = self._last()
            prev_hash = last["hash"] if last else GENESIS_HASH
            seq = (last["seq"] + 1) if last else 1
            ts = clock().isoformat()
            h = _compute_hash(prev_hash, ts, source_system, actor, actor_type, action, resource, detail,
                              related_event_id)
            entry = {"seq": seq, "ts": ts, "source_system": source_system, "actor": actor,
                     "actor_type": actor_type, "action": action, "resource": resource, "detail": detail,
                     "related_event_id": related_event_id, "prev_hash": prev_hash, "hash": h,
                     "spool_reason": reason}
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
            return entry

    def delivered_seqs(self) -> set[int]:
        if not self.delivered_path.exists():
            return set()
        return {int(x) for x in self.delivered_path.read_text(encoding="utf-8").split() if x.strip()}

    def mark_delivered(self, seq: int) -> None:
        with self._lock:
            with self.delivered_path.open("a", encoding="utf-8") as f:
                f.write(f"{seq}\n")

    def pending(self) -> list[dict[str, Any]]:
        done = self.delivered_seqs()
        return [e for e in self.entries() if e["seq"] not in done]


def verify_local_chain(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Recompute the spool's hash chain. Same result shape as AuditTrailService ``verify_chain``."""
    expected_prev = GENESIS_HASH
    checked = 0
    for e in AuditSpool(path).entries():
        checked += 1
        if e["prev_hash"] != expected_prev:
            return {"valid": False, "checked": checked, "broken_at_seq": e["seq"],
                    "message": f"Spooled event {e['seq']} does not chain from the previous event's hash."}
        recomputed = _compute_hash(e["prev_hash"], e["ts"], e["source_system"], e["actor"], e["actor_type"],
                                   e["action"], e["resource"], e["detail"], e["related_event_id"])
        if recomputed != e["hash"]:
            return {"valid": False, "checked": checked, "broken_at_seq": e["seq"],
                    "message": f"Spooled event {e['seq']} content does not match its recorded hash."}
        expected_prev = e["hash"]
    return {"valid": True, "checked": checked, "broken_at_seq": None,
            "message": f"Local chain intact across {checked} event(s)."}


class AuditClient:
    """Send events to AuditTrailService; spool locally on any failure.

    ``base_url=None`` runs fully offline (every event is spooled). ``transport``
    is injectable; the default is the stdlib :class:`UrllibTransport`.
    """

    def __init__(self, base_url: str | None, *, source_system: str, spool_path: str | os.PathLike[str],
                 transport: Transport | None = None, timeout: float = 5.0,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self.base_url = base_url.rstrip("/") if base_url else None
        self.source_system = source_system
        self.spool = AuditSpool(spool_path)
        self.transport = transport or UrllibTransport()
        self.timeout = timeout
        self.clock = clock

    def _post(self, fields: dict[str, str]) -> None:
        """POST form fields to /log; raise on any non-acceptance."""
        if not self.base_url:
            raise TransportError("no audit service configured (offline mode)")
        req = UpstreamRequest(
            method="POST", url=f"{self.base_url}/log", timeout=self.timeout,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/html"},
            body=urlencode(fields).encode("utf-8"),
        )
        resp = self.transport(req)
        if not (200 <= resp.status < 300):
            raise TransportError(f"audit service answered HTTP {resp.status}")
        if REJECTION_MARKER in resp.text():
            raise TransportError("audit service rejected the event (validation error banner in response)")

    def log(self, *, actor: str, actor_type: str, action: str, resource: str, detail: str | dict = "",
            related_event_id: int | None = None, source_system: str | None = None) -> AuditReceipt:
        """Record one event. Never raises for transport failures; raises ValueError for invalid input.

        ``detail`` may be a dict; it is serialised as compact, key-sorted JSON.
        """
        src = (source_system or self.source_system).strip()
        actor, resource = actor.strip(), resource.strip()
        _validate(actor, actor_type, action, resource, src)
        detail_s = json.dumps(detail, sort_keys=True, separators=(",", ":")) if isinstance(detail, dict) \
            else (detail or "").strip()
        fields = {"source_system": src, "actor": actor, "actor_type": actor_type, "action": action,
                  "resource": resource, "detail": detail_s,
                  "related_event_id": "" if related_event_id is None else str(int(related_event_id))}
        try:
            self._post(fields)
            return AuditReceipt(delivered=True, spooled=False)
        except Exception as e:  # noqa: BLE001 - audit must never crash the caller
            reason = str(e) or e.__class__.__name__
            log.warning("audit delivery failed, spooling locally: %s", reason)
            try:
                entry = self.spool.append(source_system=src, actor=actor, actor_type=actor_type, action=action,
                                          resource=resource, detail=detail_s, related_event_id=related_event_id,
                                          reason=reason, clock=self.clock)
            except OSError as oe:  # disk full / read-only: last resort is the process log
                log.error("audit spool write failed; event only in process log: %s %s", fields, oe)
                return AuditReceipt(delivered=False, spooled=False, error=f"{reason}; spool: {oe}")
            return AuditReceipt(delivered=False, spooled=True, local_seq=entry["seq"], local_hash=entry["hash"],
                                error=reason)

    def replay(self, *, limit: int | None = None) -> dict[str, Any]:
        """Push pending spooled events in order; stop at the first failure to keep ordering.

        The original local timestamp, sequence number and hash are appended to the
        detail as ``[spooled ts=... seq=... local_hash=...]`` so an auditor can tie
        the service's record back to the local chain.
        """
        chain = verify_local_chain(self.spool.path)
        if not chain["valid"]:
            return {"attempted": 0, "delivered": 0, "remaining": len(self.spool.pending()),
                    "error": "local chain is broken; refusing to replay: " + chain["message"]}
        pending = self.spool.pending()
        attempted = delivered = 0
        error = None
        for e in pending[:limit] if limit else pending:
            attempted += 1
            suffix = f"[spooled ts={e['ts']} seq={e['seq']} local_hash={e['hash']}]"
            detail = f"{e['detail']} {suffix}" if e["detail"] else suffix
            fields = {"source_system": e["source_system"], "actor": e["actor"], "actor_type": e["actor_type"],
                      "action": e["action"], "resource": e["resource"], "detail": detail,
                      "related_event_id": "" if e["related_event_id"] is None else str(e["related_event_id"])}
            try:
                self._post(fields)
            except Exception as ex:  # noqa: BLE001
                error = str(ex)
                break
            self.spool.mark_delivered(e["seq"])
            delivered += 1
        return {"attempted": attempted, "delivered": delivered, "remaining": len(self.spool.pending()),
                "error": error}

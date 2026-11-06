"""Vendored from timjm25/AuditTrailService, audittrail/model.py,
commit 7b052ab465a5798a9b962c59b2ea28a510d83c6e.

Only the hash-chain primitives and the two enums are copied, unchanged in
behaviour, so the local fallback spool produces hashes byte-identical to the
ones AuditTrailService computes. Do not edit; re-vendor instead.
"""
from __future__ import annotations

import hashlib

ACTOR_TYPES = ("human", "ai_system", "automated_process")

ACTIONS = (
    "AI_OUTPUT_GENERATED",
    "HUMAN_REVIEWED",
    "HUMAN_APPROVED",
    "HUMAN_OVERRIDDEN",
    "AUTO_LOG",
)

GENESIS_HASH = "0" * 64


def _compute_hash(prev_hash, ts, source_system, actor, actor_type, action, resource, detail, related_event_id):
    payload = "\x1f".join([
        prev_hash,
        ts,
        source_system,
        actor,
        actor_type,
        action,
        resource,
        detail,
        "" if related_event_id is None else str(related_event_id),
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

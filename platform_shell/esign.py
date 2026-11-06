"""21 CFR Part 11 style electronic signatures.

Signing always re-authenticates the signer (password for local users, a fresh
IdP token for Entra users), requires a meaning and a reason, and records the act
in AuditTrailService. The returned object is exactly the CDMOAgentContracts
Common 1.0.0 ``signature`` definition (signer_id, signer_name, meaning,
signed_at, method), so it can be dropped into StageGateDecision.signatures and
any other contract that carries signatures.

Part 11 mapping:
* 11.50 signature manifestation: signer name, date/time, meaning.
* 11.70 signature/record linking: the audit event ties the signature to ``resource``.
* 11.200(a)(1) two components: user id + password re-entered at every signing.
* 11.300(d) failed signing attempts count toward account lockout.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from .audit import AuditClient, AuditReceipt
from .identity import USER_ID_RE, Principal, UserStore
from .tokens import OIDCError, OIDCProvider

MEANINGS = ("authored", "reviewed", "approved", "verified", "released")

# Common 1.0.0 meaning -> AuditTrailService action.
MEANING_TO_ACTION = {
    "approved": "HUMAN_APPROVED",
    "released": "HUMAN_APPROVED",
    "reviewed": "HUMAN_REVIEWED",
    "verified": "HUMAN_REVIEWED",
    "authored": "AUTO_LOG",
}

SIGNATURE_FIELDS = ("signer_id", "signer_name", "meaning", "signed_at", "method")
RFC3339_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class ESignError(Exception):
    """Signing refused (bad input, wrong signer, not permitted)."""


@dataclass
class ESignResult:
    """A signature plus the audit receipt and the record it was applied to."""

    signature: dict[str, str]
    resource: str
    reason: str
    audit: AuditReceipt

    def to_dict(self) -> dict[str, Any]:
        return {"signature": self.signature, "resource": self.resource, "reason": self.reason,
                "audit": self.audit.to_dict()}


def rfc3339_z(dt: datetime) -> str:
    """UTC timestamp like 2026-11-06T14:30:00Z."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_signature(sig: dict[str, Any]) -> None:
    """Explicit field checks equivalent to the Common 1.0.0 ``signature`` schema."""
    extra = set(sig) - set(SIGNATURE_FIELDS)
    if any(not k.startswith("x-") for k in extra):
        raise ESignError(f"unexpected signature fields: {sorted(extra)}")
    for req in ("signer_id", "meaning", "signed_at"):
        if req not in sig:
            raise ESignError(f"signature missing {req}")
    if not USER_ID_RE.match(sig["signer_id"]):
        raise ESignError("signer_id is not a Common identifier")
    if sig["meaning"] not in MEANINGS:
        raise ESignError(f"meaning must be one of {MEANINGS}")
    if not RFC3339_Z.match(sig["signed_at"]):
        raise ESignError("signed_at must be RFC 3339 UTC with Z")
    if sig.get("method", "electronic") not in ("electronic", "wet_ink_scanned"):
        raise ESignError("method must be electronic or wet_ink_scanned")
    if len(sig.get("signer_name", "")) > 200:
        raise ESignError("signer_name longer than 200 characters")


class ESignService:
    """Apply electronic signatures and record them in the audit trail."""

    def __init__(self, users: UserStore, audit: AuditClient, *, oidc: OIDCProvider | None = None,
                 reauth_max_age_seconds: int = 300,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self.users = users
        self.audit = audit
        self.oidc = oidc
        self.reauth_max_age_seconds = reauth_max_age_seconds
        self.clock = clock

    def _validate_inputs(self, principal: Principal, meaning: str, reason: str, resource: str) -> None:
        if not principal.can("esign:sign"):
            raise ESignError("this account is not permitted to apply electronic signatures")
        if meaning not in MEANINGS:
            raise ESignError(f"meaning must be one of {MEANINGS}")
        if not (reason or "").strip():
            raise ESignError("a reason is required for an electronic signature")
        if not (resource or "").strip():
            raise ESignError("resource (the record being signed) is required")

    def _reauthenticate(self, principal: Principal, password: str | None, reauth_token: str | None) -> str:
        """Return the signer's display name after re-authentication, or raise."""
        if principal.auth_method == "oidc":
            if not (self.oidc and reauth_token):
                raise ESignError("Entra users sign with a fresh reauth_token (interactive re-login)")
            try:
                fresh = self.oidc.validate(reauth_token)
            except OIDCError as e:
                raise ESignError(f"re-authentication failed: {e}") from e
            if fresh.sub != principal.sub:
                raise ESignError("re-authentication token belongs to a different user")
            auth_time = fresh.claims.get("auth_time")
            age = self.clock().timestamp() - auth_time if isinstance(auth_time, (int, float)) else None
            if age is None or age > self.reauth_max_age_seconds:
                raise ESignError(f"re-authentication must be within {self.reauth_max_age_seconds} seconds")
            return fresh.name
        # Local users: password re-entry. Failures count toward lockout (raises IdentityError).
        user = self.users.authenticate(principal.sub, password or "")
        return user.name

    def sign(self, principal: Principal, *, meaning: str, reason: str, resource: str,
             password: str | None = None, reauth_token: str | None = None,
             related_event_id: int | None = None) -> ESignResult:
        """Re-authenticate ``principal`` and sign ``resource`` with ``meaning`` and ``reason``.

        Raises :class:`ESignError` for invalid requests and
        :class:`platform_shell.identity.IdentityError` for failed password re-entry.
        """
        self._validate_inputs(principal, meaning, reason, resource)
        name = self._reauthenticate(principal, password, reauth_token)
        signature = {
            "signer_id": principal.sub,
            "signer_name": name[:200],
            "meaning": meaning,
            "signed_at": rfc3339_z(self.clock()),
            "method": "electronic",
        }
        check_signature(signature)
        detail = json.dumps({"esign": signature, "reason": reason.strip(), "auth_method": principal.auth_method},
                            sort_keys=True, separators=(",", ":"))
        receipt = self.audit.log(actor=principal.sub, actor_type="human", action=MEANING_TO_ACTION[meaning],
                                 resource=resource.strip(), detail=detail, related_event_id=related_event_id)
        return ESignResult(signature=signature, resource=resource.strip(), reason=reason.strip(), audit=receipt)

"""Users, roles and permission scopes, backed by SQLite.

Passwords are hashed with ``hashlib.scrypt`` and a per-user random salt; the
parameters are stored alongside the hash so they can be raised later without
breaking existing users. Repeated failed logins lock the account (21 CFR 11.300(d)
"detect and report attempts at unauthorized use").
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

# Role -> permission scopes. "admin" is a super-scope: it satisfies any check.
ROLE_SCOPES: dict[str, frozenset[str]] = {
    "admin": frozenset({"admin"}),
    "program_director": frozenset({
        "registry:read", "registry:write", "bus:read", "bus:publish", "gates:read", "gates:write",
        "gates:sign", "valuation:read", "dataroom:read", "audit:read", "cgt:read", "services:read",
        "esign:sign",
    }),
    "cmc_lead": frozenset({
        "registry:read", "registry:write", "bus:read", "bus:publish", "gates:read", "cgt:read",
        "cgt:write", "audit:read", "services:read", "esign:sign",
    }),
    "clinical_lead": frozenset({
        "registry:read", "registry:write", "bus:read", "bus:publish", "gates:read", "services:read",
        "esign:sign",
    }),
    "qa": frozenset({
        "registry:read", "bus:read", "gates:read", "gates:sign", "audit:read", "audit:write",
        "cgt:read", "services:read", "esign:sign",
    }),
    "bd": frozenset({
        "registry:read", "gates:read", "valuation:read", "valuation:write", "dataroom:read",
        "dataroom:write", "services:read", "esign:sign",
    }),
    "finance": frozenset({
        "registry:read", "valuation:read", "valuation:write", "dataroom:read", "services:read",
        "esign:sign",
    }),
    "viewer": frozenset({
        "registry:read", "bus:read", "gates:read", "valuation:read", "services:read",
    }),
    # External party (licensee, CRO, CDMO): data room only, never signs.
    "partner": frozenset({"dataroom:read"}),
    # Machine identity for services that self-register and heartbeat.
    "service": frozenset({"services:read", "services:write", "audit:write", "bus:publish"}),
}

ROLES: tuple[str, ...] = tuple(ROLE_SCOPES)

# Same pattern as CDMOAgentContracts Common "identifier", so user ids are valid signer_ids.
USER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")

SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN = 2**14, 8, 1, 64


class IdentityError(Exception):
    """Base class for identity failures."""


class InvalidCredentials(IdentityError):
    """Unknown user, wrong password or inactive account (deliberately indistinguishable)."""


class AccountLocked(IdentityError):
    """Too many failed attempts; the account is locked until ``locked_until``."""

    def __init__(self, user_id: str, locked_until: str | None) -> None:
        super().__init__(f"account {user_id} is locked" + (f" until {locked_until}" if locked_until else ""))
        self.user_id = user_id
        self.locked_until = locked_until


def scopes_for_roles(roles: Iterable[str]) -> list[str]:
    """Union of scopes for ``roles``, sorted. Unknown roles raise ValueError."""
    out: set[str] = set()
    for r in roles:
        if r not in ROLE_SCOPES:
            raise ValueError(f"unknown role {r!r}; known roles: {', '.join(ROLES)}")
        out |= ROLE_SCOPES[r]
    return sorted(out)


def has_scope(scopes: Iterable[str], required: str) -> bool:
    """True when ``required`` is granted (``admin`` grants everything)."""
    s = set(scopes)
    return "admin" in s or required in s


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    """Return ``scrypt$N$r$p$salt_hex$hash_hex``."""
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                        dklen=SCRYPT_DKLEN, maxmem=64 * 1024 * 1024)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of ``password`` against a ``hash_password`` string."""
    try:
        algo, n, r, p, salt_hex, hash_hex = stored.split("$")
    except ValueError:
        return False
    if algo != "scrypt":
        return False
    dk = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex), n=int(n), r=int(r),
                        p=int(p), dklen=len(hash_hex) // 2, maxmem=64 * 1024 * 1024)
    return hmac.compare_digest(dk.hex(), hash_hex)


# Used for unknown users so a login attempt costs the same either way (no user enumeration).
_DUMMY_HASH = hash_password(secrets.token_hex(16))


@dataclass
class User:
    """A platform user as stored (no secrets)."""

    user_id: str
    name: str
    roles: list[str]
    email: str | None = None
    active: bool = True
    failed_attempts: int = 0
    locked_until: str | None = None
    created_at: str = ""

    @property
    def scopes(self) -> list[str]:
        return scopes_for_roles(self.roles)

    def to_dict(self) -> dict:
        return {"user_id": self.user_id, "name": self.name, "email": self.email, "roles": self.roles,
                "scopes": self.scopes, "active": self.active, "locked_until": self.locked_until,
                "created_at": self.created_at}


@dataclass
class Principal:
    """An authenticated caller, however they authenticated."""

    sub: str
    name: str
    roles: list[str]
    scopes: list[str]
    auth_method: str = "password"  # password | oidc
    claims: dict = field(default_factory=dict)

    @property
    def actor_type(self) -> str:
        """AuditTrailService actor_type for this principal."""
        return "automated_process" if "service" in self.roles else "human"

    def can(self, scope: str) -> bool:
        return has_scope(self.scopes, scope)


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT,
    roles TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL,
    password_changed_at TEXT NOT NULL
);
"""


def _now() -> datetime:
    return datetime.now(timezone.utc)


class UserStore:
    """SQLite user store with lockout.

    ``lockout_minutes=0`` means a locked account stays locked until an admin
    calls :meth:`unlock`.
    """

    def __init__(self, db_path: str, *, lockout_threshold: int = 5, lockout_minutes: int = 15,
                 min_password_length: int = 12, clock: Callable[[], datetime] = _now) -> None:
        self.db_path = db_path
        self.lockout_threshold = lockout_threshold
        self.lockout_minutes = lockout_minutes
        self.min_password_length = min_password_length
        self.clock = clock
        self._lock = threading.Lock()
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._mem = sqlite3.connect(":memory:", check_same_thread=False) if db_path == ":memory:" else None
        self.init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = self._mem or sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _close(self, conn: sqlite3.Connection) -> None:
        if conn is not self._mem:
            conn.close()

    def init_db(self) -> None:
        conn = self._conn()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            self._close(conn)

    @staticmethod
    def _row(row: sqlite3.Row) -> User:
        return User(user_id=row["user_id"], name=row["name"], email=row["email"],
                    roles=json.loads(row["roles"]), active=bool(row["active"]),
                    failed_attempts=row["failed_attempts"], locked_until=row["locked_until"],
                    created_at=row["created_at"])

    def _check_password_policy(self, password: str) -> None:
        if len(password) < self.min_password_length:
            raise ValueError(f"password must be at least {self.min_password_length} characters")

    def create_user(self, user_id: str, name: str, roles: Iterable[str], password: str,
                    email: str | None = None) -> User:
        """Create a user. Raises ValueError on bad id, unknown role, weak password or duplicate."""
        if not USER_ID_RE.match(user_id or ""):
            raise ValueError("user_id must match the Common identifier pattern (letters, digits, . _ : / -)")
        roles = list(dict.fromkeys(roles))
        if not roles:
            raise ValueError("at least one role is required")
        scopes_for_roles(roles)
        self._check_password_policy(password)
        ts = self.clock().isoformat()
        conn = self._conn()
        try:
            with self._lock:
                conn.execute(
                    "INSERT INTO users (user_id, name, email, roles, password_hash, created_at, password_changed_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (user_id, name.strip() or user_id, email, json.dumps(roles), hash_password(password), ts, ts),
                )
                conn.commit()
        except sqlite3.IntegrityError as e:
            raise ValueError(f"user {user_id!r} already exists") from e
        finally:
            self._close(conn)
        return self.get(user_id)  # type: ignore[return-value]

    def get(self, user_id: str) -> User | None:
        conn = self._conn()
        try:
            row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()
            return self._row(row) if row else None
        finally:
            self._close(conn)

    def list_users(self) -> list[User]:
        conn = self._conn()
        try:
            return [self._row(r) for r in conn.execute("SELECT * FROM users ORDER BY user_id").fetchall()]
        finally:
            self._close(conn)

    def _update(self, user_id: str, **cols: object) -> None:
        sets = ", ".join(f"{k} = ?" for k in cols)
        conn = self._conn()
        try:
            conn.execute(f"UPDATE users SET {sets} WHERE user_id = ?", (*cols.values(), user_id))
            conn.commit()
        finally:
            self._close(conn)

    def set_roles(self, user_id: str, roles: Iterable[str]) -> None:
        roles = list(dict.fromkeys(roles))
        scopes_for_roles(roles)
        self._update(user_id, roles=json.dumps(roles))

    def set_active(self, user_id: str, active: bool) -> None:
        self._update(user_id, active=int(active))

    def set_password(self, user_id: str, password: str) -> None:
        self._check_password_policy(password)
        self._update(user_id, password_hash=hash_password(password), password_changed_at=self.clock().isoformat())

    def unlock(self, user_id: str) -> None:
        self._update(user_id, failed_attempts=0, locked_until=None)

    def is_locked(self, user: User) -> bool:
        if user.failed_attempts < self.lockout_threshold or self.lockout_threshold <= 0:
            return False
        if user.locked_until is None:
            return True  # locked until an admin unlocks
        return self.clock() < datetime.fromisoformat(user.locked_until)

    def authenticate(self, user_id: str, password: str) -> User:
        """Verify credentials, applying lockout. Returns the user or raises.

        Raises :class:`AccountLocked` when locked (even if the password is right) and
        :class:`InvalidCredentials` otherwise.
        """
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id or "",)).fetchone()
                if row is None:
                    verify_password(password or "", _DUMMY_HASH)
                    raise InvalidCredentials("invalid credentials")
                user = self._row(row)
                if self.is_locked(user):
                    raise AccountLocked(user.user_id, user.locked_until)
                if user.failed_attempts >= self.lockout_threshold > 0:
                    # Timed lock has expired: start a fresh window.
                    user.failed_attempts = 0
                ok = verify_password(password or "", row["password_hash"])
                if ok and user.active:
                    conn.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE user_id = ?",
                                 (user.user_id,))
                    conn.commit()
                    user.failed_attempts, user.locked_until = 0, None
                    return user
                attempts = user.failed_attempts + 1
                locked_until = None
                if self.lockout_threshold > 0 and attempts >= self.lockout_threshold and self.lockout_minutes > 0:
                    locked_until = (self.clock() + timedelta(minutes=self.lockout_minutes)).isoformat()
                conn.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE user_id = ?",
                             (attempts, locked_until, user.user_id))
                conn.commit()
                if self.lockout_threshold > 0 and attempts >= self.lockout_threshold:
                    raise AccountLocked(user.user_id, locked_until)
                raise InvalidCredentials("invalid credentials")
            finally:
                self._close(conn)

    def principal(self, user: User, auth_method: str = "password") -> Principal:
        return Principal(sub=user.user_id, name=user.name, roles=list(user.roles), scopes=user.scopes,
                         auth_method=auth_method)

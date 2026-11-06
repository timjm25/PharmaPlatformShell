from datetime import timedelta

import pytest

from conftest import PASSWORD, Clock
from platform_shell.identity import (ROLES, AccountLocked, InvalidCredentials, UserStore, has_scope, hash_password,
                                     scopes_for_roles, verify_password)


def _store(tmp_path, clock=None, **kw):
    c = clock or Clock()
    return UserStore(str(tmp_path / "u.db"), clock=c.dt, **kw), c


def test_password_hash_is_salted_scrypt_and_verifies():
    a, b = hash_password(PASSWORD), hash_password(PASSWORD)
    assert a.startswith("scrypt$") and a != b  # per-user salt
    assert verify_password(PASSWORD, a) and verify_password(PASSWORD, b)
    assert not verify_password(PASSWORD + "x", a)
    assert not verify_password(PASSWORD, "garbage")


def test_required_roles_exist_and_admin_grants_everything():
    for r in ("admin", "program_director", "cmc_lead", "clinical_lead", "qa", "bd", "finance", "viewer", "partner"):
        assert r in ROLES
    assert has_scope(scopes_for_roles(["admin"]), "dataroom:write")
    assert scopes_for_roles(["partner"]) == ["dataroom:read"]
    assert "gates:sign" in scopes_for_roles(["qa"]) and "gates:sign" not in scopes_for_roles(["viewer"])
    with pytest.raises(ValueError):
        scopes_for_roles(["superuser"])


def test_create_user_validation(tmp_path):
    s, _ = _store(tmp_path)
    s.create_user("tim.maguire", "Tim Maguire", ["program_director"], PASSWORD)
    with pytest.raises(ValueError, match="already exists"):
        s.create_user("tim.maguire", "Dup", ["viewer"], PASSWORD)
    with pytest.raises(ValueError, match="at least"):
        s.create_user("short.pw", "Short", ["viewer"], "abc")
    with pytest.raises(ValueError, match="identifier"):
        s.create_user("bad id!", "Bad", ["viewer"], PASSWORD)
    with pytest.raises(ValueError, match="unknown role"):
        s.create_user("x.y", "X", ["wizard"], PASSWORD)
    # The stored row never holds the clear-text password.
    raw = (tmp_path / "u.db").read_bytes()
    assert PASSWORD.encode() not in raw


def test_lockout_after_threshold_then_timed_unlock(tmp_path):
    s, clock = _store(tmp_path, lockout_threshold=3, lockout_minutes=15)
    s.create_user("qa.patel", "QA Patel", ["qa"], PASSWORD)
    for _ in range(2):
        with pytest.raises(InvalidCredentials):
            s.authenticate("qa.patel", "wrong-password-1")
    with pytest.raises(AccountLocked):
        s.authenticate("qa.patel", "wrong-password-1")
    with pytest.raises(AccountLocked):  # right password still refused while locked
        s.authenticate("qa.patel", PASSWORD)
    clock.advance(timedelta(minutes=16).total_seconds())
    assert s.authenticate("qa.patel", PASSWORD).user_id == "qa.patel"
    assert s.get("qa.patel").failed_attempts == 0


def test_indefinite_lock_needs_admin_unlock(tmp_path):
    s, clock = _store(tmp_path, lockout_threshold=2, lockout_minutes=0)
    s.create_user("bd.ortiz", "BD Ortiz", ["bd"], PASSWORD)
    for _ in range(2):
        with pytest.raises((InvalidCredentials, AccountLocked)):
            s.authenticate("bd.ortiz", "nope-nope-nope")
    clock.advance(86400 * 30)
    with pytest.raises(AccountLocked):
        s.authenticate("bd.ortiz", PASSWORD)
    s.unlock("bd.ortiz")
    assert s.authenticate("bd.ortiz", PASSWORD)


def test_unknown_and_inactive_users_are_indistinguishable(tmp_path):
    s, _ = _store(tmp_path)
    s.create_user("viewer.kim", "Viewer Kim", ["viewer"], PASSWORD)
    s.set_active("viewer.kim", False)
    with pytest.raises(InvalidCredentials):
        s.authenticate("viewer.kim", PASSWORD)
    with pytest.raises(InvalidCredentials):
        s.authenticate("nobody", PASSWORD)

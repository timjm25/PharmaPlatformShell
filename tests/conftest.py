"""Shared fixtures: a fully wired gateway over fake upstreams, with seeded users."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from fakes import echo_service, fake_audittrail
from platform_shell import identity
from platform_shell.config import ShellConfig
from platform_shell.gateway import create_app
from platform_shell.transport import WSGITransport

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "services"
PASSWORD = "correct horse battery staple"
SECRET = "test-secret-not-real-0123456789abcdefghij"

USERS = {
    "admin.ops": ["admin"],
    "pd.lee": ["program_director"],
    "cmc.ng": ["cmc_lead"],
    "qa.patel": ["qa"],
    "bd.ortiz": ["bd"],
    "viewer.kim": ["viewer"],
    "partner.acme": ["partner"],
    "svc.asset-registry": ["service"],
}


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch):
    """Cheaper scrypt cost for speed; the stored hash records its own parameters."""
    monkeypatch.setattr(identity, "SCRYPT_N", 2**10)


@pytest.fixture
def cfg(tmp_path) -> ShellConfig:
    return ShellConfig(env="test", secret=SECRET, db_path=str(tmp_path / "users.db"),
                       audit_url="http://localhost:5056", audit_spool_path=str(tmp_path / "spool.jsonl"),
                       services_dir=str(EXAMPLES), lockout_threshold=3, lockout_minutes=15)


@pytest.fixture
def upstreams():
    return {
        "localhost:5056": fake_audittrail(),
        "localhost:5101": echo_service("asset-registry"),
        "localhost:5102": echo_service("pharma-event-bus"),
        "localhost:5103": echo_service("program-director"),
        "localhost:5104": echo_service("asset-valuation"),
        "localhost:5053": echo_service("cgt-data-model"),
    }


@pytest.fixture
def app(cfg, upstreams):
    transport = WSGITransport(upstreams)
    application = create_app(cfg, transport=transport)
    shell = application.extensions["platform_shell"]
    for uid, roles in USERS.items():
        shell.users.create_user(uid, uid.replace(".", " ").title(), roles, PASSWORD)
    application.config["UPSTREAMS"] = upstreams
    application.config["TRANSPORT"] = transport
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def shell(app):
    return app.extensions["platform_shell"]


@pytest.fixture
def audit_events(upstreams):
    return upstreams["localhost:5056"].config["EVENTS"]


@pytest.fixture
def login(client):
    def _login(user_id: str, password: str = PASSWORD) -> dict:
        r = client.post("/auth/token", json={"username": user_id, "password": password})
        assert r.status_code == 200, r.get_data(as_text=True)
        return {"Authorization": f"Bearer {r.get_json()['access_token']}"}
    return _login


class Clock:
    """Mutable clock for lockout / expiry / TTL tests."""

    def __init__(self, t: float = 1_800_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def dt(self) -> datetime:
        return datetime.fromtimestamp(self.t, tz=timezone.utc)

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()

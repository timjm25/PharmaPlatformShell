from pathlib import Path

import pytest

from conftest import EXAMPLES, ROOT, Clock
from fakes import echo_service
from platform_shell.service_registry import RegistryError, ServiceRegistry, descriptor_from_dict, load_registry
from platform_shell.transport import WSGITransport

FIXTURE = Path(__file__).parent / "fixtures" / "portfolio_registry" / "registry.yaml"


def test_example_descriptors_load_with_ports_and_scopes():
    reg = load_registry([EXAMPLES])
    caps = {d.capability: d for d in reg.list()}
    assert set(caps) == {"platform-shell", "asset-registry", "pharma-event-bus", "program-director",
                         "asset-valuation", "gxp-audit-platform", "cgt-data-model"}
    ports = {c: d.base_url.rsplit(":", 1)[1] for c, d in caps.items()}
    assert ports == {"platform-shell": "5100", "asset-registry": "5101", "pharma-event-bus": "5102",
                     "program-director": "5103", "asset-valuation": "5104", "gxp-audit-platform": "5056",
                     "cgt-data-model": "5053"}
    assert caps["pharma-event-bus"].scope_for("POST", "/publish") == "bus:publish"
    assert caps["asset-registry"].scope_for("GET", "/assets") == "registry:read"
    assert reg.get("cdmo-semantic-layer").capability == "cgt-data-model"  # portfolio-agent name still resolves
    assert not caps["platform-shell"].routable


def test_route_overrides_take_precedence():
    reg = load_registry([EXAMPLES])
    pd, val = reg.require("program-director"), reg.require("asset-valuation")
    assert pd.scope_for("POST", "gates/G2/decide") == "gates:sign"
    assert pd.scope_for("POST", "/runs") == "gates:write"
    assert val.scope_for("GET", "/dataroom/AST-000001") == "dataroom:read"
    assert val.scope_for("GET", "/valuations") == "valuation:read"


def test_this_repos_agent_yaml_is_a_valid_descriptor():
    reg = ServiceRegistry()
    d = reg.load_file(ROOT / "agent.yaml")
    assert d.capability == "platform-shell" and d.gxp and d.depends_on == ["gxp-audit-platform"]


def test_portfolio_registry_yaml_becomes_live_catalogue():
    reg = load_registry([FIXTURE])
    gxp = reg.require("gxp-audit-platform")
    assert gxp.canonical_repo == "timjm25/AuditTrailService" and gxp.entities["writes"] == ["AuditEvent", "ESignature"]
    assert reg.require("deviation-management").agent == "qa-compliance"  # no agent.yaml: catalogue-only
    assert not reg.require("ml-ops-monitoring").routable


REAL = Path("/home/claude/portfolio-agent/registry/registry.yaml")


@pytest.mark.skipif(not REAL.exists(), reason="portfolio-agent checkout not available")
def test_full_portfolio_agent_registry_parses():
    reg = load_registry([REAL])
    assert len(reg.list()) == 22


def test_register_heartbeat_and_ttl_expiry():
    clock = Clock()
    reg = ServiceRegistry(default_ttl_seconds=30, clock=clock)
    reg.load_dir(EXAMPLES)
    d = reg.register({"capability": "asset-registry", "base_url": "http://10.0.0.5:5101/", "ttl_seconds": 30})
    assert d.base_url == "http://10.0.0.5:5101" and reg.status("asset-registry") == "up"
    assert d.canonical_repo == "timjm25/AssetProgramRegistry" and d.read_scope == "registry:read"  # merged
    clock.advance(31)
    assert reg.status("asset-registry") == "down"
    reg.heartbeat("asset-registry")
    assert reg.status("asset-registry") == "up"


def test_registration_validation():
    reg = ServiceRegistry()
    reg.load_dir(EXAMPLES)
    with pytest.raises(RegistryError, match="base_url"):
        reg.register({"capability": "new-svc"})
    with pytest.raises(RegistryError, match="http"):
        reg.register({"capability": "new-svc", "base_url": "file:///etc/passwd"})
    with pytest.raises(RegistryError, match="canonical_repo"):
        reg.register({"capability": "asset-registry", "canonical_repo": "timjm25/Impostor",
                      "base_url": "http://x:1"})
    with pytest.raises(RegistryError, match="kebab"):
        descriptor_from_dict({"capability": "Not_Kebab"})
    with pytest.raises(RegistryError):
        reg.heartbeat("never-registered")


def test_health_check_marks_up_and_down():
    reg = load_registry([EXAMPLES])
    transport = WSGITransport({"localhost:5101": echo_service("asset-registry")})
    assert reg.check_health("asset-registry", transport) == "up"
    assert reg.check_health("pharma-event-bus", transport) == "down"
    assert "refused" in reg.require("pharma-event-bus").last_error
    summary = reg.check_all(transport)
    assert summary["asset-registry"] == "up" and summary["program-director"] == "down"

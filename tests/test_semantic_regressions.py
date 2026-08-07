import importlib.util
import ipaddress
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
T = ROOT / "lab" / "telemetry"
TS = "2026-08-07T12:00:00Z"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = _load("semantic_base", T / "generate_corpus.py")
network = _load("semantic_network", T / "network_event_contracts.py")
cloud = _load("semantic_cloud", T / "cloud_saas_event_contracts.py")


def test_pan_traffic_user_columns_do_not_contain_session_identifiers():
    """PAN traffic CSV must preserve documented srcuser/dstuser positions."""
    for _ in range(200):
        fields = network.pan_traffic_record(base, TS).split(",")
        src_user = fields[12]
        dest_user = fields[13]
        session_id = fields[22]

        assert src_user
        assert not src_user.isdigit()
        assert dest_user == "" or not dest_user.isdigit()
        assert session_id.isdigit()
        assert dest_user != session_id


def test_github_audit_has_no_synthetic_ip_placeholder():
    """GitHub audit telemetry must never invent placeholder IP strings."""
    for _ in range(200):
        event = cloud.github_audit_event(base, TS)
        assert not str(event.get("ip_address", "")).startswith("dei-lab-")
        if event.get("actor_ip"):
            ipaddress.ip_address(event["actor_ip"])


def test_salesforce_network_and_session_values_are_realistic():
    """Salesforce ELF values must be valid data, not dei-lab placeholders."""
    for _ in range(200):
        event = cloud.salesforce_event(base, TS)
        ipaddress.ip_address(event["CLIENT_IP"])
        assert event["USER_AGENT"]
        assert not event["USER_AGENT"].startswith("dei-lab-")
        assert event["SESSION_KEY"]
        assert not event["SESSION_KEY"].startswith("dei-lab-")
        int(event["SESSION_KEY"], 16)
        assert event["LOGIN_KEY"]
        assert not event["LOGIN_KEY"].startswith("dei-lab-")
        int(event["LOGIN_KEY"], 16)

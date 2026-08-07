import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "lab" / "telemetry" / "generate_corpus_v2.py"


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_corpus_v2", GENERATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_complete_registry_includes_batch2_verified_sources():
    module = load_generator()
    profiles = module.load_profiles()
    ids = {profile["id"] for profile in profiles}
    assert len(profiles) == 26
    assert {
        "crowdstrike_fdr_sensor",
        "aws_security_hub",
        "azure_activity",
        "cisco_asa",
    }.issubset(ids)


def test_batch2_shapes_are_semantic():
    module = load_generator()
    contracts = module.base.load_value_contracts()
    profiles = {profile["id"]: profile for profile in module.load_profiles()}

    security_hub = module.make_event(
        profiles["aws_security_hub"], "2026-08-07T12:00:00Z", contracts
    )
    assert security_hub["Severity"]["Label"] in {
        "INFORMATIONAL",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }
    assert security_hub["Workflow"]["Status"] in {
        "NEW",
        "NOTIFIED",
        "RESOLVED",
        "SUPPRESSED",
    }

    crowdstrike = module.make_event(
        profiles["crowdstrike_fdr_sensor"], "2026-08-07T12:00:00Z", contracts
    )
    assert crowdstrike["event_simpleName"] in {
        "InjectedThread",
        "ProcessRollup2",
        "NetworkConnectIP4",
        "DnsRequest",
    }


def test_record_format_is_not_claimed_as_wire_native(tmp_path):
    module = load_generator()
    contracts = module.base.load_value_contracts()
    profile = next(p for p in module.load_profiles() if p["id"] == "cisco_asa")
    result = module.write_source(
        profile,
        tmp_path,
        1,
        module.datetime(2026, 8, 1, tzinfo=module.timezone.utc),
        60,
        contracts,
    )
    assert result["record_format"] == "authoritative_searchable_json"

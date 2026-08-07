"""Guardrails for the production-realistic SIEM telemetry source registry."""

import json
from pathlib import Path

REGISTRY_PATH = Path("lab/telemetry/source_registry.json")


def _registry() -> dict[str, object]:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def test_verified_sources_have_authoritative_schema_and_fields() -> None:
    registry = _registry()
    policy = registry["policy"]
    allowed = set(policy["allowed_authorities"])

    verified = [source for source in registry["sources"] if source["status"] == "verified"]
    assert verified

    for source in verified:
        assert source["sourcetypes"], source["id"]
        assert source["target_index"], source["id"]
        assert source["raw_fields"], source["id"]
        assert source["authorities"], source["id"]
        assert any(authority["type"] in allowed for authority in source["authorities"])
        assert all(authority["url"].startswith("https://") for authority in source["authorities"])


def test_pending_sources_cannot_masquerade_as_verified() -> None:
    registry = _registry()
    assert registry["policy"]["generator_requires_status"] == "verified"
    assert registry["policy"]["lab_only_fields_allowed_as_production_truth"] is False

    valid_statuses = {"verified", "pending_research"}
    identifiers: list[str] = []
    for source in registry["sources"]:
        assert source["status"] in valid_statuses
        identifiers.append(source["id"])
    assert len(identifiers) == len(set(identifiers))


def test_high_priority_verified_profiles_are_present() -> None:
    registry = _registry()
    by_id = {source["id"]: source for source in registry["sources"]}
    required = {
        "windows_security",
        "windows_powershell",
        "aws_cloudtrail",
        "aws_guardduty",
        "okta_system_log",
        "m365_management_activity",
        "entra_signin",
        "palo_alto_traffic",
        "zscaler_zia_web",
        "suricata_eve_alert",
    }
    assert required <= set(by_id)
    assert all(by_id[source_id]["status"] == "verified" for source_id in required)


def test_known_addon_sourcetypes_are_exact() -> None:
    registry = _registry()
    by_id = {source["id"]: source for source in registry["sources"]}

    assert by_id["windows_security"]["sourcetypes"] == ["XmlWinEventLog:Security"]
    assert by_id["aws_cloudtrail"]["sourcetypes"] == ["aws:cloudtrail"]
    assert by_id["aws_guardduty"]["sourcetypes"] == ["aws:cloudwatch:guardduty"]
    assert by_id["okta_system_log"]["sourcetypes"] == ["OktaIM2:log"]
    assert by_id["m365_management_activity"]["sourcetypes"] == ["o365:management:activity"]
    assert by_id["entra_signin"]["sourcetypes"] == ["azure:monitor:aad"]
    assert by_id["palo_alto_traffic"]["sourcetypes"] == ["pan:traffic"]
    assert by_id["zscaler_zia_web"]["sourcetypes"] == ["zscalernss-web"]
    assert by_id["suricata_eve_alert"]["sourcetypes"] == ["suricata"]

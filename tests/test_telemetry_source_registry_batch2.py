import json
from pathlib import Path

REGISTRY_PATH = Path("lab/telemetry/source_registry_batch2.json")


def _registry() -> dict[str, object]:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def test_batch2_profiles_are_generator_verified() -> None:
    registry = _registry()
    sources = registry["sources"]
    assert len(sources) == 4
    for source in sources:
        assert source["status"] == "verified"
        assert source["sourcetypes"]
        assert source["raw_fields"]
        assert source["authorities"]
        assert source["ta"]["name"]


def test_batch2_expected_sourcetypes_are_exact() -> None:
    sources = {item["id"]: item for item in _registry()["sources"]}
    assert sources["crowdstrike_fdr_sensor"]["sourcetypes"] == ["crowdstrike:events:sensor"]
    assert sources["aws_security_hub"]["sourcetypes"] == ["aws:securityhub:finding"]
    assert sources["azure_activity"]["sourcetypes"] == ["azure:monitor:activity"]
    assert sources["cisco_asa"]["sourcetypes"] == ["cisco:asa"]


def test_batch2_high_value_fields_are_preserved() -> None:
    sources = {item["id"]: item for item in _registry()["sources"]}
    assert "event_simpleName" in sources["crowdstrike_fdr_sensor"]["raw_fields"]
    assert "Severity" in sources["aws_security_hub"]["raw_fields"]
    assert "operationName" in sources["azure_activity"]["raw_fields"]
    assert "message_id" in sources["cisco_asa"]["raw_fields"]

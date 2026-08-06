"""Tests for DEI telemetry source normalization."""

from dei.telemetry.normalization import normalize_sources


def test_vendor_aliases_map_to_canonical_capabilities() -> None:
    result = normalize_sources([
        "zscaler:web", "OktaIM2:log", "crowdstrike:events:sensor",
        "linux_secure", "WinEventLog:Security",
    ])
    assert result.canonical_sources == (
        "proxy", "identity.authentication", "endpoint.edr",
        "linux.authentication", "XmlWinEventLog:Security",
    )
    assert result.unmapped_sources == ()
    assert all(mapping.status == "mapped_alias" for mapping in result.mappings)


def test_enterprise_security_sources_map_to_capabilities() -> None:
    result = normalize_sources([
        "cisco:asa", "cisco:ios", "stream:dns", "cdcc:edr",
        "otx:indicator", "otx:pulse", "modular_alerts:risk", "access_combined",
    ])
    assert result.canonical_sources == (
        "network.firewall", "network.infrastructure", "network.dns",
        "endpoint.edr", "threat_intelligence", "es.risk", "web.http",
    )
    assert result.unmapped_sources == ()


def test_ambiguous_generic_sources_remain_unmapped() -> None:
    result = normalize_sources(["stash", "json"])
    assert result.unmapped_sources == ("stash", "json")
    assert all(mapping.confidence == 0 for mapping in result.mappings)


def test_unknown_sources_are_retained_and_marked_unmapped() -> None:
    result = normalize_sources(["vendor:new:telemetry"])
    assert result.canonical_sources == ("vendor:new:telemetry",)
    assert result.unmapped_sources == ("vendor:new:telemetry",)
    assert result.mappings[0].status == "unmapped"
    assert result.mappings[0].confidence == 0


def test_normalization_is_case_insensitive_and_deduplicates_observed_sources() -> None:
    result = normalize_sources(["AWS:CLOUDTRAIL", "aws:cloudtrail", ""])
    assert result.canonical_sources == ("aws:cloudtrail",)
    assert len(result.mappings) == 1
    assert result.unmapped_sources == ()

"""Tests for DEI telemetry source normalization."""

from dei.telemetry.normalization import normalize_sources


def test_vendor_aliases_map_to_canonical_capabilities() -> None:
    result = normalize_sources([
        "zscaler:web", "OktaIM2:log", "crowdstrike:events:sensor",
        "linux_secure", "WinEventLog:Security",
    ])
    assert result.canonical_sources == (
        "proxy", "identity.authentication", "endpoint.edr",
        "endpoint.process", "network.dns", "linux.authentication",
        "XmlWinEventLog:Security",
    )
    assert result.unmapped_sources == ()
    assert all(mapping.status == "mapped_alias" for mapping in result.mappings)


def test_enterprise_security_sources_map_to_capabilities() -> None:
    result = normalize_sources([
        "cisco:asa", "cisco:ios", "stream:dns", "cdcc:edr",
        "otx:indicator", "otx:pulse", "modular_alerts:risk", "access_combined",
    ])
    assert result.canonical_sources == (
        "network.firewall", "network.traffic", "network.infrastructure", "network.dns",
        "endpoint.edr", "threat_intelligence", "es.risk", "web.http",
    )
    assert result.unmapped_sources == ()


def test_26_source_ta_aliases_are_understood() -> None:
    result = normalize_sources([
        "aws:cloudwatch:guardduty",
        "aws:cloudwatchlogs:vpcflow",
        "aws:cloudwatchlogs:route53",
        "aws:securityhub:finding",
        "o365:management:activity",
        "o365:reporting:messagetrace",
        "azure:monitor:aad",
        "azure:monitor:activity",
        "m365:defender:incident:advanced_hunting",
        "google:gcp:pubsub:audit:admin_activity",
        "gws:reports:admin",
        "pan:traffic",
        "pan:threat",
        "zscalernss-web",
        "suricata",
        "auditd",
        "kube:audit",
        "github:audit",
        "cloudflare:http",
        "sfdc:logfile",
    ])
    assert result.unmapped_sources == ()
    expected = {
        "aws.guardduty",
        "network.dns",
        "network.firewall",
        "network.traffic",
        "cloud.security_finding",
        "intrusion_detection",
        "m365.activity",
        "email.message_trace",
        "identity.authentication",
        "cloud.change",
        "endpoint.edr",
        "endpoint.process",
        "endpoint.authentication",
        "gcp.audit",
        "google.workspace.admin",
        "identity.change",
        "proxy",
        "web.http",
        "linux.authentication",
        "kubernetes.audit",
        "source_control.audit",
        "salesforce.audit",
    }
    assert expected <= set(result.canonical_sources)


def test_multi_capability_mapping_is_explainable() -> None:
    result = normalize_sources(["zscalernss-web", "pan:threat"])
    zscaler = result.mappings[0]
    assert zscaler.canonical_source == "proxy"
    assert zscaler.additional_canonical_sources == (
        "web.http", "network.traffic", "intrusion_detection"
    )
    pan = result.mappings[1]
    assert pan.canonical_source == "intrusion_detection"
    assert pan.additional_canonical_sources == ("web.http",)


def test_generic_xmlwineventlog_does_not_fake_channel_specific_readiness() -> None:
    result = normalize_sources(["XmlWinEventLog"])
    assert result.canonical_sources == ("windows.eventlog",)
    assert result.unmapped_sources == ()
    assert result.mappings[0].confidence == 70
    assert "XmlWinEventLog:Security" not in result.canonical_sources
    assert "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" not in result.canonical_sources


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

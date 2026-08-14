"""Tests for DEI telemetry source normalization."""

from dei_intelligence.telemetry.normalization import normalize_sources


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


def test_new_ta_sources_map_to_runtime_validated_primary_capabilities() -> None:
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
        "crowdstrike:events:sensor",
    ])
    assert result.unmapped_sources == ()
    expected = {
        "aws.guardduty", "network.firewall", "network.dns", "aws.securityhub",
        "m365.activity", "email.message_trace", "identity.authentication",
        "azure.activity", "endpoint.edr", "gcp.audit", "google_workspace.admin",
        "web.http", "network.ids", "linux.authentication", "kubernetes.audit",
        "github.audit", "salesforce.event_monitoring",
    }
    assert expected <= set(result.canonical_sources)


def test_multi_capability_sources_keep_primary_contract_and_expose_secondary() -> None:
    result = normalize_sources(["pan:threat", "zscalernss-web", "auditd"])
    assert result.canonical_sources == (
        "network.ids", "web.http", "linux.authentication"
    )
    pan, zscaler, auditd = result.mappings
    assert pan.additional_canonical_sources == ("web.http",)
    assert zscaler.additional_canonical_sources == ("network.firewall", "network.ids")
    assert auditd.additional_canonical_sources == ("endpoint.process",)


def test_generic_xmlwineventlog_stays_broad_and_conservative() -> None:
    result = normalize_sources(["XmlWinEventLog"])
    assert result.canonical_sources == ("windows.eventlog",)
    assert result.unmapped_sources == ()
    assert result.mappings[0].confidence == 70
    assert result.mappings[0].status == "mapped_alias"


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

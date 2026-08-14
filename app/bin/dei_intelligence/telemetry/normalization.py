"""Telemetry source normalization for DEI recommendation analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class SourceMapping:
    """Explain how one observed Splunk sourcetype is interpreted by DEI."""

    observed_source: str
    canonical_source: str
    status: str
    confidence: int
    reason: str
    additional_canonical_sources: tuple[str, ...] = ()

    def to_mapping(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class NormalizationResult:
    """Normalized source inventory used by the recommendation engine."""

    canonical_sources: tuple[str, ...]
    mappings: tuple[SourceMapping, ...]
    unmapped_sources: tuple[str, ...]


# Exact aliases stay conservative. Each alias defines a primary canonical token
# for backward compatibility plus optional additional capabilities validated from
# vendor TA/runtime evidence.
_EXACT_ALIASES: dict[str, tuple[str, tuple[str, ...], int, str]] = {
    "wineventlog:security": (
        "XmlWinEventLog:Security", (), 100, "Windows Security event-log alias"
    ),
    "xmlwineventlog": (
        "windows.eventlog",
        (),
        70,
        "Generic rendered Windows Event Log XML; channel context required for Security/PowerShell readiness",
    ),
    "zscaler:web": (
        "proxy",
        ("web.http", "network.firewall"),
        100,
        "Zscaler web telemetry provides proxy, web, and network-security capabilities",
    ),
    "zscalernss-web": (
        "web.http",
        ("network.firewall", "network.ids"),
        100,
        "Zscaler NSS web telemetry provides web, network traffic, and threat context",
    ),
    "oktaim2:log": (
        "identity.authentication", (), 100, "Okta System Log provides identity and authentication telemetry"
    ),
    "crowdstrike:events:sensor": (
        "endpoint.edr",
        ("network.dns",),
        100,
        "CrowdStrike sensor events provide endpoint, process, and DNS telemetry",
    ),
    "linux_secure": (
        "linux.authentication", (), 100, "Linux secure/auth logs provide authentication and privilege telemetry"
    ),
    "auditd": (
        "linux.authentication",
        ("endpoint.process",),
        95,
        "Linux auditd provides authentication and process/syscall telemetry",
    ),
    "cisco:asa": (
        "network.firewall", (), 100, "Cisco ASA telemetry provides firewall and network-security events"
    ),
    "cisco:ios": (
        "network.infrastructure", (), 100, "Cisco IOS telemetry provides network infrastructure events"
    ),
    "stream:dns": (
        "network.dns", (), 100, "Splunk Stream DNS telemetry provides DNS activity"
    ),
    "cdcc:edr": (
        "endpoint.edr", (), 90, "Known lab EDR sourcetype provides endpoint security telemetry"
    ),
    "otx:indicator": (
        "threat_intelligence", (), 100, "OTX indicator telemetry provides threat-intelligence observables"
    ),
    "otx:pulse": (
        "threat_intelligence", (), 100, "OTX pulse telemetry provides threat-intelligence context"
    ),
    "modular_alerts:risk": (
        "es.risk", (), 100, "Enterprise Security risk events provide risk-based alerting telemetry"
    ),
    "access_combined": (
        "web.http", (), 95, "Combined web access logs provide HTTP request telemetry"
    ),
    "aws:cloudwatch:guardduty": (
        "aws.guardduty",
        ("network.ids",),
        100,
        "GuardDuty finding telemetry provides AWS threat-detection context",
    ),
    "aws:cloudwatchlogs:vpcflow": (
        "network.firewall", (), 100, "AWS VPC Flow Logs provide network traffic and allow/deny telemetry"
    ),
    "aws:cloudwatchlogs:route53": (
        "network.dns", (), 100, "Route 53 Resolver query logs provide DNS telemetry"
    ),
    "aws:securityhub:finding": (
        "aws.securityhub",
        ("network.ids",),
        100,
        "AWS Security Hub findings provide normalized security findings",
    ),
    "o365:management:activity": (
        "m365.activity",
        ("identity.authentication",),
        100,
        "Microsoft 365 Management Activity provides audit, authentication, and change telemetry",
    ),
    "o365:reporting:messagetrace": (
        "email.message_trace", (), 100, "Microsoft 365 Message Trace provides email-delivery telemetry"
    ),
    "azure:monitor:aad": (
        "identity.authentication", (), 100, "Microsoft Entra sign-in telemetry provides identity and authentication events"
    ),
    "azure:monitor:activity": (
        "azure.activity", (), 100, "Azure Activity Log provides cloud control-plane change telemetry"
    ),
    "m365:defender:incident:advanced_hunting": (
        "endpoint.edr",
        ("identity.authentication", "network.firewall"),
        100,
        "Microsoft Defender Advanced Hunting provides endpoint, authentication, and network telemetry",
    ),
    "google:gcp:pubsub:audit:admin_activity": (
        "gcp.audit", (), 100, "Google Cloud Admin Activity audit logs provide control-plane change telemetry"
    ),
    "gws:reports:admin": (
        "google_workspace.admin", (), 100, "Google Workspace Admin audit logs provide SaaS administration telemetry"
    ),
    "pan:traffic": (
        "network.firewall", (), 100, "PAN-OS Traffic logs provide network traffic and policy-action telemetry"
    ),
    "pan:threat": (
        "network.ids", ("web.http",), 100, "PAN-OS Threat logs provide intrusion and web-threat telemetry"
    ),
    "suricata": (
        "network.ids", (), 100, "Suricata EVE alerts provide network intrusion telemetry"
    ),
    "kube:audit": (
        "kubernetes.audit", (), 100, "Kubernetes audit events provide cluster control-plane activity"
    ),
    "github:audit": (
        "github.audit", (), 100, "GitHub audit logs provide repository and organization administration telemetry"
    ),
    "cloudflare:http": (
        "web.http", (), 100, "Cloudflare HTTP logs provide edge web-request telemetry"
    ),
    "sfdc:logfile": (
        "salesforce.event_monitoring",
        ("identity.authentication",),
        100,
        "Salesforce Event Monitoring provides SaaS authentication and activity telemetry",
    ),
}

_CANONICAL_SOURCES = {
    "xmlwineventlog:security": "XmlWinEventLog:Security",
    "xmlwineventlog:microsoft-windows-powershell/operational": "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational",
    "aws:cloudtrail": "aws:cloudtrail",
    "proxy": "proxy",
    "ai:gateway": "ai:gateway",
    "dlp": "dlp",
    "azure:openai:diagnostic": "azure:openai:diagnostic",
    "gcp:audit:vertexai": "gcp:audit:vertexai",
    "identity.authentication": "identity.authentication",
    "endpoint.edr": "endpoint.edr",
    "linux.authentication": "linux.authentication",
    "network.firewall": "network.firewall",
    "network.infrastructure": "network.infrastructure",
    "network.dns": "network.dns",
    "network.ids": "network.ids",
    "endpoint.process": "endpoint.process",
    "threat_intelligence": "threat_intelligence",
    "es.risk": "es.risk",
    "web.http": "web.http",
    "aws.guardduty": "aws.guardduty",
    "aws.securityhub": "aws.securityhub",
    "m365.activity": "m365.activity",
    "email.message_trace": "email.message_trace",
    "azure.activity": "azure.activity",
    "gcp.audit": "gcp.audit",
    "google_workspace.admin": "google_workspace.admin",
    "kubernetes.audit": "kubernetes.audit",
    "github.audit": "github.audit",
    "salesforce.event_monitoring": "salesforce.event_monitoring",
    "windows.eventlog": "windows.eventlog",
}


def normalize_sources(observed_sources: list[str]) -> NormalizationResult:
    """Normalize discovered sourcetypes while retaining explainability."""
    seen_observed: set[str] = set()
    canonical: list[str] = []
    canonical_seen: set[str] = set()
    mappings: list[SourceMapping] = []
    unmapped: list[str] = []

    for raw_source in observed_sources:
        source = raw_source.strip()
        if not source:
            continue
        key = source.lower()
        if key in seen_observed:
            continue
        seen_observed.add(key)

        alias = _EXACT_ALIASES.get(key)
        if alias is not None:
            canonical_source, additional, confidence, reason = alias
            mapping = SourceMapping(
                source, canonical_source, "mapped_alias", confidence, reason, additional
            )
        elif key in _CANONICAL_SOURCES:
            canonical_source = _CANONICAL_SOURCES[key]
            mapping = SourceMapping(
                source,
                canonical_source,
                "canonical",
                100,
                "Source already matches a DEI canonical telemetry token",
            )
        else:
            canonical_source = source
            mapping = SourceMapping(
                source, source, "unmapped", 0, "No DEI telemetry mapping is currently defined"
            )
            unmapped.append(source)

        canonical_key = canonical_source.lower()
        if canonical_key not in canonical_seen:
            canonical_seen.add(canonical_key)
            canonical.append(canonical_source)
        mappings.append(mapping)

    return NormalizationResult(tuple(canonical), tuple(mappings), tuple(unmapped))

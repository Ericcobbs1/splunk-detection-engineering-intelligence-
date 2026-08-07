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


# Primary aliases remain conservative and explainable. Some TA sourcetypes also
# advertise additional capabilities because one telemetry stream can satisfy
# multiple detection domains (for example Zscaler web or PAN threat telemetry).
_EXACT_ALIASES: dict[str, tuple[str, int, str]] = {
    "wineventlog:security": ("XmlWinEventLog:Security", 100, "Windows Security event-log alias"),
    "xmlwineventlog": ("windows.eventlog", 70, "Generic Windows XML event-log telemetry requires channel or index context for detection-specific routing"),
    "zscaler:web": ("proxy", 100, "Zscaler web telemetry satisfies the proxy capability"),
    "zscalernss-web": ("proxy", 100, "Zscaler NSS web telemetry provides proxy and web-security activity"),
    "oktaim2:log": ("identity.authentication", 100, "Okta System Log provides identity and authentication telemetry"),
    "crowdstrike:events:sensor": ("endpoint.edr", 100, "CrowdStrike sensor events provide endpoint/EDR telemetry"),
    "m365:defender:incident:advanced_hunting": ("endpoint.edr", 100, "Microsoft Defender Advanced Hunting provides endpoint/EDR telemetry"),
    "linux_secure": ("linux.authentication", 100, "Linux secure/auth logs provide authentication and privilege telemetry"),
    "auditd": ("linux.authentication", 95, "Linux auditd provides authentication, process, and privilege telemetry"),
    "cisco:asa": ("network.firewall", 100, "Cisco ASA telemetry provides firewall and network-security events"),
    "cisco:ios": ("network.infrastructure", 100, "Cisco IOS telemetry provides network infrastructure events"),
    "stream:dns": ("network.dns", 100, "Splunk Stream DNS telemetry provides DNS activity"),
    "aws:cloudwatchlogs:route53": ("network.dns", 100, "Route 53 query logs provide authoritative DNS activity"),
    "aws:cloudwatchlogs:vpcflow": ("network.traffic", 100, "AWS VPC Flow Logs provide network-flow telemetry"),
    "aws:cloudwatch:guardduty": ("aws.guardduty", 100, "GuardDuty findings provide AWS threat-detection telemetry"),
    "aws:securityhub:finding": ("cloud.security_finding", 100, "AWS Security Hub findings provide cloud security findings"),
    "o365:management:activity": ("m365.activity", 100, "Microsoft 365 Management Activity provides SaaS audit/change telemetry"),
    "o365:reporting:messagetrace": ("email.message_trace", 100, "Microsoft 365 Message Trace provides email-flow telemetry"),
    "azure:monitor:aad": ("identity.authentication", 100, "Microsoft Entra sign-in telemetry provides identity authentication activity"),
    "azure:monitor:activity": ("cloud.change", 100, "Azure Activity Logs provide cloud administrative change telemetry"),
    "google:gcp:pubsub:audit:admin_activity": ("gcp.audit", 100, "Google Cloud Admin Activity audit logs provide cloud-change telemetry"),
    "google:gcp:pubsub:message": ("gcp.audit", 80, "Legacy/generic GCP Pub/Sub audit telemetry requires granular audit sourcetype normalization when available"),
    "gws:reports:admin": ("google.workspace.admin", 100, "Google Workspace Admin audit telemetry provides SaaS administrative activity"),
    "pan:traffic": ("network.firewall", 100, "PAN-OS Traffic logs provide firewall and network-flow telemetry"),
    "pan:threat": ("intrusion_detection", 100, "PAN-OS Threat logs provide intrusion and threat telemetry"),
    "suricata": ("intrusion_detection", 100, "Suricata EVE alerts provide IDS telemetry"),
    "kube:audit": ("kubernetes.audit", 100, "Kubernetes Audit logs provide cluster administrative and access telemetry"),
    "github:audit": ("source_control.audit", 100, "GitHub audit logs provide source-control administrative activity"),
    "cloudflare:http": ("web.http", 100, "Cloudflare HTTP logs provide web request and edge-security telemetry"),
    "sfdc:logfile": ("salesforce.audit", 100, "Salesforce Event Monitoring provides SaaS audit activity"),
    "cdcc:edr": ("endpoint.edr", 90, "Known lab EDR sourcetype provides endpoint security telemetry"),
    "otx:indicator": ("threat_intelligence", 100, "OTX indicator telemetry provides threat-intelligence observables"),
    "otx:pulse": ("threat_intelligence", 100, "OTX pulse telemetry provides threat-intelligence context"),
    "modular_alerts:risk": ("es.risk", 100, "Enterprise Security risk events provide risk-based alerting telemetry"),
    "access_combined": ("web.http", 95, "Combined web access logs provide HTTP request telemetry"),
}

_ADDITIONAL_CAPABILITIES: dict[str, tuple[str, ...]] = {
    "zscalernss-web": ("web.http", "network.traffic", "intrusion_detection"),
    "crowdstrike:events:sensor": ("endpoint.process", "network.dns"),
    "m365:defender:incident:advanced_hunting": ("endpoint.process", "endpoint.authentication", "network.traffic"),
    "auditd": ("endpoint.process",),
    "cisco:asa": ("network.traffic",),
    "aws:cloudwatchlogs:vpcflow": ("network.firewall",),
    "aws:cloudwatch:guardduty": ("intrusion_detection",),
    "aws:securityhub:finding": ("intrusion_detection",),
    "o365:management:activity": ("identity.change", "cloud.change"),
    "o365:reporting:messagetrace": ("email",),
    "azure:monitor:activity": ("identity.change",),
    "google:gcp:pubsub:audit:admin_activity": ("cloud.change",),
    "gws:reports:admin": ("identity.change",),
    "pan:traffic": ("network.traffic",),
    "pan:threat": ("web.http",),
    "suricata": ("network.traffic",),
    "sfdc:logfile": ("identity.authentication", "cloud.change"),
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
    "threat_intelligence": "threat_intelligence",
    "es.risk": "es.risk",
    "web.http": "web.http",
}


def _append_canonical(
    canonical: list[str], canonical_seen: set[str], source: str
) -> None:
    key = source.lower()
    if key not in canonical_seen:
        canonical_seen.add(key)
        canonical.append(source)


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
            canonical_source, confidence, reason = alias
            extras = _ADDITIONAL_CAPABILITIES.get(key, ())
            mapping = SourceMapping(
                source,
                canonical_source,
                "mapped_alias",
                confidence,
                reason,
                extras,
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
                source,
                source,
                "unmapped",
                0,
                "No DEI telemetry mapping is currently defined",
            )
            unmapped.append(source)

        _append_canonical(canonical, canonical_seen, canonical_source)
        for extra in mapping.additional_canonical_sources:
            _append_canonical(canonical, canonical_seen, extra)
        mappings.append(mapping)

    return NormalizationResult(tuple(canonical), tuple(mappings), tuple(unmapped))

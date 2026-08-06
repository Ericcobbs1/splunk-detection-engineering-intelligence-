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

    def to_mapping(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class NormalizationResult:
    """Normalized source inventory used by the recommendation engine."""

    canonical_sources: tuple[str, ...]
    mappings: tuple[SourceMapping, ...]
    unmapped_sources: tuple[str, ...]


# Exact aliases stay conservative: ambiguous generic sourcetypes are intentionally
# left unmapped until field/CIM-aware inference is available.
_EXACT_ALIASES: dict[str, tuple[str, int, str]] = {
    "wineventlog:security": ("XmlWinEventLog:Security", 100, "Windows Security event-log alias"),
    "zscaler:web": ("proxy", 100, "Zscaler web telemetry satisfies the proxy capability"),
    "oktaim2:log": ("identity.authentication", 100, "Okta System Log provides identity and authentication telemetry"),
    "crowdstrike:events:sensor": ("endpoint.edr", 100, "CrowdStrike sensor events provide endpoint/EDR telemetry"),
    "linux_secure": ("linux.authentication", 100, "Linux secure/auth logs provide authentication and privilege telemetry"),
    "cisco:asa": ("network.firewall", 100, "Cisco ASA telemetry provides firewall and network-security events"),
    "cisco:ios": ("network.infrastructure", 100, "Cisco IOS telemetry provides network infrastructure events"),
    "stream:dns": ("network.dns", 100, "Splunk Stream DNS telemetry provides DNS activity"),
    "cdcc:edr": ("endpoint.edr", 90, "Known lab EDR sourcetype provides endpoint security telemetry"),
    "otx:indicator": ("threat_intelligence", 100, "OTX indicator telemetry provides threat-intelligence observables"),
    "otx:pulse": ("threat_intelligence", 100, "OTX pulse telemetry provides threat-intelligence context"),
    "modular_alerts:risk": ("es.risk", 100, "Enterprise Security risk events provide risk-based alerting telemetry"),
    "access_combined": ("web.http", 95, "Combined web access logs provide HTTP request telemetry"),
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
            mapping = SourceMapping(source, canonical_source, "mapped_alias", confidence, reason)
        elif key in _CANONICAL_SOURCES:
            canonical_source = _CANONICAL_SOURCES[key]
            mapping = SourceMapping(source, canonical_source, "canonical", 100, "Source already matches a DEI canonical telemetry token")
        else:
            canonical_source = source
            mapping = SourceMapping(source, source, "unmapped", 0, "No DEI telemetry mapping is currently defined")
            unmapped.append(source)

        canonical_key = canonical_source.lower()
        if canonical_key not in canonical_seen:
            canonical_seen.add(canonical_key)
            canonical.append(canonical_source)
        mappings.append(mapping)

    return NormalizationResult(tuple(canonical), tuple(mappings), tuple(unmapped))

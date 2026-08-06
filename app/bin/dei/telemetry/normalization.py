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
        """Return a JSON-compatible representation."""
        return asdict(self)


@dataclass(frozen=True)
class NormalizationResult:
    """Normalized source inventory used by the recommendation engine."""

    canonical_sources: tuple[str, ...]
    mappings: tuple[SourceMapping, ...]
    unmapped_sources: tuple[str, ...]


# Exact aliases are intentionally conservative. Pattern/field/CIM inference can be
# layered on later without changing the recommendation-engine contract.
_EXACT_ALIASES: dict[str, tuple[str, int, str]] = {
    "wineventlog:security": (
        "XmlWinEventLog:Security",
        100,
        "Windows Security event-log alias",
    ),
    "zscaler:web": (
        "proxy",
        100,
        "Zscaler web telemetry satisfies the proxy capability",
    ),
    "oktaim2:log": (
        "identity.authentication",
        100,
        "Okta System Log provides identity and authentication telemetry",
    ),
    "crowdstrike:events:sensor": (
        "endpoint.edr",
        100,
        "CrowdStrike sensor events provide endpoint/EDR telemetry",
    ),
    "linux_secure": (
        "linux.authentication",
        100,
        "Linux secure/auth logs provide authentication and privilege telemetry",
    ),
}

# These are already canonical tokens used by current detection content or by the
# capability model being introduced for future knowledge packs.
_CANONICAL_SOURCES = {
    "xmlwineventlog:security": "XmlWinEventLog:Security",
    "xmlwineventlog:microsoft-windows-powershell/operational": (
        "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
    ),
    "aws:cloudtrail": "aws:cloudtrail",
    "proxy": "proxy",
    "ai:gateway": "ai:gateway",
    "dlp": "dlp",
    "azure:openai:diagnostic": "azure:openai:diagnostic",
    "gcp:audit:vertexai": "gcp:audit:vertexai",
    "identity.authentication": "identity.authentication",
    "endpoint.edr": "endpoint.edr",
    "linux.authentication": "linux.authentication",
}


def normalize_sources(observed_sources: list[str]) -> NormalizationResult:
    """Normalize discovered sourcetypes while retaining explainability.

    Unknown sourcetypes remain visible to DEI and are explicitly marked as
    unmapped. They are not silently discarded.
    """
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
            mapping = SourceMapping(
                observed_source=source,
                canonical_source=canonical_source,
                status="mapped_alias",
                confidence=confidence,
                reason=reason,
            )
        elif key in _CANONICAL_SOURCES:
            canonical_source = _CANONICAL_SOURCES[key]
            mapping = SourceMapping(
                observed_source=source,
                canonical_source=canonical_source,
                status="canonical",
                confidence=100,
                reason="Source already matches a DEI canonical telemetry token",
            )
        else:
            canonical_source = source
            mapping = SourceMapping(
                observed_source=source,
                canonical_source=source,
                status="unmapped",
                confidence=0,
                reason="No DEI telemetry mapping is currently defined",
            )
            unmapped.append(source)

        canonical_key = canonical_source.lower()
        if canonical_key not in canonical_seen:
            canonical_seen.add(canonical_key)
            canonical.append(canonical_source)
        mappings.append(mapping)

    return NormalizationResult(
        canonical_sources=tuple(canonical),
        mappings=tuple(mappings),
        unmapped_sources=tuple(unmapped),
    )

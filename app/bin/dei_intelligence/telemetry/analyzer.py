"""Telemetry-to-capability analysis for DEI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dei_intelligence.knowledgepacks.models import KnowledgePack


@dataclass(frozen=True)
class TelemetryAnalysis:
    """Serializable result of matching observed sources to Knowledge Packs."""

    observed_sources: tuple[str, ...]
    matched_sources: tuple[str, ...]
    unmatched_sources: tuple[str, ...]
    matched_packs: tuple[str, ...]
    enabled_capabilities: tuple[str, ...]
    missing_required_sources: tuple[str, ...]
    source_coverage_percent: float

    def to_mapping(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""
        return {
            "observed_sources": list(self.observed_sources),
            "matched_sources": list(self.matched_sources),
            "unmatched_sources": list(self.unmatched_sources),
            "matched_packs": list(self.matched_packs),
            "enabled_capabilities": list(self.enabled_capabilities),
            "missing_required_sources": list(self.missing_required_sources),
            "source_coverage_percent": self.source_coverage_percent,
        }


class TelemetryAnalyzer:
    """Determine detection capabilities enabled by observed telemetry sources."""

    def analyze(
        self,
        observed_sources: tuple[str, ...],
        packs: tuple[KnowledgePack, ...],
    ) -> TelemetryAnalysis:
        """Match normalized source names against installed Knowledge Packs."""
        observed = tuple(sorted({source.strip() for source in observed_sources if source.strip()}))
        supported = {
            source
            for pack in packs
            for source in pack.manifest.supported_sources
        }
        matched = tuple(sorted(set(observed) & supported))
        unmatched = tuple(sorted(set(observed) - supported))

        matched_pack_objects = tuple(
            pack
            for pack in packs
            if set(pack.manifest.supported_sources) & set(matched)
        )
        matched_packs = tuple(sorted(pack.manifest.pack_id for pack in matched_pack_objects))
        capabilities = tuple(
            sorted(
                {
                    capability
                    for pack in matched_pack_objects
                    for capability in pack.manifest.capabilities
                }
            )
        )
        required = {
            source
            for pack in matched_pack_objects
            for source in pack.manifest.supported_sources
        }
        missing = tuple(sorted(required - set(matched)))
        coverage = 0.0 if not supported else round((len(matched) / len(supported)) * 100, 2)

        return TelemetryAnalysis(
            observed_sources=observed,
            matched_sources=matched,
            unmatched_sources=unmatched,
            matched_packs=matched_packs,
            enabled_capabilities=capabilities,
            missing_required_sources=missing,
            source_coverage_percent=coverage,
        )

"""Data-driven detection recommendation engine for DEI."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


class RecommendationError(ValueError):
    """Raised when the detection catalog or request is invalid."""


@dataclass(frozen=True)
class DetectionOpportunity:
    """One validated, data-driven detection opportunity."""

    detection_id: str
    name: str
    pack_id: str
    capability: str
    required_sources: tuple[str, ...]
    priority: int
    severity: str
    mitre_techniques: tuple[str, ...]
    why: str
    implementation: str
    requires_enterprise_security: bool

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> DetectionOpportunity:
        """Validate and construct a detection opportunity."""
        required = {
            "id",
            "name",
            "pack_id",
            "capability",
            "required_sources",
            "priority",
            "severity",
            "mitre_techniques",
            "why",
            "implementation",
            "requires_enterprise_security",
        }
        missing = sorted(required - value.keys())
        if missing:
            raise RecommendationError(f"Detection catalog entry missing: {', '.join(missing)}")

        priority = value["priority"]
        if not isinstance(priority, int) or not 0 <= priority <= 100:
            raise RecommendationError("Detection priority must be an integer from 0 to 100")

        severity = str(value["severity"]).lower()
        if severity not in {"low", "medium", "high", "critical"}:
            raise RecommendationError(f"Unsupported severity: {severity}")

        required_sources = tuple(str(item).strip() for item in value["required_sources"])
        if not required_sources or any(not item for item in required_sources):
            raise RecommendationError("Detection required_sources must not be empty")

        return cls(
            detection_id=str(value["id"]),
            name=str(value["name"]),
            pack_id=str(value["pack_id"]),
            capability=str(value["capability"]),
            required_sources=required_sources,
            priority=priority,
            severity=severity,
            mitre_techniques=tuple(str(item) for item in value["mitre_techniques"]),
            why=str(value["why"]),
            implementation=str(value["implementation"]),
            requires_enterprise_security=bool(value["requires_enterprise_security"]),
        )


@dataclass(frozen=True)
class DetectionRecommendation:
    """Explainable recommendation produced for observed telemetry."""

    detection_id: str
    name: str
    pack_id: str
    capability: str
    readiness: str
    score: int
    severity: str
    observed_sources: tuple[str, ...]
    missing_sources: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    why: str
    implementation: str
    requires_enterprise_security: bool

    def to_mapping(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""
        return asdict(self)


@dataclass(frozen=True)
class RecommendationReport:
    """Summary and ranked recommendations for one telemetry assessment."""

    observed_source_count: int
    production_ready_count: int
    partial_count: int
    unsupported_count: int
    recommendations: tuple[DetectionRecommendation, ...]

    def to_mapping(self) -> dict[str, Any]:
        """Return a JSON-compatible report."""
        return {
            "observed_source_count": self.observed_source_count,
            "production_ready_count": self.production_ready_count,
            "partial_count": self.partial_count,
            "unsupported_count": self.unsupported_count,
            "recommendations": [item.to_mapping() for item in self.recommendations],
        }


class RecommendationEngine:
    """Rank detection opportunities using observed telemetry and readiness."""

    def __init__(self, opportunities: tuple[DetectionOpportunity, ...]) -> None:
        if not opportunities:
            raise RecommendationError("Detection catalog must contain at least one entry")
        identifiers = [item.detection_id for item in opportunities]
        if len(identifiers) != len(set(identifiers)):
            raise RecommendationError("Detection catalog contains duplicate IDs")
        self._opportunities = opportunities

    @classmethod
    def from_catalog(cls, catalog_path: Path) -> RecommendationEngine:
        """Load and validate a JSON detection catalog."""
        try:
            raw = json.loads(catalog_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RecommendationError(f"Unable to load detection catalog: {exc}") from exc
        if not isinstance(raw, list):
            raise RecommendationError("Detection catalog must be a JSON array")
        opportunities = tuple(
            DetectionOpportunity.from_mapping(item)
            for item in raw
            if isinstance(item, dict)
        )
        if len(opportunities) != len(raw):
            raise RecommendationError("Every detection catalog entry must be an object")
        return cls(opportunities)

    def recommend(
        self,
        observed_sources: list[str],
        *,
        enterprise_security_enabled: bool = False,
        include_unsupported: bool = False,
    ) -> RecommendationReport:
        """Return ranked detection recommendations for observed source names."""
        normalized = {source.strip().lower() for source in observed_sources if source.strip()}
        recommendations: list[DetectionRecommendation] = []
        ready = partial = unsupported = 0

        for opportunity in self._opportunities:
            required = {source.lower() for source in opportunity.required_sources}
            observed = tuple(
                source
                for source in opportunity.required_sources
                if source.lower() in normalized
            )
            missing = tuple(
                source
                for source in opportunity.required_sources
                if source.lower() not in normalized
            )
            matched_count = len(observed)
            if matched_count == len(required):
                readiness = "production_ready"
                readiness_points = 20
                ready += 1
            elif matched_count:
                readiness = "partial"
                readiness_points = 5
                partial += 1
            else:
                readiness = "unsupported"
                readiness_points = -25
                unsupported += 1

            if opportunity.requires_enterprise_security and not enterprise_security_enabled:
                readiness = "requires_enterprise_security"
                readiness_points = -10

            if readiness == "unsupported" and not include_unsupported:
                continue

            score = max(0, min(100, opportunity.priority + readiness_points))
            recommendations.append(
                DetectionRecommendation(
                    detection_id=opportunity.detection_id,
                    name=opportunity.name,
                    pack_id=opportunity.pack_id,
                    capability=opportunity.capability,
                    readiness=readiness,
                    score=score,
                    severity=opportunity.severity,
                    observed_sources=observed,
                    missing_sources=missing,
                    mitre_techniques=opportunity.mitre_techniques,
                    why=opportunity.why,
                    implementation=opportunity.implementation,
                    requires_enterprise_security=opportunity.requires_enterprise_security,
                )
            )

        recommendations.sort(key=lambda item: (-item.score, item.name.lower()))
        return RecommendationReport(
            observed_source_count=len(normalized),
            production_ready_count=ready,
            partial_count=partial,
            unsupported_count=unsupported,
            recommendations=tuple(recommendations),
        )

"""Data-driven detection recommendation engine for DEI."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from dei.telemetry.normalization import SourceMapping, normalize_sources


class RecommendationError(ValueError):
    """Raised when the detection catalog or request is invalid."""


@dataclass(frozen=True)
class DetectionOpportunity:
    detection_id: str
    name: str
    pack_id: str
    capability: str
    required_sources: tuple[str, ...]
    required_fields: dict[str, tuple[tuple[str, ...], ...]]
    priority: int
    severity: str
    mitre_techniques: tuple[str, ...]
    why: str
    implementation: str
    requires_enterprise_security: bool

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "DetectionOpportunity":
        required = {
            "id", "name", "pack_id", "capability", "required_sources",
            "priority", "severity", "mitre_techniques", "why",
            "implementation", "requires_enterprise_security",
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

        field_requirements: dict[str, tuple[tuple[str, ...], ...]] = {}
        raw_fields = value.get("required_fields", {})
        if not isinstance(raw_fields, dict):
            raise RecommendationError("required_fields must be an object")
        for source, groups in raw_fields.items():
            if not isinstance(source, str) or not isinstance(groups, list):
                raise RecommendationError("required_fields must map source names to arrays")
            parsed_groups: list[tuple[str, ...]] = []
            for group in groups:
                candidates = [group] if isinstance(group, str) else group
                if not isinstance(candidates, list) or not candidates or not all(
                    isinstance(item, str) and item.strip() for item in candidates
                ):
                    raise RecommendationError("field requirement groups must contain field names")
                parsed_groups.append(tuple(item.strip() for item in candidates))
            field_requirements[source] = tuple(parsed_groups)

        return cls(
            detection_id=str(value["id"]), name=str(value["name"]),
            pack_id=str(value["pack_id"]), capability=str(value["capability"]),
            required_sources=required_sources, required_fields=field_requirements,
            priority=priority, severity=severity,
            mitre_techniques=tuple(str(item) for item in value["mitre_techniques"]),
            why=str(value["why"]), implementation=str(value["implementation"]),
            requires_enterprise_security=bool(value["requires_enterprise_security"]),
        )


@dataclass(frozen=True)
class DetectionRecommendation:
    detection_id: str
    name: str
    pack_id: str
    capability: str
    readiness: str
    score: int
    severity: str
    observed_sources: tuple[str, ...]
    missing_sources: tuple[str, ...]
    field_validation: str
    missing_fields: dict[str, tuple[str, ...]]
    unverified_field_sources: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    why: str
    implementation: str
    requires_enterprise_security: bool

    def to_mapping(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RecommendationReport:
    observed_source_count: int
    normalized_source_count: int
    production_ready_count: int
    partial_count: int
    unsupported_count: int
    field_gap_count: int
    field_unverified_count: int
    source_mappings: tuple[SourceMapping, ...]
    unmapped_sources: tuple[str, ...]
    recommendations: tuple[DetectionRecommendation, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "observed_source_count": self.observed_source_count,
            "normalized_source_count": self.normalized_source_count,
            "production_ready_count": self.production_ready_count,
            "partial_count": self.partial_count,
            "unsupported_count": self.unsupported_count,
            "field_gap_count": self.field_gap_count,
            "field_unverified_count": self.field_unverified_count,
            "source_mappings": [item.to_mapping() for item in self.source_mappings],
            "unmapped_sources": list(self.unmapped_sources),
            "recommendations": [item.to_mapping() for item in self.recommendations],
        }


class RecommendationEngine:
    def __init__(self, opportunities: tuple[DetectionOpportunity, ...]) -> None:
        if not opportunities:
            raise RecommendationError("Detection catalog must contain at least one entry")
        identifiers = [item.detection_id for item in opportunities]
        if len(identifiers) != len(set(identifiers)):
            raise RecommendationError("Detection catalog contains duplicate IDs")
        self._opportunities = opportunities

    @classmethod
    def from_catalog(cls, catalog_path: Path) -> "RecommendationEngine":
        try:
            raw = json.loads(catalog_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RecommendationError(f"Unable to load detection catalog: {exc}") from exc
        if not isinstance(raw, list):
            raise RecommendationError("Detection catalog must be a JSON array")
        opportunities = tuple(
            DetectionOpportunity.from_mapping(item) for item in raw if isinstance(item, dict)
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
        fields_by_source: dict[str, list[str]] | None = None,
    ) -> RecommendationReport:
        normalization = normalize_sources(observed_sources)
        normalized = {source.lower() for source in normalization.canonical_sources}
        for mapping in normalization.mappings:
            normalized.update(source.lower() for source in mapping.additional_canonical_sources)

        canonical_fields: dict[str, set[str]] = {}
        if fields_by_source is not None:
            mapping_by_observed = {
                item.observed_source.lower(): (
                    item.canonical_source,
                    *item.additional_canonical_sources,
                )
                for item in normalization.mappings
            }
            for source, fields in fields_by_source.items():
                canonical_sources = mapping_by_observed.get(source.lower(), (source,))
                normalized_fields = {field.lower() for field in fields if field.strip()}
                for canonical_source in canonical_sources:
                    canonical_fields.setdefault(canonical_source.lower(), set()).update(
                        normalized_fields
                    )

        recommendations: list[DetectionRecommendation] = []
        ready = partial = unsupported = field_gaps = field_unverified = 0

        for opportunity in self._opportunities:
            required = {source.lower() for source in opportunity.required_sources}
            observed = tuple(
                source for source in opportunity.required_sources if source.lower() in normalized
            )
            missing = tuple(
                source for source in opportunity.required_sources if source.lower() not in normalized
            )
            matched_count = len(observed)

            field_validation = "not_evaluated"
            missing_fields: dict[str, tuple[str, ...]] = {}
            unverified_field_sources: tuple[str, ...] = ()
            if fields_by_source is not None and matched_count == len(required):
                unverified = tuple(
                    source
                    for source in opportunity.required_fields
                    if source.lower() not in canonical_fields
                )
                if unverified:
                    field_validation = "unverified"
                    unverified_field_sources = unverified
                else:
                    field_validation = "passed"
                    for source, groups in opportunity.required_fields.items():
                        available = canonical_fields[source.lower()]
                        missing_groups = tuple(
                            " OR ".join(group)
                            for group in groups
                            if not any(candidate.lower() in available for candidate in group)
                        )
                        if missing_groups:
                            missing_fields[source] = missing_groups
                    if missing_fields:
                        field_validation = "failed"

            if matched_count == len(required):
                if field_validation == "failed":
                    readiness = "field_gap"
                    readiness_points = 0
                elif field_validation == "unverified":
                    readiness = "field_unverified"
                    readiness_points = 0
                else:
                    readiness = "production_ready"
                    readiness_points = 20
            elif matched_count:
                readiness = "partial"
                readiness_points = 5
            else:
                readiness = "unsupported"
                readiness_points = -25

            if opportunity.requires_enterprise_security and not enterprise_security_enabled:
                readiness = "requires_enterprise_security"
                readiness_points = -10

            if readiness == "production_ready":
                ready += 1
            elif readiness in {"partial", "field_gap", "field_unverified"}:
                partial += 1
            elif readiness in {"unsupported", "requires_enterprise_security"}:
                unsupported += 1

            if readiness == "field_gap":
                field_gaps += 1
            elif readiness == "field_unverified":
                field_unverified += 1

            if readiness in {"unsupported", "requires_enterprise_security"} and not include_unsupported:
                continue

            score = max(0, min(100, opportunity.priority + readiness_points))
            recommendations.append(DetectionRecommendation(
                detection_id=opportunity.detection_id, name=opportunity.name,
                pack_id=opportunity.pack_id, capability=opportunity.capability,
                readiness=readiness, score=score, severity=opportunity.severity,
                observed_sources=observed, missing_sources=missing,
                field_validation=field_validation, missing_fields=missing_fields,
                unverified_field_sources=unverified_field_sources,
                mitre_techniques=opportunity.mitre_techniques, why=opportunity.why,
                implementation=opportunity.implementation,
                requires_enterprise_security=opportunity.requires_enterprise_security,
            ))

        recommendations.sort(key=lambda item: (-item.score, item.name.lower()))
        return RecommendationReport(
            observed_source_count=len(normalization.mappings),
            normalized_source_count=len(normalization.canonical_sources),
            production_ready_count=ready, partial_count=partial,
            unsupported_count=unsupported, field_gap_count=field_gaps,
            field_unverified_count=field_unverified,
            source_mappings=normalization.mappings,
            unmapped_sources=normalization.unmapped_sources,
            recommendations=tuple(recommendations),
        )

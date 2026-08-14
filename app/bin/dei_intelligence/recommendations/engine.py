"""Data-driven detection recommendation engine for DEI."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from dei_intelligence.knowledgepacks.loader import KnowledgePackError, KnowledgePackLoader
from dei_intelligence.telemetry.normalization import SourceMapping, normalize_sources

_DETECTION_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_MITRE_TECHNIQUE_PATTERN = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")
_DETECTION_KEYS = {
    "id", "name", "pack_id", "capability", "required_sources", "required_fields",
    "priority", "severity", "mitre_techniques", "why", "implementation",
    "requires_enterprise_security",
}


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
        unexpected = sorted(value.keys() - _DETECTION_KEYS)
        if unexpected:
            raise RecommendationError(
                f"Detection catalog entry contains unsupported fields: {', '.join(unexpected)}"
            )

        detection_id = value["id"]
        if not isinstance(detection_id, str) or _DETECTION_ID_PATTERN.fullmatch(detection_id) is None:
            raise RecommendationError("Detection id must be a stable lowercase identifier")
        for field_name in ("name", "pack_id", "capability", "why", "implementation"):
            field_value = value[field_name]
            if not isinstance(field_value, str) or not field_value.strip():
                raise RecommendationError(f"Detection {field_name} must be a non-empty string")

        priority = value["priority"]
        if not isinstance(priority, int) or not 0 <= priority <= 100:
            raise RecommendationError("Detection priority must be an integer from 0 to 100")
        severity = str(value["severity"]).lower()
        if severity not in {"low", "medium", "high", "critical"}:
            raise RecommendationError(f"Unsupported severity: {severity}")
        raw_required_sources = value["required_sources"]
        if not isinstance(raw_required_sources, list) or not all(
            isinstance(item, str) for item in raw_required_sources
        ):
            raise RecommendationError("Detection required_sources must be an array of strings")
        required_sources = tuple(item.strip() for item in raw_required_sources)
        if not required_sources or any(not item for item in required_sources):
            raise RecommendationError("Detection required_sources must not be empty")
        if len(required_sources) != len(set(required_sources)):
            raise RecommendationError("Detection required_sources must not contain duplicates")

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
        if set(field_requirements) != set(required_sources):
            raise RecommendationError(
                "Detection required_fields must define every required source and no others"
            )

        raw_techniques = value["mitre_techniques"]
        if not isinstance(raw_techniques, list) or not all(
            isinstance(item, str) and _MITRE_TECHNIQUE_PATTERN.fullmatch(item)
            for item in raw_techniques
        ):
            raise RecommendationError("Detection mitre_techniques must contain ATT&CK technique IDs")
        if len(raw_techniques) != len(set(raw_techniques)):
            raise RecommendationError("Detection mitre_techniques must not contain duplicates")
        if not isinstance(value["requires_enterprise_security"], bool):
            raise RecommendationError("Detection requires_enterprise_security must be boolean")

        return cls(
            detection_id=detection_id, name=value["name"],
            pack_id=str(value["pack_id"]), capability=str(value["capability"]),
            required_sources=required_sources, required_fields=field_requirements,
            priority=priority, severity=severity,
            mitre_techniques=tuple(raw_techniques),
            why=value["why"], implementation=value["implementation"],
            requires_enterprise_security=value["requires_enterprise_security"],
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

    @property
    def detection_count(self) -> int:
        """Return the number of validated detections available to the engine."""
        return len(self._opportunities)

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

    @classmethod
    def from_knowledge_packs(
        cls,
        pack_root: Path,
        manifest_schema_path: Path,
        detection_schema_path: Path,
        *,
        current_dei_version: str = "0.1.0",
    ) -> "RecommendationEngine":
        """Load and cross-validate every pack-owned detection catalog."""
        try:
            detection_schema = json.loads(detection_schema_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RecommendationError(f"Unable to load detection schema: {exc}") from exc
        required = detection_schema.get("required") if isinstance(detection_schema, dict) else None
        properties = detection_schema.get("properties") if isinstance(detection_schema, dict) else None
        if (
            not isinstance(required, list)
            or not isinstance(properties, dict)
            or not _DETECTION_KEYS.issubset(set(required))
            or not _DETECTION_KEYS.issubset(properties)
        ):
            raise RecommendationError(f"Invalid detection schema: {detection_schema_path}")

        try:
            packs = KnowledgePackLoader(
                manifest_schema_path, current_dei_version=current_dei_version
            ).load_all(pack_root)
        except KnowledgePackError as exc:
            raise RecommendationError(f"Unable to load knowledge packs: {exc}") from exc

        opportunities: list[DetectionOpportunity] = []
        for pack in packs:
            manifest = pack.manifest
            for detection_path in pack.detection_paths:
                try:
                    raw = json.loads(detection_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise RecommendationError(
                        f"Unable to load detection catalog {detection_path}: {exc}"
                    ) from exc
                if not isinstance(raw, list) or not raw:
                    raise RecommendationError(
                        f"Detection catalog must be a non-empty JSON array: {detection_path}"
                    )
                for value in raw:
                    if not isinstance(value, dict):
                        raise RecommendationError(
                            f"Every detection catalog entry must be an object: {detection_path}"
                        )
                    opportunity = DetectionOpportunity.from_mapping(value)
                    if opportunity.pack_id != manifest.pack_id:
                        raise RecommendationError(
                            f"Detection {opportunity.detection_id!r} declares pack "
                            f"{opportunity.pack_id!r}, expected {manifest.pack_id!r}"
                        )
                    if opportunity.capability not in manifest.capabilities:
                        raise RecommendationError(
                            f"Detection {opportunity.detection_id!r} references undeclared "
                            f"capability {opportunity.capability!r}"
                        )
                    undeclared_sources = sorted(
                        set(opportunity.required_sources) - set(manifest.supported_sources)
                    )
                    if undeclared_sources:
                        raise RecommendationError(
                            f"Detection {opportunity.detection_id!r} references sources not "
                            f"declared by pack {manifest.pack_id!r}: "
                            f"{', '.join(undeclared_sources)}"
                        )
                    if (
                        manifest.requires_enterprise_security
                        and not opportunity.requires_enterprise_security
                    ):
                        raise RecommendationError(
                            f"Detection {opportunity.detection_id!r} must require Enterprise "
                            f"Security because pack {manifest.pack_id!r} requires it"
                        )
                    opportunities.append(opportunity)
        return cls(tuple(opportunities))

    def recommend(
        self,
        observed_sources: list[str],
        *,
        enterprise_security_enabled: bool = False,
        include_unsupported: bool = False,
        fields_by_source: dict[str, list[str]] | None = None,
        telemetry_routes: list[dict[str, Any]] | None = None,
    ) -> RecommendationReport:
        routed_sources, routed_field_sets = self._route_evidence(telemetry_routes or [])
        effective_sources = list(observed_sources) + routed_sources
        normalization = normalize_sources(effective_sources)
        normalized = {source.lower() for source in normalization.canonical_sources}
        for mapping in normalization.mappings:
            normalized.update(source.lower() for source in mapping.additional_canonical_sources)

        canonical_fields: dict[str, set[str]] = {}
        effective_fields = fields_by_source
        if telemetry_routes is not None:
            # Route evidence is authoritative when supplied. Do not merge the legacy
            # sourcetype-wide inventory, which can combine distinct routes.
            effective_fields = {
                source: sorted(set().union(*route_fields))
                for source, route_fields in routed_field_sets.items()
            }
        if effective_fields is not None:
            mapping_by_observed = {
                item.observed_source.lower(): (
                    item.canonical_source,
                    *item.additional_canonical_sources,
                )
                for item in normalization.mappings
            }
            for source, fields in effective_fields.items():
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
            if effective_fields is not None and matched_count == len(required):
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
                        candidates = routed_field_sets.get(source.lower()) if telemetry_routes is not None else None
                        route_candidates = candidates or [canonical_fields[source.lower()]]
                        complete_route = next((available for available in route_candidates if all(
                            any(candidate.lower() in available for candidate in group) for group in groups
                        )), None)
                        available = complete_route or set().union(*route_candidates)
                        missing_groups = () if complete_route is not None else tuple(
                            " OR ".join(group) for group in groups
                            if not any(candidate.lower() in available for candidate in group)
                        )
                        if not missing_groups and complete_route is None:
                            missing_groups = ("required fields are split across telemetry routes",)
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

    @staticmethod
    def _route_evidence(
        routes: list[dict[str, Any]],
    ) -> tuple[list[str], dict[str, list[set[str]]]]:
        """Convert scoped telemetry into canonical, non-cross-contaminating evidence."""
        sources: list[str] = []
        fields: dict[str, list[set[str]]] = {}
        channel_aliases = {
            "security": "XmlWinEventLog:Security",
            "microsoft-windows-powershell/operational": (
                "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
            ),
        }
        for route in routes:
            sourcetype = str(route.get("sourcetype", "")).strip()
            route_fields = {
                str(field).strip().lower() for field in route.get("fields", []) if str(field).strip()
            }
            canonical_routes: set[str] = set()
            if sourcetype.lower() == "xmlwineventlog":
                for channel in route.get("channels", []):
                    canonical = channel_aliases.get(str(channel).strip().lower())
                    if canonical:
                        canonical_routes.add(canonical)
            elif sourcetype:
                canonical_routes.add(sourcetype)
            for source in canonical_routes:
                sources.append(source)
                fields.setdefault(source.lower(), []).append(route_fields)
        return sources, fields

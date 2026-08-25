"""Capability inventory derived from installed DEI Knowledge Packs."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from dei_intelligence.knowledgepacks.models import KnowledgePack


@dataclass(frozen=True)
class CapabilityInventory:
    """Serializable aggregate of installed Knowledge Pack content."""

    knowledge_pack_count: int
    capability_count: int
    domain_count: int
    supported_source_count: int
    detection_count: int
    detections: tuple[dict[str, Any], ...]
    packs: tuple[dict[str, Any], ...]

    def to_mapping(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""
        return asdict(self)


class CapabilityService:
    """Build deterministic capability inventory responses."""

    def inventory(self, packs: tuple[KnowledgePack, ...]) -> CapabilityInventory:
        """Aggregate unique domains, sources, and capabilities across packs."""
        domains = {domain for pack in packs for domain in pack.manifest.domains}
        sources = {
            source for pack in packs for source in pack.manifest.supported_sources
        }
        capabilities = {
            capability for pack in packs for capability in pack.manifest.capabilities
        }
        detections: list[dict[str, Any]] = []
        for pack in packs:
            for path in pack.detection_paths:
                values = json.loads(path.read_text(encoding="utf-8"))
                for value in values:
                    if not isinstance(value, dict):
                        continue
                    entry = dict(value)
                    entry["detection_id"] = str(entry.pop("id", ""))
                    entry["knowledge_pack"] = pack.manifest.name
                    detections.append(entry)
        detections.sort(
            key=lambda item: (str(item.get("name", "")), str(item.get("detection_id", "")))
        )
        pack_entries = tuple(
            {
                "id": pack.manifest.pack_id,
                "name": pack.manifest.name,
                "version": pack.manifest.version,
                "domains": pack.manifest.domains,
                "supported_sources": pack.manifest.supported_sources,
                "capabilities": pack.manifest.capabilities,
                "requires_enterprise_security": (
                    pack.manifest.requires_enterprise_security
                ),
            }
            for pack in sorted(packs, key=lambda item: item.manifest.pack_id)
        )
        return CapabilityInventory(
            knowledge_pack_count=len(packs),
            capability_count=len(capabilities),
            domain_count=len(domains),
            supported_source_count=len(sources),
            detection_count=len(detections),
            detections=tuple(detections),
            packs=pack_entries,
        )

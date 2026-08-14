"""Typed models for DEI knowledge packs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class KnowledgePackManifest:
    """Validated metadata describing one knowledge pack."""

    pack_id: str
    name: str
    version: str
    minimum_dei_version: str
    domains: tuple[str, ...]
    supported_sources: tuple[str, ...]
    capabilities: tuple[str, ...]
    detection_files: tuple[str, ...]
    description: str = ""
    author: str = ""
    requires_enterprise_security: bool = False

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> KnowledgePackManifest:
        """Build an immutable manifest from validated JSON data."""
        return cls(
            pack_id=str(data["id"]),
            name=str(data["name"]),
            version=str(data["version"]),
            minimum_dei_version=str(data["minimum_dei_version"]),
            domains=tuple(str(item) for item in data["domains"]),
            supported_sources=tuple(str(item) for item in data["supported_sources"]),
            capabilities=tuple(str(item) for item in data["capabilities"]),
            detection_files=tuple(str(item) for item in data["detection_files"]),
            description=str(data.get("description", "")),
            author=str(data.get("author", "")),
            requires_enterprise_security=bool(data.get("requires_enterprise_security", False)),
        )


@dataclass(frozen=True)
class KnowledgePack:
    """A discovered knowledge pack and its filesystem location."""

    root: Path
    manifest_path: Path
    manifest: KnowledgePackManifest
    detection_paths: tuple[Path, ...]

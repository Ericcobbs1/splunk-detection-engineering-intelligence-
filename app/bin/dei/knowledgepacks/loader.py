"""Discovery and validation for DEI knowledge packs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from dei.knowledgepacks.models import KnowledgePack, KnowledgePackManifest


class KnowledgePackError(RuntimeError):
    """Raised when a knowledge pack cannot be discovered or validated."""


def _version_tuple(version: str) -> tuple[int, int, int]:
    """Convert a validated semantic version string into a comparable tuple."""
    major, minor, patch = version.split(".")
    return int(major), int(minor), int(patch)


class KnowledgePackLoader:
    """Discover manifest files and load validated knowledge packs."""

    def __init__(self, schema_path: Path, current_dei_version: str = "0.1.0") -> None:
        self._schema_path = schema_path
        self._current_dei_version = current_dei_version
        self._current_dei_version_tuple = _version_tuple(current_dei_version)
        schema = self._read_json(schema_path)
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as exc:
            raise KnowledgePackError(f"Invalid knowledge pack schema: {schema_path}") from exc
        self._validator = Draft202012Validator(schema)

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise KnowledgePackError(f"Unable to read JSON file: {path}") from exc
        if not isinstance(data, dict):
            raise KnowledgePackError(f"JSON object required: {path}")
        return data

    def discover(self, root: Path) -> tuple[Path, ...]:
        """Return manifest files found directly beneath knowledge-pack directories."""
        if not root.is_dir():
            raise KnowledgePackError(f"Knowledge pack root does not exist: {root}")
        return tuple(sorted(root.glob("*/manifest.json")))

    def load(self, manifest_path: Path) -> KnowledgePack:
        """Validate and load a single knowledge pack manifest."""
        data = self._read_json(manifest_path)
        try:
            self._validator.validate(data)
        except ValidationError as exc:
            location = ".".join(str(part) for part in exc.absolute_path) or "manifest"
            raise KnowledgePackError(
                f"Invalid knowledge pack manifest at {location}: {exc.message}"
            ) from exc

        manifest = KnowledgePackManifest.from_mapping(data)
        directory_name = manifest_path.parent.name
        if directory_name != manifest.pack_id:
            raise KnowledgePackError(
                "Knowledge pack directory must match manifest id: "
                f"{directory_name!r} != {manifest.pack_id!r}"
            )

        if _version_tuple(manifest.minimum_dei_version) > self._current_dei_version_tuple:
            raise KnowledgePackError(
                f"Knowledge pack {manifest.pack_id!r} requires DEI "
                f"{manifest.minimum_dei_version} or newer; current version is "
                f"{self._current_dei_version}"
            )

        return KnowledgePack(
            root=manifest_path.parent,
            manifest_path=manifest_path,
            manifest=manifest,
        )

    def load_all(self, root: Path) -> tuple[KnowledgePack, ...]:
        """Discover and load all packs while rejecting duplicate identifiers."""
        packs = tuple(self.load(path) for path in self.discover(root))
        seen: set[str] = set()
        for pack in packs:
            if pack.manifest.pack_id in seen:
                raise KnowledgePackError(
                    f"Duplicate knowledge pack id: {pack.manifest.pack_id}"
                )
            seen.add(pack.manifest.pack_id)
        return packs

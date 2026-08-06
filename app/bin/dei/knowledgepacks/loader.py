"""Discovery and validation for DEI knowledge packs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from dei.knowledgepacks.models import KnowledgePack, KnowledgePackManifest


class KnowledgePackError(RuntimeError):
    """Raised when a knowledge pack cannot be discovered or validated."""


class KnowledgePackLoader:
    """Discover manifest files and load validated knowledge packs."""

    def __init__(self, schema_path: Path) -> None:
        self._schema_path = schema_path
        self._validator = Draft202012Validator(self._read_json(schema_path))

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

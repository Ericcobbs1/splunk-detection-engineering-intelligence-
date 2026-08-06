"""Discovery and validation for DEI knowledge packs."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from dei.knowledgepacks.models import KnowledgePack, KnowledgePackManifest

_SEMVER_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_CAPABILITY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_ALLOWED_DOMAINS = {
    "identity", "endpoint", "network", "cloud", "ai",
    "email", "application", "database", "ot",
}
_ALLOWED_KEYS = {
    "id", "name", "version", "minimum_dei_version", "description", "author",
    "domains", "supported_sources", "capabilities", "requires_enterprise_security",
}
_REQUIRED_KEYS = {
    "id", "name", "version", "minimum_dei_version",
    "domains", "supported_sources", "capabilities",
}


class KnowledgePackError(RuntimeError):
    """Raised when a knowledge pack cannot be discovered or validated."""


def _version_tuple(version: str) -> tuple[int, int, int]:
    """Convert a semantic version string into a comparable tuple."""
    match = _SEMVER_PATTERN.fullmatch(version)
    if match is None:
        raise KnowledgePackError(f"Invalid DEI version: {version!r}")
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


def _validate_schema_document(schema: dict[str, Any], schema_path: Path) -> None:
    """Verify the packaged schema has the structure DEI expects.

    Splunk does not ship jsonschema. DEI therefore validates its compact manifest
    contract internally rather than depending on a third-party runtime package.
    """
    if schema.get("type") != "object":
        raise KnowledgePackError(f"Invalid knowledge pack schema: {schema_path}")
    required = schema.get("required")
    properties = schema.get("properties")
    if not isinstance(required, list) or not isinstance(properties, dict):
        raise KnowledgePackError(f"Invalid knowledge pack schema: {schema_path}")
    if not _REQUIRED_KEYS.issubset(set(required)):
        raise KnowledgePackError(f"Invalid knowledge pack schema: {schema_path}")


def _validate_string_list(name: str, value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise KnowledgePackError(f"Invalid knowledge pack manifest at {name}: non-empty array required")
    if not all(isinstance(item, str) and item for item in value):
        raise KnowledgePackError(f"Invalid knowledge pack manifest at {name}: string values required")
    if len(value) != len(set(value)):
        raise KnowledgePackError(f"Invalid knowledge pack manifest at {name}: duplicate values")
    return value


def _validate_manifest(data: dict[str, Any]) -> None:
    missing = sorted(_REQUIRED_KEYS - data.keys())
    if missing:
        raise KnowledgePackError(
            "Invalid knowledge pack manifest at manifest: missing " + ", ".join(missing)
        )
    unexpected = sorted(data.keys() - _ALLOWED_KEYS)
    if unexpected:
        raise KnowledgePackError(
            "Invalid knowledge pack manifest at manifest: unsupported " + ", ".join(unexpected)
        )

    pack_id = data.get("id")
    if not isinstance(pack_id, str) or _ID_PATTERN.fullmatch(pack_id) is None:
        raise KnowledgePackError("Invalid knowledge pack manifest at id: invalid identifier")
    name = data.get("name")
    if not isinstance(name, str) or len(name) < 3:
        raise KnowledgePackError("Invalid knowledge pack manifest at name: minimum length is 3")
    for key in ("version", "minimum_dei_version"):
        value = data.get(key)
        if not isinstance(value, str) or _SEMVER_PATTERN.fullmatch(value) is None:
            raise KnowledgePackError(f"Invalid knowledge pack manifest at {key}: semantic version required")

    domains = _validate_string_list("domains", data.get("domains"))
    if any(item not in _ALLOWED_DOMAINS for item in domains):
        raise KnowledgePackError("Invalid knowledge pack manifest at domains: unsupported domain")
    _validate_string_list("supported_sources", data.get("supported_sources"))
    capabilities = _validate_string_list("capabilities", data.get("capabilities"))
    if any(_CAPABILITY_PATTERN.fullmatch(item) is None for item in capabilities):
        raise KnowledgePackError("Invalid knowledge pack manifest at capabilities: invalid capability")

    for key in ("description", "author"):
        if key in data and not isinstance(data[key], str):
            raise KnowledgePackError(f"Invalid knowledge pack manifest at {key}: string required")
    if "requires_enterprise_security" in data and not isinstance(
        data["requires_enterprise_security"], bool
    ):
        raise KnowledgePackError(
            "Invalid knowledge pack manifest at requires_enterprise_security: boolean required"
        )


class KnowledgePackLoader:
    """Discover manifest files and load validated knowledge packs."""

    def __init__(self, schema_path: Path, current_dei_version: str = "0.1.0") -> None:
        self._schema_path = schema_path
        self._current_dei_version = current_dei_version
        self._current_dei_version_tuple = _version_tuple(current_dei_version)
        schema = self._read_json(schema_path)
        _validate_schema_document(schema, schema_path)

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
        """Return manifests for every visible knowledge-pack directory."""
        if not root.is_dir():
            raise KnowledgePackError(f"Knowledge pack root does not exist: {root}")

        manifests: list[Path] = []
        for pack_directory in sorted(root.iterdir()):
            if not pack_directory.is_dir() or pack_directory.name.startswith("."):
                continue
            manifest_path = pack_directory / "manifest.json"
            if not manifest_path.is_file():
                raise KnowledgePackError(
                    f"Knowledge pack directory is missing manifest.json: {pack_directory}"
                )
            manifests.append(manifest_path)
        return tuple(manifests)

    def load(self, manifest_path: Path) -> KnowledgePack:
        """Validate and load a single knowledge pack manifest."""
        data = self._read_json(manifest_path)
        _validate_manifest(data)

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

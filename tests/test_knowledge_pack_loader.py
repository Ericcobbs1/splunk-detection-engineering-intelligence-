"""Tests for knowledge pack discovery and validation."""

from pathlib import Path

import pytest

from dei.knowledgepacks.loader import KnowledgePackError, KnowledgePackLoader

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "schemas" / "knowledge-pack.schema.json"
PACK_ROOT = REPO_ROOT / "knowledgepacks"


def test_load_all_reference_packs() -> None:
    loader = KnowledgePackLoader(SCHEMA_PATH)

    packs = loader.load_all(PACK_ROOT)

    assert {pack.manifest.pack_id for pack in packs} == {"ai", "aws", "windows"}
    assert all(not pack.manifest.requires_enterprise_security for pack in packs)


def test_discover_requires_existing_directory(tmp_path: Path) -> None:
    loader = KnowledgePackLoader(SCHEMA_PATH)

    with pytest.raises(KnowledgePackError, match="does not exist"):
        loader.discover(tmp_path / "missing")


def test_invalid_manifest_is_rejected(tmp_path: Path) -> None:
    pack_root = tmp_path / "invalid"
    pack_root.mkdir()
    manifest_path = pack_root / "manifest.json"
    manifest_path.write_text('{"id": "Invalid ID"}', encoding="utf-8")
    loader = KnowledgePackLoader(SCHEMA_PATH)

    with pytest.raises(KnowledgePackError, match="Invalid knowledge pack manifest"):
        loader.load(manifest_path)


def test_invalid_schema_is_rejected(tmp_path: Path) -> None:
    schema_path = tmp_path / "invalid-schema.json"
    schema_path.write_text('{"type": 42}', encoding="utf-8")

    with pytest.raises(KnowledgePackError, match="Invalid knowledge pack schema"):
        KnowledgePackLoader(schema_path)


def test_pack_directory_must_match_manifest_id(tmp_path: Path) -> None:
    pack_root = tmp_path / "wrong-directory"
    pack_root.mkdir()
    manifest_path = pack_root / "manifest.json"
    manifest_path.write_text(
        """{
          "id": "expected-directory",
          "name": "Expected Directory",
          "version": "0.1.0",
          "minimum_dei_version": "0.1.0",
          "domains": ["endpoint"],
          "supported_sources": ["example"],
          "capabilities": ["example.capability"]
        }""",
        encoding="utf-8",
    )
    loader = KnowledgePackLoader(SCHEMA_PATH)

    with pytest.raises(KnowledgePackError, match="directory must match manifest id"):
        loader.load(manifest_path)

"""Contract tests for the modular, pack-owned detection library."""

import json
import shutil
from pathlib import Path

import pytest

from dei_intelligence.knowledgepacks.loader import KnowledgePackError, KnowledgePackLoader
from dei_intelligence.recommendations.engine import RecommendationEngine, RecommendationError
from library_helpers import DETECTION_SCHEMA, MANIFEST_SCHEMA, PACK_ROOT, load_catalog


def _engine(pack_root: Path) -> RecommendationEngine:
    return RecommendationEngine.from_knowledge_packs(
        pack_root,
        MANIFEST_SCHEMA,
        DETECTION_SCHEMA,
    )


def test_every_pack_owns_detection_content_and_aggregates_once() -> None:
    catalog = load_catalog()
    report = _engine(PACK_ROOT).recommend([], include_unsupported=True)

    assert not Path("app/detections/catalog.json").exists()
    assert len(report.recommendations) == len(catalog)
    assert len({item["id"] for item in catalog}) == len(catalog)
    assert {
        path.parent.name for path in PACK_ROOT.glob("*/detections.json")
    } == {path.name for path in PACK_ROOT.iterdir() if path.is_dir()}


def test_library_rejects_capability_not_declared_by_owning_pack(tmp_path: Path) -> None:
    pack_root = tmp_path / "knowledgepacks"
    shutil.copytree(PACK_ROOT, pack_root)
    detection_path = pack_root / "ai" / "detections.json"
    detections = json.loads(detection_path.read_text(encoding="utf-8"))
    detections[0]["capability"] = "ai.undeclared"
    detection_path.write_text(json.dumps(detections), encoding="utf-8")

    with pytest.raises(RecommendationError, match="undeclared capability"):
        _engine(pack_root)


def test_library_rejects_duplicate_ids_across_packs(tmp_path: Path) -> None:
    pack_root = tmp_path / "knowledgepacks"
    shutil.copytree(PACK_ROOT, pack_root)
    ai_detection = json.loads(
        (pack_root / "ai" / "detections.json").read_text(encoding="utf-8")
    )[0]
    aws_path = pack_root / "aws" / "detections.json"
    aws_detections = json.loads(aws_path.read_text(encoding="utf-8"))
    duplicate = dict(aws_detections[0])
    duplicate["id"] = ai_detection["id"]
    aws_detections.append(duplicate)
    aws_path.write_text(json.dumps(aws_detections), encoding="utf-8")

    with pytest.raises(RecommendationError, match="duplicate IDs"):
        _engine(pack_root)


def test_manifest_rejects_detection_path_escape(tmp_path: Path) -> None:
    pack_root = tmp_path / "example"
    pack_root.mkdir()
    manifest = {
        "id": "example",
        "name": "Example Pack",
        "version": "1.0.0",
        "minimum_dei_version": "0.1.0",
        "domains": ["application"],
        "supported_sources": ["example.source"],
        "capabilities": ["example.capability"],
        "detection_files": ["../detections.json"],
    }
    manifest_path = pack_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(KnowledgePackError, match="contained by the pack"):
        KnowledgePackLoader(MANIFEST_SCHEMA).load(manifest_path)

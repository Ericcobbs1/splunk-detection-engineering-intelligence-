"""Shared accessors for the installed modular detection library."""

import json
from pathlib import Path
from typing import Any

from dei_intelligence.recommendations.engine import RecommendationEngine

ROOT = Path(__file__).resolve().parents[1]
PACK_ROOT = ROOT / "app" / "knowledgepacks"
MANIFEST_SCHEMA = ROOT / "app" / "schemas" / "knowledge-pack.schema.json"
DETECTION_SCHEMA = ROOT / "app" / "schemas" / "detection.schema.json"


def load_catalog() -> list[dict[str, Any]]:
    """Return all pack-owned detection mappings in deterministic pack order."""
    catalog: list[dict[str, Any]] = []
    for path in sorted(PACK_ROOT.glob("*/detections.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(raw, list)
        catalog.extend(raw)
    return catalog


def engine_from_library() -> RecommendationEngine:
    """Build the recommendation engine through the production library path."""
    return RecommendationEngine.from_knowledge_packs(
        PACK_ROOT,
        MANIFEST_SCHEMA,
        DETECTION_SCHEMA,
    )

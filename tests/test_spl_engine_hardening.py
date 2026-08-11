import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "app" / "appserver" / "static" / "detection_query_generator_v3.js"
STANDARDS = ROOT / "app" / "appserver" / "static" / "dei_detection_standards_v1.js"
CATALOG = ROOT / "app" / "detections" / "catalog.json"


def test_every_catalog_detection_has_an_explicit_analytic_family() -> None:
    generator = GENERATOR.read_text(encoding="utf-8")
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    family_block = generator.split("var ANALYTIC_FAMILIES=", 1)[1].split("};", 1)[0]
    missing = [item["id"] for item in catalog if f'"{item["id"]}"' not in family_block]
    assert missing == []
    assert 'return ANALYTIC_FAMILIES[id]||"unsupported"' in generator
    assert "dei_generation_blocker=" in generator
    assert "No explicit analytic template exists for this detection ID" in generator


def test_detection_templates_preserve_entities_and_correct_source_semantics() -> None:
    generator = GENERATOR.read_text(encoding="utf-8")
    for contract in (
        "numeric_severity=tonumber(coalesce(severity,Severity))",
        "where numeric_severity>=7",
        "workflow_status=upper(coalesce('Workflow.Status',workflow_status))",
        "destination=coalesce(dest,url,host,service,application)",
            "NOT (action IN (",
            "blocked", "deny", "denied",
            "fillnull value=", "unknown", "user destination",
        "bytes_out=tonumber(coalesce(bytes_out,bytes_sent,response_bytes,sc_bytes))",
        "control-plane-change|admin-activity-change",
        "'protoPayload.requestMetadata.callerIp'",
            "user src_ip object",
        "earliest(_time) AS first_seen latest(_time) AS last_seen",
    ):
        assert contract in generator


def test_standards_engine_blocks_generic_templates_and_reviews_spl_semantics() -> None:
    standards = STANDARDS.read_text(encoding="utf-8")
    for contract in (
        "template.unsupported", "stats.null-group", "field.dotted",
        "logic.threshold", "context.time", "dei_generation_blocker",
    ):
        assert contract in standards

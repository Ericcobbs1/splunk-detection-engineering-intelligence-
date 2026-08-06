"""Field-level readiness tests for the DEI recommendation engine."""

import json
from pathlib import Path

from dei.recommendations.engine import RecommendationEngine


def _catalog(tmp_path: Path) -> Path:
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps([
        {
            "id": "windows-password-spray",
            "name": "Windows Password Spray",
            "pack_id": "windows",
            "capability": "windows.authentication",
            "required_sources": ["XmlWinEventLog:Security"],
            "required_fields": {
                "XmlWinEventLog:Security": [
                    ["EventCode", "event_id"],
                    ["TargetUserName", "user"],
                    ["IpAddress", "src_ip"],
                ]
            },
            "priority": 95,
            "severity": "high",
            "mitre_techniques": ["T1110.003"],
            "why": "Repeated failed logons can indicate password spraying.",
            "implementation": "splunk_spl",
            "requires_enterprise_security": False,
        }
    ]), encoding="utf-8")
    return catalog


def test_field_validation_passes_with_vendor_field_aliases(tmp_path: Path) -> None:
    engine = RecommendationEngine.from_catalog(_catalog(tmp_path))
    report = engine.recommend(
        ["WinEventLog:Security"],
        fields_by_source={"WinEventLog:Security": ["event_id", "user", "src_ip"]},
        include_unsupported=True,
    )
    recommendation = report.recommendations[0]
    assert recommendation.readiness == "production_ready"
    assert recommendation.field_validation == "passed"
    assert recommendation.missing_fields == {}
    assert report.production_ready_count == 1
    assert report.field_gap_count == 0


def test_field_validation_creates_field_gap_when_required_data_is_missing(tmp_path: Path) -> None:
    engine = RecommendationEngine.from_catalog(_catalog(tmp_path))
    report = engine.recommend(
        ["XmlWinEventLog:Security"],
        fields_by_source={"XmlWinEventLog:Security": ["EventCode", "TargetUserName"]},
        include_unsupported=True,
    )
    recommendation = report.recommendations[0]
    assert recommendation.readiness == "field_gap"
    assert recommendation.field_validation == "failed"
    assert recommendation.missing_fields == {
        "XmlWinEventLog:Security": ("IpAddress OR src_ip",)
    }
    assert report.production_ready_count == 0
    assert report.partial_count == 1
    assert report.field_gap_count == 1


def test_source_only_requests_remain_backward_compatible(tmp_path: Path) -> None:
    engine = RecommendationEngine.from_catalog(_catalog(tmp_path))
    report = engine.recommend(["XmlWinEventLog:Security"], include_unsupported=True)
    recommendation = report.recommendations[0]
    assert recommendation.readiness == "production_ready"
    assert recommendation.field_validation == "not_evaluated"

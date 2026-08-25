"""Contracts for the pre-feature reliability hardening pass."""

from pathlib import Path

STATIC = Path("app/appserver/static")


def test_environment_scan_sends_route_scoped_evidence_and_waits_for_kv() -> None:
    source = (STATIC / "dei_environment_scan_v1.js").read_text(encoding="utf-8")
    assert "telemetry_routes:result.telemetry_routes" in source
    assert "channels:channels,fields:fields" in source
    assert 'storage({resource:"scan",operation:"upsert",summary:snapshot,history:history})' in source
    assert 'durable:false,mode:"browser session"' in source
    assert '"complete_with_warning"' in source
    assert '"dei","v1","storage"' in source


def test_lifecycle_fallback_is_visible_and_not_described_as_durable() -> None:
    source = (STATIC / "dei_lifecycle_store_v1.js").read_text(encoding="utf-8")
    assert 'trigger("dei:persistence-warning"' in source
    assert "saved only in this browser and are not shared or governed" in source
    assert "_persistence = {durable:false" in source
    assert 'expected_revision:record._revision' in source
    assert "status>=400&&status<500" in source
    assert "The governed lifecycle change was rejected" in source
    assert "A sanitized, non-durable recovery copy was saved" in source
    assert '["sample_results", "raw_results", "_raw"]' in source
    assert 'request({resource:"lifecycle", operation:"delete", key:key})' in source

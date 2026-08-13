"""Contracts for the pre-feature reliability hardening pass."""

from pathlib import Path

STATIC = Path("app/appserver/static")


def test_environment_scan_sends_route_scoped_evidence_and_waits_for_kv() -> None:
    source = (STATIC / "dei_environment_scan_v1.js").read_text(encoding="utf-8")
    assert "telemetry_routes:result.telemetry_routes" in source
    assert "channels:channels,fields:fields" in source
    assert "$.when(writeRecord(scanCollection,snapshot),writeRecord(historyCollection,history))" in source
    assert 'durable:false,mode:"browser session"' in source
    assert '"complete_with_warning"' in source
    assert "data:JSON.stringify(createPayload)" in source
    assert "xhr.status!==409" in source
    assert "collectionEndpoint(collection,key)" in source


def test_lifecycle_fallback_is_visible_and_not_described_as_durable() -> None:
    source = (STATIC / "dei_lifecycle_store_v1.js").read_text(encoding="utf-8")
    assert 'trigger("dei:persistence-warning"' in source
    assert "saved only in this browser and are not shared or governed" in source
    assert "_persistence = {durable:false" in source
    assert 'url:endpoint(), method:"POST", data:JSON.stringify(payload)' in source
    assert "xhr.status === 409" in source
    assert 'url:endpoint(key), method:"POST", data:JSON.stringify(updatePayload)' in source

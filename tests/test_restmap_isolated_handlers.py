"""Regression tests for Splunk persistent REST handler isolation."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
RESTMAP = REPO_ROOT / "app" / "default" / "restmap.conf"
BIN_DIR = REPO_ROOT / "app" / "bin"


def test_each_rest_endpoint_uses_a_distinct_script_module() -> None:
    text = RESTMAP.read_text(encoding="utf-8")

    expected = {
        "dei_health_rest.py": "dei_health_rest.HealthApplication",
        "dei_capabilities_rest.py": "dei_capabilities_rest.CapabilitiesApplication",
        "dei_telemetry_rest.py": "dei_telemetry_rest.TelemetryApplication",
        "dei_recommendations_rest.py": "dei_recommendations_rest.RecommendationsApplication",
    }

    for script, handler in expected.items():
        assert f"script = {script}" in text
        assert f"handler = {handler}" in text
        assert (BIN_DIR / script).is_file()


def test_shared_multiclass_entrypoint_is_not_registered() -> None:
    text = RESTMAP.read_text(encoding="utf-8")

    assert "script = dei_rest.py" not in text
    assert "handler = dei_rest." not in text

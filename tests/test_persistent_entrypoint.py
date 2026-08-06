"""Regression tests for the Splunk persistent REST entrypoint."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = REPO_ROOT / "app" / "bin" / "dei_rest.py"


def test_entrypoint_lazy_loads_dei_handlers() -> None:
    source = ENTRYPOINT.read_text(encoding="utf-8")

    assert "importlib.import_module" in source
    assert "from dei.api" not in source
    assert 'handler_module = "dei.api.recommendations_handler"' in source
    assert 'handler_name = "RecommendationsHandler"' in source


def test_entrypoint_returns_structured_loader_errors() -> None:
    source = ENTRYPOINT.read_text(encoding="utf-8")

    assert '"error": "DEI handler load or execution failed"' in source
    assert '"exception_type": type(exc).__name__' in source
    assert '"status": 500' in source

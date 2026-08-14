"""Regression guards for Splunk's bundled Python 3.9 runtime."""

from pathlib import Path


def test_recommendations_handler_avoids_runtime_pep604_type_alias() -> None:
    source = Path("app/bin/dei_intelligence/api/recommendations_handler.py").read_text(encoding="utf-8")
    assert "Optional[dict[str, list[str]]]" in source
    assert "RecommendationFactory = Callable[[list[str], bool, bool, dict[str, list[str]] | None]" not in source


def test_knowledge_pack_loader_has_no_jsonschema_runtime_dependency() -> None:
    source = Path("app/bin/dei_intelligence/knowledgepacks/loader.py").read_text(encoding="utf-8")
    assert "from jsonschema" not in source
    assert "import jsonschema" not in source


def test_project_targets_splunk_python39() -> None:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.9"' in pyproject
    assert 'target-version = "py39"' in pyproject
    assert 'python_version = "3.9"' in pyproject

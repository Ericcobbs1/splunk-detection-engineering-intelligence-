"""Protect DEI persistent handlers from packages owned by other Splunk apps."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_BIN = ROOT / "app" / "bin"
QUALITY_WORKFLOW = ROOT / ".github" / "workflows" / "quality.yml"


def test_dei_handlers_ignore_a_conflicting_generic_dei_package(tmp_path: Path) -> None:
    foreign = tmp_path / "foreign_app"
    (foreign / "dei" / "api").mkdir(parents=True)
    (foreign / "dei" / "__init__.py").write_text("OWNER = 'foreign-app'\n", encoding="utf-8")
    (foreign / "dei" / "api" / "__init__.py").write_text("", encoding="utf-8")

    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join((str(foreign), str(APP_BIN)))
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import dei; "
                "from dei_intelligence.api.storage_handler import StorageHandler; "
                "assert dei.OWNER == 'foreign-app'; "
                "assert StorageHandler.__module__ == "
                "'dei_intelligence.api.storage_handler'"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 0, result.stderr


def test_persistent_entrypoints_use_only_the_isolated_runtime_namespace() -> None:
    entrypoints = sorted(APP_BIN.glob("dei*_rest.py"))
    assert entrypoints
    for entrypoint in entrypoints:
        source = entrypoint.read_text(encoding="utf-8")
        assert "from dei." not in source
        assert '"dei.api.' not in source
    assert "from dei_intelligence.api.storage_handler import StorageHandler" in (
        APP_BIN / "dei_storage_rest.py"
    ).read_text(encoding="utf-8")


def test_ci_type_checks_the_isolated_runtime_package() -> None:
    workflow = QUALITY_WORKFLOW.read_text(encoding="utf-8")
    assert "mypy app/bin/dei_intelligence" in workflow
    assert "mypy app/bin/dei\n" not in workflow

"""Tests for DEI runtime configuration, logging, and health reporting."""

import json
import logging

import pytest

from dei_intelligence.core.config import ConfigurationError, RuntimeConfig
from dei_intelligence.core.health import HealthService
from dei_intelligence.core.logging import JsonFormatter, configure_logger


def test_runtime_config_normalizes_values() -> None:
    config = RuntimeConfig.from_mapping(
        {
            "app_version": "0.2.0",
            "log_level": "debug",
            "enterprise_security_enabled": True,
        }
    )

    assert config.app_version == "0.2.0"
    assert config.log_level == "DEBUG"
    assert config.enterprise_security_enabled is True


def test_runtime_config_rejects_invalid_values() -> None:
    with pytest.raises(ConfigurationError, match="Unsupported log_level"):
        RuntimeConfig.from_mapping({"log_level": "verbose"})

    with pytest.raises(ConfigurationError, match="must be a boolean"):
        RuntimeConfig.from_mapping({"enterprise_security_enabled": "yes"})


def test_json_formatter_emits_structured_record() -> None:
    record = logging.LogRecord(
        name="DEI.Core.Health",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="runtime ready",
        args=(),
        exc_info=None,
    )

    payload = json.loads(JsonFormatter().format(record))

    assert payload["level"] == "INFO"
    assert payload["logger"] == "DEI.Core.Health"
    assert payload["message"] == "runtime ready"
    assert "timestamp" in payload


def test_configure_logger_replaces_existing_handlers() -> None:
    logger = configure_logger("DEI.Test", "WARNING")
    logger = configure_logger("DEI.Test", "DEBUG")

    assert logger.level == logging.DEBUG
    assert len(logger.handlers) == 1
    assert isinstance(logger.handlers[0].formatter, JsonFormatter)


def test_health_service_reports_runtime_state() -> None:
    config = RuntimeConfig(app_version="0.1.0", enterprise_security_enabled=False)

    report = HealthService(config).report(knowledge_pack_count=3)

    assert report.to_mapping() == {
        "status": "healthy",
        "version": "0.1.0",
        "knowledge_pack_count": 3,
        "enterprise_security_enabled": False,
    }


def test_health_service_rejects_negative_pack_count() -> None:
    with pytest.raises(ValueError, match="must not be negative"):
        HealthService(RuntimeConfig()).report(-1)

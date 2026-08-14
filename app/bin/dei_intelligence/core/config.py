"""Typed runtime configuration for the DEI platform."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from dei_intelligence import __version__


class ConfigurationError(ValueError):
    """Raised when DEI runtime configuration is invalid."""


@dataclass(frozen=True)
class RuntimeConfig:
    """Validated runtime settings shared by DEI core services."""

    app_version: str = __version__
    log_level: str = "INFO"
    enterprise_security_enabled: bool = False

    @classmethod
    def from_mapping(cls, values: Mapping[str, object]) -> RuntimeConfig:
        """Build runtime configuration from an untrusted mapping."""
        app_version = str(values.get("app_version", cls.app_version)).strip()
        log_level = str(values.get("log_level", cls.log_level)).upper().strip()
        enterprise_security_enabled = values.get(
            "enterprise_security_enabled", cls.enterprise_security_enabled
        )

        if not app_version:
            raise ConfigurationError("app_version must not be empty")
        if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ConfigurationError(f"Unsupported log_level: {log_level}")
        if not isinstance(enterprise_security_enabled, bool):
            raise ConfigurationError("enterprise_security_enabled must be a boolean")

        return cls(
            app_version=app_version,
            log_level=log_level,
            enterprise_security_enabled=enterprise_security_enabled,
        )

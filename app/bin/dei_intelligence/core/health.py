"""Health reporting for the DEI core runtime."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from dei_intelligence.core.config import RuntimeConfig


@dataclass(frozen=True)
class HealthReport:
    """Serializable snapshot of DEI runtime health."""

    status: str
    version: str
    knowledge_pack_count: int
    enterprise_security_enabled: bool

    def to_mapping(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""
        return asdict(self)


class HealthService:
    """Build deterministic health reports for API adapters."""

    def __init__(self, config: RuntimeConfig) -> None:
        self._config = config

    def report(self, knowledge_pack_count: int) -> HealthReport:
        """Return runtime health after validating dependency counts."""
        if knowledge_pack_count < 0:
            raise ValueError("knowledge_pack_count must not be negative")
        return HealthReport(
            status="healthy",
            version=self._config.app_version,
            knowledge_pack_count=knowledge_pack_count,
            enterprise_security_enabled=self._config.enterprise_security_enabled,
        )

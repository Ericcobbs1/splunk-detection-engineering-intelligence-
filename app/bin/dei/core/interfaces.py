"""Abstract contracts implemented by DEI platform services."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Mapping, Sequence


class TelemetryService(ABC):
    """Discover and profile telemetry available to DEI."""

    @abstractmethod
    def profile(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Create a telemetry profile from a bounded analysis request."""


class KnowledgeService(ABC):
    """Load and query declarative detection knowledge."""

    @abstractmethod
    def list_detections(self) -> Sequence[Mapping[str, Any]]:
        """Return detection definitions available from enabled knowledge packs."""


class RecommendationService(ABC):
    """Match telemetry capabilities to supported detection definitions."""

    @abstractmethod
    def recommend(
        self,
        telemetry_profile: Mapping[str, Any],
    ) -> Sequence[Mapping[str, Any]]:
        """Return explainable recommendations for a telemetry profile."""


class ScoringService(ABC):
    """Calculate readiness and confidence scores."""

    @abstractmethod
    def score(
        self,
        detection: Mapping[str, Any],
        telemetry_profile: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Return score components and a normalized overall score."""


class ValidationService(ABC):
    """Validate generated detections against historical telemetry."""

    @abstractmethod
    def validate(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Execute a bounded validation and return evidence and diagnostics."""


class IntegrationService(ABC):
    """Expose optional integrations such as Splunk Enterprise Security."""

    @abstractmethod
    def capabilities(self) -> Mapping[str, bool]:
        """Return detected integration capabilities without making them mandatory."""

"""Unit tests for the DEI service registry."""

from abc import ABC, abstractmethod

import pytest

from dei.core.service_registry import ServiceRegistry, ServiceRegistryError


class ExampleService(ABC):
    @abstractmethod
    def name(self) -> str:
        """Return the service name."""


class ExampleImplementation(ExampleService):
    def name(self) -> str:
        return "example"


def test_register_and_resolve_service() -> None:
    registry = ServiceRegistry()
    implementation = ExampleImplementation()

    registry.register(ExampleService, implementation)

    assert registry.resolve(ExampleService) is implementation
    assert tuple(registry.registered_interfaces()) == (ExampleService,)


def test_duplicate_registration_is_rejected() -> None:
    registry = ServiceRegistry()
    registry.register(ExampleService, ExampleImplementation())

    with pytest.raises(ServiceRegistryError, match="already registered"):
        registry.register(ExampleService, ExampleImplementation())


def test_missing_service_is_rejected() -> None:
    registry = ServiceRegistry()

    with pytest.raises(ServiceRegistryError, match="not registered"):
        registry.resolve(ExampleService)


def test_invalid_implementation_is_rejected() -> None:
    registry = ServiceRegistry()

    with pytest.raises(ServiceRegistryError, match="does not implement"):
        registry.register(ExampleService, object())  # type: ignore[arg-type]

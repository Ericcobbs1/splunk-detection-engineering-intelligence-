"""Service registration and dependency lookup for DEI components."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Generic, Iterable, Type, TypeVar


T = TypeVar("T")


class ServiceRegistryError(RuntimeError):
    """Raised when a service registration or lookup cannot be completed."""


@dataclass
class ServiceRegistry:
    """Store services by interface type without coupling callers to implementations."""

    _services: Dict[Type[Any], Any] = field(default_factory=dict)

    def register(self, interface: Type[T], implementation: T, *, replace: bool = False) -> None:
        """Register an implementation for an interface.

        Args:
            interface: Abstract class or protocol used as the lookup key.
            implementation: Concrete service instance.
            replace: Allow replacement of an existing registration.
        """
        if interface in self._services and not replace:
            raise ServiceRegistryError(f"Service already registered: {interface.__name__}")
        if not isinstance(implementation, interface):
            raise ServiceRegistryError(
                f"Implementation {type(implementation).__name__} does not implement {interface.__name__}"
            )
        self._services[interface] = implementation

    def resolve(self, interface: Type[T]) -> T:
        """Return the registered implementation for an interface."""
        try:
            return self._services[interface]
        except KeyError as exc:
            raise ServiceRegistryError(f"Service not registered: {interface.__name__}") from exc

    def registered_interfaces(self) -> Iterable[Type[Any]]:
        """Return an immutable view of registered interface types."""
        return tuple(self._services.keys())

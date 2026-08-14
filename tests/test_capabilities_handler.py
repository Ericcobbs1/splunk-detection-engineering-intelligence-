"""Tests for the DEI capabilities service and REST adapter."""

from dei_intelligence.api.capabilities_handler import (
    CapabilitiesHandler,
    _default_inventory_factory,
)
from dei_intelligence.core.capabilities import CapabilityInventory
from dei_intelligence.knowledgepacks.loader import KnowledgePackError


def test_default_inventory_aggregates_packaged_packs() -> None:
    inventory = _default_inventory_factory()

    assert inventory.knowledge_pack_count == 3
    assert inventory.capability_count == 18
    assert inventory.domain_count == 6
    assert inventory.supported_source_count == 12
    assert [pack["id"] for pack in inventory.packs] == ["ai", "aws", "windows"]


def test_capabilities_handler_returns_inventory() -> None:
    handler = CapabilitiesHandler()

    response = handler.handle('{"method":"GET"}')
    payload = response["payload"]

    assert response["status"] == 200
    assert payload["knowledge_pack_count"] == 3
    assert payload["capability_count"] == 18
    assert len(payload["packs"]) == 3


def test_capabilities_handler_rejects_non_get_method() -> None:
    handler = CapabilitiesHandler()

    response = handler.handle('{"method":"POST"}')

    assert response["status"] == 405
    assert response["payload"] == {"error": "method not allowed"}


def test_capabilities_handler_reports_pack_validation_failure() -> None:
    def fail_inventory() -> CapabilityInventory:
        raise KnowledgePackError("broken pack")

    handler = CapabilitiesHandler(inventory_factory=fail_inventory)

    response = handler.handle('{"method":"GET"}')

    assert response["status"] == 500
    assert response["payload"] == {
        "detail": "broken pack",
        "error": "knowledge pack validation failed",
    }

"""Tests for authenticated server-side governed persistence."""

import json
from pathlib import Path
from typing import Any

from dei.api.storage_handler import LIFECYCLE, SCAN_HISTORY, SCAN_SUMMARIES, StorageHandler

APP = Path("app")


class FakeStore:
    def __init__(self) -> None:
        self.records: dict[str, dict[str, dict[str, Any]]] = {}
        self.deleted: list[tuple[str, str]] = []

    def list(self, collection: str) -> list[dict[str, Any]]:
        return list(self.records.get(collection, {}).values())

    def upsert(self, collection: str, record: dict[str, Any]) -> None:
        self.records.setdefault(collection, {})[str(record["_key"])] = dict(record)

    def delete(self, collection: str, key: str) -> None:
        self.deleted.append((collection, key))
        self.records.setdefault(collection, {}).pop(key, None)


def request(payload: dict[str, Any], method: str = "POST") -> str:
    return json.dumps({"method": method, "sessionKey": "token", "payload": payload})


def test_storage_runtime_modules_are_packaged() -> None:
    assert (APP / "bin" / "dei_storage_rest.py").is_file()
    assert (APP / "bin" / "dei" / "api" / "storage_handler.py").is_file()


def test_scan_write_and_read_are_server_side_and_durable() -> None:
    store = FakeStore()
    handler = StorageHandler(store_factory=lambda _: store)
    response = handler.handle(request({
        "resource": "scan", "operation": "upsert",
        "summary": {"_key": "latest", "assessment_id": "scan-1"},
        "history": {"_key": "scan-1", "assessment_id": "scan-1"},
    }))
    assert response == {"status": 200, "payload": {"durable": True, "mode": "Splunk KV Store"}}
    assert store.records[SCAN_SUMMARIES]["latest"]["assessment_id"] == "scan-1"
    assert store.records[SCAN_HISTORY]["scan-1"]["assessment_id"] == "scan-1"
    read = handler.handle(request({"resource": "scan", "operation": "read"}))
    assert read["payload"]["assessment_id"] == "scan-1"


def test_lifecycle_write_read_and_delete_use_governed_collection() -> None:
    store = FakeStore()
    handler = StorageHandler(store_factory=lambda _: store)
    record = {"_key": "det-1", "state": "testing"}
    assert handler.handle(request({"resource": "lifecycle", "record": record}))["status"] == 200
    listed = handler.handle(request({"resource": "lifecycle", "operation": "read"}))
    assert listed["payload"]["records"] == [record]
    assert handler.handle(request({
        "resource": "lifecycle", "operation": "delete", "key": "det-1"
    }))["status"] == 200
    assert store.deleted == [(LIFECYCLE, "det-1")]


def test_storage_rejects_missing_session_and_invalid_records() -> None:
    handler = StorageHandler(store_factory=lambda _: FakeStore())
    assert handler.handle(json.dumps({"method": "POST", "payload": {"resource": "scan"}}))["status"] == 401
    assert handler.handle(request({"resource": "scan"}))["status"] == 400

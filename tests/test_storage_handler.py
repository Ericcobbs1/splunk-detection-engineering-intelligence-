"""Tests for authenticated server-side governed persistence."""

import json
from typing import Any

from dei.api.storage_handler import (
    LIFECYCLE,
    SCAN_HISTORY,
    SCAN_SUMMARIES,
    USER_PREFERENCES,
    StorageHandler,
)


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


def test_storage_accepts_splunk_persistent_connection_session_shape() -> None:
    received: list[str] = []
    store = FakeStore()
    handler = StorageHandler(store_factory=lambda token: received.append(token) or store)
    runtime_request = json.dumps({
        "method": "POST",
        "session": {"authtoken": "runtime-token", "user": "admin"},
        "payload": json.dumps({"resource": "lifecycle", "operation": "read"}),
    })

    response = handler.handle(runtime_request)

    assert response["status"] == 200
    assert received == ["runtime-token"]


def test_user_preferences_are_scoped_to_the_requested_user_key() -> None:
    store = FakeStore()
    handler = StorageHandler(store_factory=lambda _: store)
    preference = {"_key": "eric", "filters": {"coverage": {"readiness": "field_gap"}}}

    written = handler.handle(request({"resource": "preferences", "record": preference}))
    read = handler.handle(request({"resource": "preferences", "operation": "read", "key": "eric"}))
    missing = handler.handle(request({"resource": "preferences", "operation": "read", "key": "other"}))

    assert written["status"] == 200
    assert store.records[USER_PREFERENCES]["eric"] == preference
    assert read["payload"]["preference"] == preference
    assert missing["payload"]["preference"] == {}


def test_user_preferences_require_a_key_and_record() -> None:
    handler = StorageHandler(store_factory=lambda _: FakeStore())
    assert handler.handle(request({"resource": "preferences", "operation": "read"}))["status"] == 400
    assert handler.handle(request({"resource": "preferences", "record": {}}))["status"] == 400


def test_runtime_session_user_owns_the_preference_record() -> None:
    store = FakeStore()
    handler = StorageHandler(store_factory=lambda _: store)
    runtime = json.dumps({
        "method": "POST",
        "session": {"authtoken": "runtime-token", "user": "eric"},
        "payload": json.dumps({
            "resource": "preferences",
            "record": {"_key": "another-user", "filters": {"health": {"state": "failed"}}},
        }),
    })

    response = handler.handle(runtime)

    assert response["status"] == 200
    assert "eric" in store.records[USER_PREFERENCES]
    assert "another-user" not in store.records[USER_PREFERENCES]

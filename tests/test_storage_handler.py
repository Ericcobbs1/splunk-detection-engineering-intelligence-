"""Tests for authenticated server-side governed persistence."""

from __future__ import annotations

import json
from typing import Any

from dei_intelligence.api.storage_handler import (
    LIFECYCLE,
    SCAN_HISTORY,
    SCAN_SUMMARIES,
    USER_PREFERENCES,
    KVStore,
    StorageHandler,
)


class FakeStore:
    def __init__(self) -> None:
        self.records: dict[str, dict[str, dict[str, Any]]] = {}
        self.deleted: list[tuple[str, str]] = []

    def list(self, collection: str) -> list[dict[str, Any]]:
        return list(self.records.get(collection, {}).values())

    def get(self, collection: str, key: str) -> dict[str, Any] | None:
        return self.records.get(collection, {}).get(key)

    def upsert(self, collection: str, record: dict[str, Any]) -> None:
        self.records.setdefault(collection, {})[str(record["_key"])] = dict(record)

    def create(self, collection: str, record: dict[str, Any]) -> None:
        key = str(record["_key"])
        if key in self.records.setdefault(collection, {}):
            raise ValueError("record already exists")
        self.records[collection][key] = dict(record)

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


def test_kv_upsert_updates_existing_record_without_duplicate_key_errors() -> None:
    calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def update_existing(_token: str, method: str, path: str, payload: Any):
        calls.append((method, path, payload))
        if method == "GET":
            return 200, '[{"_key":"det-1"}]'
        return 200, ""

    KVStore("token", request=update_existing).upsert("records", {"_key": "det-1", "state": "testing"})

    assert len(calls) == 1
    assert calls[0][1].endswith("/records/det-1")
    assert calls[0][2] == {"state": "testing"}


def test_kv_upsert_creates_when_record_does_not_exist() -> None:
    calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def create_missing(_token: str, method: str, path: str, payload: Any):
        calls.append((method, path, payload))
        return (404, "") if path.endswith("/det-1") else (201, "")

    KVStore("token", request=create_missing).upsert("records", {"_key": "det-1", "state": "testing"})

    assert len(calls) == 2
    assert calls[0][1].endswith("/records/det-1")
    assert calls[1][1].endswith("/records")
    assert calls[1][2] == {"_key": "det-1", "state": "testing"}


def test_lifecycle_write_and_read_use_governed_collection_and_delete_is_blocked() -> None:
    store = FakeStore()
    handler = StorageHandler(store_factory=lambda _: store)
    record = {"_key": "det-1", "state": "testing", "history": []}
    assert handler.handle(request({"resource": "lifecycle", "record": record}))["status"] == 200
    listed = handler.handle(request({"resource": "lifecycle", "operation": "read"}))
    saved = listed["payload"]["records"][0]
    assert saved["state"] == "testing"
    assert saved["_revision"] == 1
    assert handler.handle(request({
        "resource": "lifecycle", "operation": "delete", "key": "det-1"
    }))["status"] == 405
    assert store.deleted == []


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


def test_lifecycle_rejects_history_rewrite_and_stale_revision() -> None:
    store = FakeStore()
    handler = StorageHandler(store_factory=lambda _: store)
    first = {"_key": "det-1", "state": "draft", "history": [{"event": "created", "actor": "spoof", "at": "spoof"}]}
    assert handler.handle(request({"resource": "lifecycle", "record": first}))["status"] == 200
    saved = store.records[LIFECYCLE]["det-1"]
    assert saved["history"][0]["actor"] == "unknown"
    rewritten = dict(saved, history=[{"event": "changed"}])
    assert handler.handle(request({"resource": "lifecycle", "record": rewritten, "expected_revision": 1}))["status"] == 409
    current = dict(saved, state="testing", history=saved["history"] + [{"event": "validated"}])
    assert handler.handle(request({"resource": "lifecycle", "record": current, "expected_revision": 0}))["status"] == 409


def test_scan_history_is_create_only_and_payload_is_bounded() -> None:
    store = FakeStore()
    handler = StorageHandler(store_factory=lambda _: store)
    payload = {"resource": "scan", "summary": {"_key": "latest"}, "history": {"_key": "scan-1", "assessment_id": "scan-1"}}
    assert handler.handle(request(payload))["status"] == 200
    assert handler.handle(request(payload))["status"] == 409
    oversized = json.dumps({"method": "POST", "sessionKey": "token", "payload": {"blob": "x" * 1_000_001}})
    assert handler.handle(oversized)["status"] == 413


def test_server_removes_raw_validation_samples_before_persistence() -> None:
    store = FakeStore()
    handler = StorageHandler(store_factory=lambda _: store)
    record = {
        "_key": "det-sensitive",
        "state": "testing",
        "history": [],
        "validation": {"status": "passed", "result_count": 1, "sample_results": [{"password": "secret", "_raw": "token"}]},
    }
    assert handler.handle(request({"resource": "lifecycle", "record": record}))["status"] == 200
    saved = store.records[LIFECYCLE]["det-sensitive"]
    assert saved["validation"]["result_count"] == 1
    assert "sample_results" not in saved["validation"]
def test_handler_accepts_persistent_rest_bytes_payload() -> None:
    store = FakeStore()
    handler = StorageHandler(lambda _session: store)
    request = json.dumps({"sessionKey": "token", "method": "POST", "payload": {"resource": "lifecycle", "operation": "read"}}).encode("utf-8")
    response = handler.handle(request)
    assert response["status"] == 200


def test_handler_rejects_non_utf8_persistent_rest_payload() -> None:
    handler = StorageHandler(lambda _session: FakeStore())
    response = handler.handle(b"\xff\xfe")
    assert response["status"] == 400

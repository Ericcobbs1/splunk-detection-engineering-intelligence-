"""Authenticated server-side persistence for DEI scan and lifecycle records."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, Optional
from urllib.parse import quote

from dei_intelligence.api.response import persistent_response

APP = "splunk_detection_engineering_intelligence"
SCAN_SUMMARIES = "dei_scan_summaries"
SCAN_HISTORY = "dei_scan_history"
LIFECYCLE = "dei_lifecycle_records"
USER_PREFERENCES = "dei_user_preferences"
RequestFn = Callable[[str, str, str, Optional[dict[str, Any]]], tuple[int, str]]


def _decode_payload(request_data: dict[str, Any]) -> Optional[dict[str, Any]]:
    payload: Any = request_data.get("payload", request_data)
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            return None
    if isinstance(payload, dict) and isinstance(payload.get("payload"), str):
        try:
            payload = json.loads(payload["payload"])
        except json.JSONDecodeError:
            return None
    return payload if isinstance(payload, dict) else None


def _session_key(request_data: dict[str, Any]) -> str:
    for source in (
        request_data,
        request_data.get("session", {}),
        request_data.get("connection", {}),
    ):
        if isinstance(source, dict):
            value = (
                source.get("sessionKey")
                or source.get("session_key")
                or source.get("authtoken")
            )
            if isinstance(value, str) and value:
                return value
    return ""


def _session_user(request_data: dict[str, Any]) -> str:
    for source in (
        request_data.get("session", {}),
        request_data.get("connection", {}),
        request_data,
    ):
        if isinstance(source, dict):
            value = source.get("user") or source.get("username")
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _default_request(
    session_key: str, method: str, path: str, payload: Optional[dict[str, Any]]
) -> tuple[int, str]:
    from splunk.rest import simpleRequest  # type: ignore[import-not-found]

    kwargs: dict[str, Any] = {"sessionKey": session_key, "method": method, "raiseAllErrors": False}
    if payload is not None:
        kwargs["jsonargs"] = json.dumps(payload)
    response, content = simpleRequest(path, **kwargs)
    status = int(response.get("status", 0))
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="replace")
    return status, str(content or "")


class KVStore:
    def __init__(self, session_key: str, request: RequestFn = _default_request) -> None:
        self._session_key = session_key
        self._request = request

    @staticmethod
    def endpoint(collection: str, key: str = "") -> str:
        path = f"/servicesNS/nobody/{APP}/storage/collections/data/{quote(collection, safe='')}"
        return f"{path}/{quote(key, safe='')}" if key else path

    def list(self, collection: str) -> list[dict[str, Any]]:
        status, content = self._request(self._session_key, "GET", self.endpoint(collection), None)
        if status != 200:
            raise RuntimeError(f"KV read failed with HTTP {status}")
        value = json.loads(content or "[]")
        if not isinstance(value, list):
            raise RuntimeError("KV read returned an unexpected response")
        return [item for item in value if isinstance(item, dict)]

    def upsert(self, collection: str, record: dict[str, Any]) -> None:
        key = str(record.get("_key", "")).strip()
        if not key:
            raise ValueError("record _key is required")
        status, _ = self._request(self._session_key, "POST", self.endpoint(collection), record)
        if status in (200, 201):
            return
        if status != 409:
            raise RuntimeError(f"KV create failed with HTTP {status}")
        replacement = dict(record)
        replacement.pop("_key", None)
        status, _ = self._request(
            self._session_key, "POST", self.endpoint(collection, key), replacement
        )
        if status not in (200, 201):
            raise RuntimeError(f"KV update failed with HTTP {status}")

    def delete(self, collection: str, key: str) -> None:
        status, _ = self._request(self._session_key, "DELETE", self.endpoint(collection, key), None)
        if status not in (200, 204, 404):
            raise RuntimeError(f"KV delete failed with HTTP {status}")


class StorageHandler:
    """Persist governed DEI state using the authenticated Splunk session."""

    def __init__(self, store_factory: Callable[[str], KVStore] = KVStore) -> None:
        self._store_factory = store_factory

    def handle(self, request: str) -> dict[str, Any]:
        try:
            request_data = json.loads(request)
        except json.JSONDecodeError:
            return persistent_response(400, {"error": "request must be valid JSON"})
        if not isinstance(request_data, dict):
            return persistent_response(400, {"error": "request must be a JSON object"})
        session_key = _session_key(request_data)
        if not session_key:
            return persistent_response(401, {"error": "authenticated Splunk session is required"})
        payload = _decode_payload(request_data)
        if payload is None:
            return persistent_response(400, {"error": "payload must be valid JSON"})
        method = str(request_data.get("method", "POST")).upper()
        resource = str(payload.get("resource", "")).strip().lower()
        session_user = _session_user(request_data)
        store = self._store_factory(session_key)
        try:
            if method == "GET" and resource == "scan":
                records = store.list(SCAN_SUMMARIES)
                latest = next((item for item in records if item.get("_key") == "latest"), None)
                return persistent_response(200, latest or {})
            if method == "GET" and resource == "lifecycle":
                return persistent_response(200, {"records": store.list(LIFECYCLE)})
            if method != "POST":
                return persistent_response(405, {"error": "method not allowed"})
            operation = str(payload.get("operation", "upsert")).lower()
            if resource == "scan" and operation == "read":
                records = store.list(SCAN_SUMMARIES)
                latest = next((item for item in records if item.get("_key") == "latest"), None)
                return persistent_response(200, latest or {})
            if resource == "lifecycle" and operation == "read":
                return persistent_response(200, {"records": store.list(LIFECYCLE)})
            if resource == "preferences" and operation == "read":
                key = session_user or str(payload.get("key", "")).strip()
                if not key:
                    return persistent_response(400, {"error": "preference key is required"})
                record = next((item for item in store.list(USER_PREFERENCES) if item.get("_key") == key), None)
                return persistent_response(200, {"preference": record or {}})
            if resource == "scan":
                summary, history = payload.get("summary"), payload.get("history")
                if not isinstance(summary, dict) or not isinstance(history, dict):
                    return persistent_response(400, {"error": "summary and history records are required"})
                store.upsert(SCAN_HISTORY, history)
                try:
                    store.upsert(SCAN_SUMMARIES, summary)
                except Exception:
                    store.delete(SCAN_HISTORY, str(history.get("_key", "")))
                    raise
                return persistent_response(200, {"durable": True, "mode": "Splunk KV Store"})
            if resource == "lifecycle":
                if operation == "delete":
                    key = str(payload.get("key", "")).strip()
                    if not key:
                        return persistent_response(400, {"error": "lifecycle key is required"})
                    store.delete(LIFECYCLE, key)
                    return persistent_response(200, {"durable": True})
                record = payload.get("record")
                if not isinstance(record, dict):
                    return persistent_response(400, {"error": "lifecycle record is required"})
                store.upsert(LIFECYCLE, record)
                return persistent_response(200, {"durable": True, "mode": "Splunk KV Store"})
            if resource == "preferences":
                record = payload.get("record")
                if not isinstance(record, dict) or not str(record.get("_key", "")).strip():
                    return persistent_response(400, {"error": "user preference record and key are required"})
                if session_user:
                    record = dict(record)
                    record["_key"] = session_user
                store.upsert(USER_PREFERENCES, record)
                return persistent_response(200, {"durable": True, "mode": "Splunk KV Store"})
            return persistent_response(400, {"error": "unknown storage resource"})
        except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
            return persistent_response(503, {"error": "durable persistence failed", "detail": str(exc)})

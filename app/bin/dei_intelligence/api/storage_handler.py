"""Authenticated server-side persistence for DEI scan and lifecycle records."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import quote

from dei_intelligence.api.response import persistent_response

APP = "splunk_detection_engineering_intelligence"
SCAN_SUMMARIES = "dei_scan_summaries"
SCAN_HISTORY = "dei_scan_history"
LIFECYCLE = "dei_lifecycle_records"
USER_PREFERENCES = "dei_user_preferences"
RequestFn = Callable[[str, str, str, Optional[dict[str, Any]]], tuple[int, str]]
MAX_REQUEST_BYTES = 1_000_000
MAX_HISTORY_EVENTS = 500
MAX_SCAN_HISTORY_RECORDS = 50
ALLOWED_STATES = {
    "recommendation", "draft", "testing", "peer_review", "production",
    "monitoring", "tuning", "retired",
}
ALLOWED_TRANSITIONS = {
    "recommendation": {"recommendation", "draft"},
    "draft": {"recommendation", "draft", "testing"},
    "testing": {"draft", "testing", "peer_review"},
    "peer_review": {"draft", "peer_review", "production"},
    "production": {"production", "monitoring", "retired"},
    "monitoring": {"monitoring", "tuning", "retired"},
    "tuning": {"tuning", "testing", "retired"},
    "retired": {"retired"},
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_size(value: Any) -> int:
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def _remove_validation_samples(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _remove_validation_samples(item)
            for key, item in value.items()
            if key not in {"sample_results", "raw_results", "_raw"}
        }
    if isinstance(value, list):
        return [_remove_validation_samples(item) for item in value]
    return value


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
    try:
        response, content = simpleRequest(path, **kwargs)
    except Exception as exc:
        match = re.search(r"HTTP\s+(\d{3})", str(exc))
        if match:
            return int(match.group(1)), str(exc)
        raise
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

    def get(self, collection: str, key: str) -> Optional[dict[str, Any]]:
        query = quote(json.dumps({"_key": key}, separators=(",", ":")), safe="")
        path = f"{self.endpoint(collection)}?query={query}&limit=1"
        status, content = self._request(self._session_key, "GET", path, None)
        if status != 200:
            raise RuntimeError(f"KV read failed with HTTP {status}")
        value = json.loads(content or "[]")
        if not isinstance(value, list):
            raise RuntimeError("KV read returned an unexpected response")
        return next((item for item in value if isinstance(item, dict)), None)

    def contains(self, collection: str, key: str) -> bool:
        query = quote(json.dumps({"_key": key}, separators=(",", ":")), safe="")
        path = f"{self.endpoint(collection)}?query={query}&limit=1"
        status, content = self._request(self._session_key, "GET", path, None)
        if status != 200:
            raise RuntimeError(f"KV existence check failed with HTTP {status}")
        value = json.loads(content or "[]")
        if not isinstance(value, list):
            raise RuntimeError("KV existence check returned an unexpected response")
        return any(isinstance(item, dict) and str(item.get("_key", "")) == key for item in value)

    def upsert(self, collection: str, record: dict[str, Any]) -> None:
        key = str(record.get("_key", "")).strip()
        if not key:
            raise ValueError("record _key is required")
        replacement = dict(record)
        replacement.pop("_key", None)
        status, _ = self._request(
            self._session_key, "POST", self.endpoint(collection, key), replacement
        )
        if status in (200, 201):
            return
        if status != 404:
            raise RuntimeError(f"KV update failed with HTTP {status}")
        status, _ = self._request(self._session_key, "POST", self.endpoint(collection), record)
        if status in (200, 201):
            return
        if status in (400, 409):
            status, _ = self._request(
                self._session_key, "POST", self.endpoint(collection, key), replacement
            )
            if status in (200, 201):
                return
        raise RuntimeError(f"KV create failed with HTTP {status}")

    def create(self, collection: str, record: dict[str, Any]) -> None:
        key = str(record.get("_key", "")).strip()
        if not key:
            raise ValueError("record _key is required")
        status, _ = self._request(self._session_key, "POST", self.endpoint(collection), record)
        if status in (200, 201):
            return
        if status in (400, 409):
            raise ValueError("record already exists")
        raise RuntimeError(f"KV create failed with HTTP {status}")

    def delete(self, collection: str, key: str) -> None:
        status, _ = self._request(self._session_key, "DELETE", self.endpoint(collection, key), None)
        if status not in (200, 204, 404):
            raise RuntimeError(f"KV delete failed with HTTP {status}")


class StorageHandler:
    """Persist governed DEI state using the authenticated Splunk session."""

    def __init__(self, store_factory: Callable[[str], KVStore] = KVStore) -> None:
        self._store_factory = store_factory

    def handle(self, request: str) -> dict[str, Any]:
        if len(request.encode("utf-8")) > MAX_REQUEST_BYTES:
            return persistent_response(413, {"error": "request payload is too large"})
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
                if _json_size(summary) > MAX_REQUEST_BYTES or _json_size(history) > MAX_REQUEST_BYTES:
                    return persistent_response(413, {"error": "scan record is too large"})
                if str(summary.get("_key", "")) != "latest":
                    return persistent_response(400, {"error": "scan summary key must be latest"})
                assessment_id = str(history.get("assessment_id", "")).strip()
                if not assessment_id or str(history.get("_key", "")) != assessment_id:
                    return persistent_response(400, {"error": "scan history key must match assessment_id"})
                try:
                    store.create(SCAN_HISTORY, history)
                except ValueError:
                    return persistent_response(409, {"error": "scan history assessment already exists"})
                try:
                    store.upsert(SCAN_SUMMARIES, summary)
                except Exception:
                    store.delete(SCAN_HISTORY, str(history.get("_key", "")))
                    raise
                history_records = store.list(SCAN_HISTORY)
                if len(history_records) > MAX_SCAN_HISTORY_RECORDS:
                    ordered = sorted(history_records, key=lambda item: str(item.get("completed_at") or item.get("created_at") or item.get("_key", "")))
                    for expired in ordered[: len(history_records) - MAX_SCAN_HISTORY_RECORDS]:
                        store.delete(SCAN_HISTORY, str(expired.get("_key", "")))
                return persistent_response(200, {"durable": True, "mode": "Splunk KV Store"})
            if resource == "lifecycle":
                if operation == "delete":
                    return persistent_response(405, {"error": "lifecycle records are retained; retire the detection instead"})
                record = payload.get("record")
                if not isinstance(record, dict):
                    return persistent_response(400, {"error": "lifecycle record is required"})
                if _json_size(record) > MAX_REQUEST_BYTES:
                    return persistent_response(413, {"error": "lifecycle record is too large"})
                key = str(record.get("_key", "")).strip()
                state = str(record.get("state", "")).strip().lower()
                if not key or state not in ALLOWED_STATES:
                    return persistent_response(400, {"error": "valid lifecycle _key and state are required"})
                incoming_history = record.get("history", [])
                if not isinstance(incoming_history, list) or len(incoming_history) > MAX_HISTORY_EVENTS:
                    return persistent_response(400, {"error": "lifecycle history is invalid or exceeds its limit"})
                existing = store.get(LIFECYCLE, key)
                existing_history = list(existing.get("history", [])) if existing else []
                if incoming_history[: len(existing_history)] != existing_history:
                    return persistent_response(409, {"error": "existing audit history is immutable"})
                if existing:
                    previous_state = str(existing.get("state", "recommendation")).lower()
                    if state not in ALLOWED_TRANSITIONS.get(previous_state, {previous_state}):
                        return persistent_response(409, {"error": f"illegal lifecycle transition: {previous_state} to {state}"})
                    expected = payload.get("expected_revision")
                    current = int(existing.get("_revision", 1))
                    if expected is not None and int(expected) != current:
                        return persistent_response(409, {"error": "lifecycle record changed; reload before saving", "current_revision": current})
                else:
                    current = 0
                new_events = incoming_history[len(existing_history):]
                stamped = existing_history + [dict(event, actor=session_user or "unknown", at=_now()) for event in new_events if isinstance(event, dict)]
                record = dict(record)
                record = _remove_validation_samples(record)
                record["history"] = stamped
                record["updated_by"] = session_user or "unknown"
                record["updated_at"] = _now()
                record["_revision"] = current + 1
                review = record.get("review", {})
                if isinstance(review, dict) and review.get("decision") == "approved":
                    submitted_by = str(review.get("submitted_by", "")).strip()
                    if submitted_by and submitted_by == (session_user or ""):
                        return persistent_response(409, {"error": "submitter cannot approve the same detection version"})
                    review = dict(review)
                    review["reviewed_by"] = session_user or "unknown"
                    review["reviewed_at"] = _now()
                    record["review"] = review
                store.upsert(LIFECYCLE, record)
                return persistent_response(200, {"durable": True, "mode": "Splunk KV Store", "record": record})
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

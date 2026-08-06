"""Regression coverage for field aliases validated against live Splunk samples."""

import json
from pathlib import Path

CATALOG_PATH = Path("app/detections/catalog.json")


def _entry(detection_id: str) -> dict[str, object]:
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    return next(item for item in catalog if item["id"] == detection_id)


def test_high_confidence_vendor_aliases_are_present() -> None:
    iam = _entry("aws-iam-policy-escalation")
    sensitive = _entry("ai-sensitive-data-exposure")
    model_admin = _entry("ai-model-admin-change")
    web_post = _entry("web-anomalous-post-volume")

    assert "userIdentity.userName" in iam["required_fields"]["aws:cloudtrail"][1]
    assert "data_classifications{}" in sensitive["required_fields"]["dlp"][1]
    assert "protoPayload.methodName" in model_admin["required_fields"]["gcp:audit:vertexai"][0]
    assert "uri_path" in web_post["required_fields"]["web.http"][1]


def test_unsafe_semantic_shortcuts_are_not_accepted() -> None:
    identity = _entry("identity-privilege-grant")
    s3 = _entry("aws-s3-public-access")
    sensitive = _entry("ai-sensitive-data-exposure")

    target_group = identity["required_fields"]["identity.authentication"][2]
    bucket_group = s3["required_fields"]["aws:cloudtrail"][1]
    prompt_group = sensitive["required_fields"]["ai:gateway"][1]

    assert "actor.alternateId" not in target_group
    assert "requestParameters.resource" not in bucket_group
    assert "prompt_classification{}" not in prompt_group
    assert "prompt_token_count" not in prompt_group
    assert "sensitive" not in prompt_group

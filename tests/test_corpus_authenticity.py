import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "lab" / "telemetry" / "generate_corpus.py"


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_corpus", GENERATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def profile_by_id(module, profile_id):
    return next(p for p in module.load_profiles() if p["id"] == profile_id)


def test_cloudtrail_event_is_vendor_native_and_semantic():
    module = load_generator()
    event = module.make_event(
        profile_by_id(module, "aws_cloudtrail"),
        "2026-08-07T12:00:00Z",
        module.load_value_contracts(),
    )
    assert "event" not in event
    assert "index" not in event
    assert "sourcetype" not in event
    assert event["eventSource"].endswith("amazonaws.com")
    assert event["eventName"] in {
        "ConsoleLogin",
        "CreateUser",
        "AttachUserPolicy",
        "PutBucketPolicy",
        "StopLogging",
        "RunInstances",
        "AssumeRole",
    }
    assert event["userIdentity"]["type"] in {
        "IAMUser",
        "AssumedRole",
        "Root",
        "AWSService",
    }
    assert event["requestParameters"]["bucketName"] in {
        "corp-logs",
        "finance-archive",
        "security-evidence",
    }


def test_okta_actor_and_target_are_distinct_schema_objects():
    module = load_generator()
    event = module.make_event(
        profile_by_id(module, "okta_system_log"),
        "2026-08-07T12:00:00Z",
        module.load_value_contracts(),
    )
    assert isinstance(event["actor"], dict)
    assert isinstance(event["target"], dict)
    assert "alternateId" in event["actor"]
    assert "alternateId" in event["target"]


def test_manifest_records_vendor_native_format(tmp_path):
    module = load_generator()
    profile = profile_by_id(module, "aws_vpc_flow")
    result = module.write_source(
        profile,
        tmp_path,
        2,
        module.datetime(2026, 8, 1, tzinfo=module.timezone.utc),
        60,
        module.load_value_contracts(),
    )
    assert result["record_format"] == "vendor_native_ndjson"
    first = json.loads(Path(result["file"]).read_text().splitlines()[0])
    assert "event" not in first
    assert first["action"] in {"ACCEPT", "REJECT"}

import importlib.util
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TELEMETRY = ROOT / "lab" / "telemetry"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = _load("dei_test_aws_base", TELEMETRY / "generate_corpus.py")
aws = _load("dei_test_aws_contracts", TELEMETRY / "aws_event_contracts.py")
TS = "2026-08-07T12:00:00Z"


def test_cloudtrail_event_action_fields_are_coherent():
    random.seed(20260807)
    events = [aws.cloudtrail_event(base, TS) for _ in range(1000)]
    names = {e["eventName"] for e in events}
    expected = {
        "ConsoleLogin",
        "CreateUser",
        "AttachUserPolicy",
        "PutBucketPublicAccessBlock",
        "StopLogging",
        "CreateAccessKey",
    }
    assert expected <= names
    for event in events:
        assert event["userIdentity"]["arn"].startswith("arn:aws:iam::")
        assert event["sourceIPAddress"]
        if event["eventName"] == "PutBucketPublicAccessBlock":
            assert event["requestParameters"]["bucketName"]
            assert "PublicAccessBlockConfiguration" in event["requestParameters"]
        if event["eventName"] == "AttachUserPolicy":
            assert event["requestParameters"]["policyArn"].endswith("AdministratorAccess")
        if event["eventName"] == "ConsoleLogin":
            assert event["eventType"] == "AwsConsoleSignIn"
            assert event["responseElements"]["ConsoleLogin"] in {"Success", "Failure"}


def test_guardduty_native_nested_finding_shape():
    event = aws.guardduty_event(base, TS)
    assert event["schemaVersion"] == "2.0"
    assert event["resource"]["resourceType"] == "Instance"
    assert event["service"]["serviceName"] == "guardduty"
    assert 1.0 <= event["severity"] <= 8.9
    assert ":" in event["type"]


def test_vpc_flow_is_default_v2_space_delimited_record():
    record = aws.vpc_flow_record(base, TS)
    parts = record.split(" ")
    assert len(parts) == 14
    assert parts[0] == "2"
    assert parts[1] == aws.AWS_ACCOUNT
    assert parts[2].startswith("eni-")
    assert parts[12] in {"ACCEPT", "REJECT"}
    assert parts[13] == "OK"
    assert aws.serialize("aws_vpc_flow", record) == record


def test_route53_resolver_schema_and_values():
    event = aws.route53_event(base, TS)
    assert event["version"] == "1.1"
    assert event["query_class"] == "IN"
    assert event["rcode"] in {"NOERROR", "NXDOMAIN", "SERVFAIL"}
    assert event["transport"] in {"UDP", "TCP"}
    assert isinstance(event["answers"], list)
    assert "instance" in event["srcids"]


def test_security_hub_asff_required_fields():
    event = aws.security_hub_event(base, TS)
    required = (
        "AwsAccountId",
        "CreatedAt",
        "Description",
        "GeneratorId",
        "Id",
        "ProductArn",
        "Resources",
        "SchemaVersion",
        "Severity",
        "Title",
        "UpdatedAt",
    )
    for field in required:
        assert field in event
    assert event["SchemaVersion"] == "2018-10-08"
    assert event["RecordState"] in {"ACTIVE", "ARCHIVED"}
    assert event["Workflow"]["Status"] in {"NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"}


def test_contract_metadata_has_authorities():
    meta = aws.contract_metadata()
    assert meta["version"] >= 1
    assert len(meta["profiles"]) == 5
    assert all(url.startswith("https://") for url in meta["authorities"].values())

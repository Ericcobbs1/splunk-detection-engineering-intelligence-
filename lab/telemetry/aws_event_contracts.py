"""TA-facing AWS telemetry contracts used by the DEI lab corpus."""
from __future__ import annotations

import json
import random
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

AWS_ACCOUNT = "123456789012"
REGIONS = ("us-east-1", "us-east-2", "us-west-2")


def _uuid() -> str:
    return str(uuid.uuid4())


def _epoch(ts: str) -> int:
    return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())


def cloudtrail_event(base: Any, ts: str) -> Dict[str, Any]:
    """Generate internally coherent CloudTrail management events."""
    region = random.choice(REGIONS)
    actor = base.username()
    source_ip = base.public_ip()
    event_name = random.choice([
        "ConsoleLogin",
        "CreateUser",
        "AttachUserPolicy",
        "PutBucketPublicAccessBlock",
        "StopLogging",
        "CreateAccessKey",
    ])
    event: Dict[str, Any] = {
        "eventVersion": "1.11",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDA" + base.hex_digest(16).upper(),
            "arn": f"arn:aws:iam::{AWS_ACCOUNT}:user/{actor}",
            "accountId": AWS_ACCOUNT,
            "accessKeyId": "AKIA" + base.hex_digest(16).upper(),
            "userName": actor,
        },
        "eventTime": ts,
        "awsRegion": region,
        "sourceIPAddress": source_ip,
        "userAgent": random.choice(["aws-cli/2.17.0", "signin.amazonaws.com", "console.amazonaws.com"]),
        "eventID": _uuid(),
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": AWS_ACCOUNT,
        "responseElements": None,
    }
    if event_name == "ConsoleLogin":
        event.update({
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "eventType": "AwsConsoleSignIn",
            "requestParameters": None,
            "responseElements": {"ConsoleLogin": random.choice(["Success", "Failure"])},
            "additionalEventData": {"MFAUsed": random.choice(["Yes", "No"]), "MobileVersion": "No"},
        })
    elif event_name == "CreateUser":
        target = base.username()
        event.update({
            "eventSource": "iam.amazonaws.com",
            "eventName": event_name,
            "requestParameters": {"userName": target, "path": "/"},
            "responseElements": {"user": {"userName": target, "arn": f"arn:aws:iam::{AWS_ACCOUNT}:user/{target}"}},
        })
    elif event_name == "AttachUserPolicy":
        target = base.username()
        event.update({
            "eventSource": "iam.amazonaws.com",
            "eventName": event_name,
            "requestParameters": {"userName": target, "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        })
    elif event_name == "CreateAccessKey":
        target = base.username()
        event.update({
            "eventSource": "iam.amazonaws.com",
            "eventName": event_name,
            "requestParameters": {"userName": target},
            "responseElements": {"accessKey": {"userName": target, "status": "Active", "accessKeyId": "AKIA" + base.hex_digest(16).upper()}},
        })
    elif event_name == "PutBucketPublicAccessBlock":
        bucket = random.choice(["corp-logs", "finance-archive", "security-evidence"])
        event.update({
            "eventSource": "s3.amazonaws.com",
            "eventName": event_name,
            "requestParameters": {
                "bucketName": bucket,
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": random.choice([True, False]),
                    "IgnorePublicAcls": random.choice([True, False]),
                    "BlockPublicPolicy": random.choice([True, False]),
                    "RestrictPublicBuckets": random.choice([True, False]),
                },
            },
            "resources": [{"type": "AWS::S3::Bucket", "ARN": f"arn:aws:s3:::{bucket}"}],
        })
    else:
        event.update({
            "eventSource": "cloudtrail.amazonaws.com",
            "eventName": "StopLogging",
            "requestParameters": {"name": "organization-security-trail"},
        })
    return event


def guardduty_event(base: Any, ts: str) -> Dict[str, Any]:
    region = random.choice(REGIONS)
    detector = base.hex_digest(32)
    finding_id = base.hex_digest(32)
    finding_type = random.choice([
        "Policy:IAMUser/RootCredentialUsage",
        "Recon:EC2/PortProbeUnprotectedPort",
        "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
        "CredentialAccess:IAMUser/AnomalousBehavior",
    ])
    return {
        "accountId": AWS_ACCOUNT,
        "arn": f"arn:aws:guardduty:{region}:{AWS_ACCOUNT}:detector/{detector}/finding/{finding_id}",
        "createdAt": ts,
        "description": f"GuardDuty detected {finding_type} activity.",
        "id": finding_id,
        "partition": "aws",
        "region": region,
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId": "i-" + base.hex_digest(17),
                "instanceType": "m6i.large",
                "networkInterfaces": [{"privateIpAddress": base.private_ip()}],
            },
        },
        "schemaVersion": "2.0",
        "service": {
            "serviceName": "guardduty",
            "detectorId": detector,
            "eventFirstSeen": ts,
            "eventLastSeen": ts,
            "count": random.randint(1, 20),
            "action": {"actionType": "NETWORK_CONNECTION", "networkConnectionAction": {"blocked": random.choice([True, False])}},
        },
        "severity": round(random.uniform(1.0, 8.9), 1),
        "title": finding_type,
        "type": finding_type,
        "updatedAt": ts,
    }


def vpc_flow_record(base: Any, ts: str) -> str:
    """AWS VPC Flow Logs default version-2 space-delimited record."""
    start = _epoch(ts)
    end = start + random.randint(30, 600)
    protocol = random.choice([6, 17])
    return " ".join(str(v) for v in [
        2,
        AWS_ACCOUNT,
        "eni-" + base.hex_digest(17),
        base.private_ip(),
        base.public_ip(),
        random.randint(1024, 65535),
        random.choice([22, 53, 80, 443, 3389]),
        protocol,
        random.randint(1, 5000),
        random.randint(64, 5000000),
        start,
        end,
        random.choice(["ACCEPT", "REJECT"]),
        "OK",
    ])


def route53_event(base: Any, ts: str) -> Dict[str, Any]:
    qtype = random.choice(["A", "AAAA", "CNAME", "MX", "TXT"])
    query = random.choice(["login.corp.example", "api.corp.example", "updates.vendor.example", "example.com"])
    if qtype == "A":
        rdata = base.public_ip()
    elif qtype == "AAAA":
        rdata = "2001:db8::" + format(random.randint(1, 65535), "x")
    elif qtype == "MX":
        rdata = "10 mail.corp.example"
    elif qtype == "TXT":
        rdata = "v=spf1 include:corp.example -all"
    else:
        rdata = "edge.corp.example"
    return {
        "version": "1.1",
        "account_id": AWS_ACCOUNT,
        "region": random.choice(REGIONS),
        "vpc_id": "vpc-" + base.hex_digest(17),
        "query_timestamp": ts,
        "query_name": query,
        "query_type": qtype,
        "query_class": "IN",
        "rcode": random.choice(["NOERROR", "NXDOMAIN", "SERVFAIL"]),
        "answers": [{"Rdata": rdata, "Type": qtype, "Class": "IN"}],
        "srcaddr": base.private_ip(),
        "srcport": random.randint(1024, 65535),
        "transport": random.choice(["UDP", "TCP"]),
        "srcids": {"instance": "i-" + base.hex_digest(17)},
    }


def security_hub_event(base: Any, ts: str) -> Dict[str, Any]:
    """ASFF payload for the aws:securityhub:finding sourcetype."""
    region = random.choice(REGIONS)
    finding_id = base.hex_digest(32)
    label, normalized = random.choice([("INFORMATIONAL", 0), ("LOW", 20), ("MEDIUM", 50), ("HIGH", 80), ("CRITICAL", 95)])
    return {
        "AwsAccountId": AWS_ACCOUNT,
        "CreatedAt": ts,
        "Description": "Security Hub finding generated from a production-shaped ASFF contract.",
        "FirstObservedAt": ts,
        "GeneratorId": f"arn:aws:securityhub:{region}:{AWS_ACCOUNT}:control/dei-control",
        "Id": f"arn:aws:securityhub:{region}:{AWS_ACCOUNT}:subscription/dei/{finding_id}",
        "LastObservedAt": ts,
        "ProductArn": f"arn:aws:securityhub:{region}::product/aws/securityhub",
        "ProductFields": {"aws/securityhub/FindingId": finding_id},
        "RecordState": random.choice(["ACTIVE", "ARCHIVED"]),
        "Resources": [{"Type": "AwsEc2Instance", "Id": f"arn:aws:ec2:{region}:{AWS_ACCOUNT}:instance/i-{base.hex_digest(17)}", "Region": region}],
        "SchemaVersion": "2018-10-08",
        "Severity": {"Label": label, "Normalized": normalized},
        "SourceUrl": f"https://{region}.console.aws.amazon.com/securityhub/home?region={region}",
        "Title": "Security Hub posture finding",
        "Types": ["Software and Configuration Checks/Vulnerabilities/CVE"],
        "UpdatedAt": ts,
        "Workflow": {"Status": random.choice(["NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"])},
    }


def make_aws_event(profile_id: str, base: Any, ts: str) -> Any:
    if profile_id == "aws_cloudtrail":
        return cloudtrail_event(base, ts)
    if profile_id == "aws_guardduty":
        return guardduty_event(base, ts)
    if profile_id == "aws_vpc_flow":
        return vpc_flow_record(base, ts)
    if profile_id == "aws_route53_dns":
        return route53_event(base, ts)
    if profile_id == "aws_security_hub":
        return security_hub_event(base, ts)
    raise ValueError(f"Unsupported AWS profile: {profile_id}")


def serialize(profile_id: str, event: Any) -> str:
    if profile_id == "aws_vpc_flow":
        return event
    return json.dumps(event, separators=(",", ":"))


def contract_metadata() -> Dict[str, Any]:
    return {
        "version": 1,
        "profiles": ["aws_cloudtrail", "aws_guardduty", "aws_vpc_flow", "aws_route53_dns", "aws_security_hub"],
        "authorities": {
            "vpc_flow": "https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html",
            "route53": "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs-format.html",
            "guardduty": "https://docs.aws.amazon.com/guardduty/latest/APIReference/API_Finding.html",
            "security_hub": "https://docs.aws.amazon.com/securityhub/latest/userguide/asff-required-attributes.html",
            "cloudtrail": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html",
        },
    }

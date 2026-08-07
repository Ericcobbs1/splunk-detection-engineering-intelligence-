#!/usr/bin/env python3
"""Generate documentation-backed vendor-native lab telemetry.

Only verified profiles are emitted. NDJSON files contain raw vendor events only;
index and sourcetype routing metadata lives in manifest.json so Splunk TAs can
parse the same event shape they would receive in production.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent
REGISTRY = ROOT / "source_registry.json"
MEGABATCH = ROOT / "verified_profiles_megabatch.json"
VALUE_CONTRACTS = ROOT / "value_contracts.json"


def load_profiles() -> List[Dict[str, Any]]:
    base = json.loads(REGISTRY.read_text(encoding="utf-8"))["sources"]
    extra = json.loads(MEGABATCH.read_text(encoding="utf-8"))["profiles"]
    by_id = {item["id"]: item for item in base}
    by_id.update({item["id"]: item for item in extra})
    return [p for p in by_id.values() if p.get("status") == "verified"]


def load_value_contracts() -> Dict[str, Dict[str, Any]]:
    return json.loads(VALUE_CONTRACTS.read_text(encoding="utf-8"))


def public_ip() -> str:
    return f"{random.randint(11,223)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"


def private_ip() -> str:
    return f"10.{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(1,254)}"


def timestamp(start: datetime, span_seconds: int) -> str:
    return (start + timedelta(seconds=random.randint(0, span_seconds))).isoformat().replace("+00:00", "Z")


def username() -> str:
    return random.choice(["alice", "bob", "carol", "dave", "svc_backup", "svc_sql", "administrator"])


def email() -> str:
    return f"{username().replace('_','.') }@corp.example"


def hostname() -> str:
    return f"host{random.randint(1,300):03d}.corp.example"


def hex_digest(length: int) -> str:
    seed = f"{uuid.uuid4()}-{random.random()}".encode("utf-8")
    digest = hashlib.sha256(seed).hexdigest()
    while len(digest) < length:
        digest += hashlib.sha256(digest.encode("utf-8")).hexdigest()
    return digest[:length]


def aws_arn() -> str:
    user = username()
    return random.choice([
        f"arn:aws:iam::123456789012:user/{user}",
        f"arn:aws:sts::123456789012:assumed-role/SecurityAnalyst/{user}",
    ])


def structural_value(profile_id: str, field: str, ts: str) -> Optional[Any]:
    leaf = field.split(".")[-1]
    lower = leaf.lower()

    if field in {"requestParameters", "responseElements"} and profile_id == "aws_cloudtrail":
        if field == "requestParameters":
            return {"bucketName": random.choice(["corp-logs", "finance-archive", "security-evidence"])}
        return None
    if field == "resources" and profile_id == "aws_cloudtrail":
        return [{"type": "AWS::S3::Bucket", "ARN": "arn:aws:s3:::corp-logs"}]
    if field == "resource" and profile_id == "aws_guardduty":
        return {"resourceType": "Instance", "instanceDetails": {"instanceId": "i-" + hex_digest(17)}}
    if field == "service" and profile_id == "aws_guardduty":
        return {"serviceName": "guardduty", "detectorId": hex_digest(32)}
    if field == "DeviceDetail" and profile_id == "entra_signin":
        return {"deviceId": str(uuid.uuid4()), "displayName": hostname(), "operatingSystem": "Windows 11", "browser": "Edge 127"}
    if field == "resource.labels" and profile_id == "gcp_audit":
        return {"project_id": "dei-lab-project", "location": "us-central1"}
    if field == "protoPayload.authorizationInfo" and profile_id == "gcp_audit":
        return [{"permission": "resourcemanager.projects.get", "granted": True, "resource": "projects/dei-lab-project"}]
    if field == "events.parameters" and profile_id == "google_workspace":
        return [{"name": "USER_EMAIL", "value": email()}]
    if field == "sourceIPs" and profile_id == "kubernetes_audit":
        return [private_ip()]
    if field == "answers" and profile_id == "aws_route53_dns":
        return [{"Rdata": public_ip(), "Type": "A", "Class": "IN"}]
    if field == "srcids" and profile_id == "aws_route53_dns":
        return {"instance": "i-" + hex_digest(17)}

    if lower in {"timestamp", "eventtime", "createddatetime", "creationtime", "published", "created_at", "query_timestamp", "requestreceivedtimestamp", "stagetimestamp", "createdat", "updatedat", "startdate", "enddate"}:
        return ts
    if lower in {"uuid", "auditid", "correlationid", "request_id", "id", "messageid", "messagetraceid"} or lower.endswith("id"):
        return str(uuid.uuid4())
    if lower in {"sha256", "filedigest"}:
        return hex_digest(64)
    if lower == "sha1":
        return hex_digest(40)
    if lower in {"clientip", "ipaddress", "sourceipaddress", "callerip", "remoteip", "srcaddr", "src", "sourceips"}:
        return private_ip()
    if lower in {"serverip", "dstaddr", "dst", "localip"}:
        return public_ip()
    if "port" in lower or lower in {"sport", "dport", "srcport", "dstport", "natsport", "natdport"}:
        return random.choice([22, 53, 80, 443, 3389, 8080])
    if lower in {"bytes", "bytes_sent", "bytes_received", "packets", "size", "run_time"}:
        return random.randint(64, 250000)
    if lower in {"user", "username", "accountname", "targetusername", "subjectusername", "srcuser", "dstuser"}:
        return username()
    if lower in {"userprincipalname", "principalemail", "actor.email", "senderaddress", "recipientaddress", "userid"} or "email" in lower:
        return email()
    if lower in {"hostname", "devicename", "computer"}:
        return hostname()
    if field in {"userIdentity.arn"}:
        return aws_arn()
    if field in {"userIdentity.userName", "userIdentity.sessionContext.sessionIssuer.userName"}:
        return username()
    if lower in {"url", "uri", "clientrequesturi"}:
        return random.choice(["https://portal.corp.example/", "https://api.corp.example/v1/users", "https://files.corp.example/download"])
    if lower in {"clientrequesthost"}:
        return random.choice(["portal.corp.example", "api.corp.example", "files.corp.example"])
    if lower in {"clientrequestpath"}:
        return random.choice(["/", "/login", "/api/v1/users", "/download"])
    if lower in {"useragent", "clientrequestuseragent", "client.useragent.rawuseragent"}:
        return random.choice(["Mozilla/5.0", "curl/8.7.1", "aws-cli/2.17.0"])
    if lower in {"account-id", "accountid", "account_id", "recipientaccountid", "organization_id"}:
        return "123456789012"
    if lower in {"region", "awsregion"}:
        return random.choice(["us-east-1", "us-east-2", "us-west-2"])
    return None


def fallback_value(field: str) -> Any:
    leaf = field.split(".")[-1]
    if leaf in {"readOnly", "managementEvent", "public"}:
        return random.choice([True, False])
    return f"dei-lab-{leaf.lower()}-{random.randint(1,9999)}"


def assign_nested(event: Dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = event
    for part in parts[:-1]:
        child = cur.get(part)
        if not isinstance(child, dict):
            child = {}
            cur[part] = child
        cur = child
    cur[parts[-1]] = value


def make_event(profile: Dict[str, Any], ts: str, external_contracts: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    event: Dict[str, Any] = {}
    contracts: Dict[str, Any] = dict(profile.get("value_contracts", {}))
    contracts.update(external_contracts.get(profile["id"], {}))
    for field in profile["raw_fields"]:
        contract = contracts.get(field)
        if isinstance(contract, list) and contract:
            value = random.choice(contract)
        elif isinstance(contract, dict) and contract.get("type") == "number":
            value = round(random.uniform(float(contract.get("min", 0)), float(contract.get("max", 100))), 1)
        else:
            value = structural_value(profile["id"], field, ts)
            if value is None and field != "responseElements":
                value = fallback_value(field)
        if field == "responseElements" and value is None:
            value = None
        assign_nested(event, field, value)
    return event


def write_source(profile: Dict[str, Any], out: Path, count: int, start: datetime, span: int, contracts: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    sourcetype = profile["sourcetypes"][0]
    target = out / profile["target_index"]
    target.mkdir(parents=True, exist_ok=True)
    path = target / f"{profile['id']}.ndjson"
    with path.open("w", encoding="utf-8") as handle:
        for _ in range(count):
            ts = timestamp(start, span)
            handle.write(json.dumps(make_event(profile, ts, contracts), separators=(",", ":")) + "\n")
    return {
        "id": profile["id"],
        "index": profile["target_index"],
        "sourcetype": sourcetype,
        "events": count,
        "file": str(path),
        "record_format": "vendor_native_ndjson",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="dist/siem-corpus")
    parser.add_argument("--events-per-source", type=int, default=5000)
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--seed", type=int, default=20260807)
    args = parser.parse_args()
    random.seed(args.seed)
    profiles = load_profiles()
    contracts = load_value_contracts()
    if not profiles:
        raise SystemExit("No verified profiles available")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=args.days)
    span = args.days * 86400
    manifest = [write_source(p, out, args.events_per_source, start, span, contracts) for p in profiles]
    (out / "manifest.json").write_text(
        json.dumps({"generated_at": now.isoformat(), "record_format": "vendor_native_ndjson", "sources": manifest}, indent=2),
        encoding="utf-8",
    )
    print(f"Generated {len(manifest)} verified vendor-native source datasets / {len(manifest) * args.events_per_source:,} events")


if __name__ == "__main__":
    main()

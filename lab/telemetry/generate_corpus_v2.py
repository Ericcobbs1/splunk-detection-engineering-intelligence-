#!/usr/bin/env python3
"""Build the complete DEI searchable-event corpus from every verified registry.

This is intentionally a lab searchable-schema representation, not a claim that
all products emit JSON on the wire. Field names, object shapes, and value domains
come from the verified vendor/Splunk profiles. Splunk routing metadata remains in
the manifest; vendor/TAs provide CIM knowledge after ingestion where applicable.
"""
from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent
BASE_GENERATOR = ROOT / "generate_corpus.py"
BATCH2 = ROOT / "source_registry_batch2.json"
RECORD_FORMAT = "authoritative_searchable_json"

_BASE_SPEC = importlib.util.spec_from_file_location("dei_generate_corpus_base", BASE_GENERATOR)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError(f"Unable to load base corpus generator: {BASE_GENERATOR}")
base = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(base)


def _normalize_profile(profile: Dict[str, Any]) -> Dict[str, Any]:
    profile = copy.deepcopy(profile)
    contracts = profile.get("value_contracts", {})
    for field, contract in list(contracts.items()):
        if isinstance(contract, dict) and contract.get("examples"):
            contracts[field] = contract["examples"]
    return profile


def load_profiles() -> List[Dict[str, Any]]:
    profiles = base.load_profiles()
    batch2 = json.loads(BATCH2.read_text(encoding="utf-8"))["sources"]
    by_id = {item["id"]: item for item in profiles}
    by_id.update({item["id"]: item for item in batch2})
    return [
        _normalize_profile(profile)
        for profile in by_id.values()
        if profile.get("status") == "verified"
    ]


def _batch2_semantics(profile_id: str, event: Dict[str, Any]) -> Dict[str, Any]:
    if profile_id == "crowdstrike_fdr_sensor":
        event["event_simpleName"] = random.choice(
            ["InjectedThread", "ProcessRollup2", "NetworkConnectIP4", "DnsRequest"]
        )
        event["event_platform"] = random.choice(["Win", "Lin", "Mac"])
        event["aip"] = base.public_ip()
        event["aid"] = base.hex_digest(32)
        event["cid"] = base.hex_digest(32)

    elif profile_id == "aws_security_hub":
        severity = random.choice(
            [
                ("INFORMATIONAL", 0),
                ("LOW", 20),
                ("MEDIUM", 50),
                ("HIGH", 80),
                ("CRITICAL", 95),
            ]
        )
        event["Severity"] = {"Label": severity[0], "Normalized": severity[1]}
        event["Workflow"] = {
            "Status": random.choice(["NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"])
        }
        event["Resources"] = [
            {
                "Type": "AwsEc2Instance",
                "Id": "arn:aws:ec2:us-east-1:123456789012:instance/i-" + base.hex_digest(17),
                "Region": "us-east-1",
            }
        ]
        event["ProductArn"] = (
            "arn:aws:securityhub:us-east-1::product/aws/securityhub"
        )
        event["ProductFields"] = {"aws/securityhub/FindingId": base.hex_digest(32)}
        event["SchemaVersion"] = "2018-10-08"

    elif profile_id == "azure_activity":
        event["identity"] = {
            "authorization": {
                "action": "Microsoft.Compute/virtualMachines/write",
                "scope": "/subscriptions/00000000-0000-0000-0000-000000000001",
            },
            "claims": {"name": base.email()},
        }
        event["properties"] = {
            "statusCode": random.choice(["OK", "Created", "Forbidden"]),
            "serviceRequestId": base.hex_digest(32),
        }
        event["operationName"] = random.choice(
            [
                "Microsoft.Compute/virtualMachines/write",
                "Microsoft.Authorization/roleAssignments/write",
                "Microsoft.Storage/storageAccounts/write",
            ]
        )
        event["callerIpAddress"] = base.public_ip()
        event["resourceId"] = (
            "/subscriptions/00000000-0000-0000-0000-000000000001/"
            "resourceGroups/dei-lab/providers/Microsoft.Compute/virtualMachines/vm01"
        )

    elif profile_id == "cisco_asa":
        event["message_id"] = random.choice(
            ["113019", "113039", "602303", "602304", "611101", "611103", "716001", "722022", "723001"]
        )
        event["src_ip"] = base.private_ip()
        event["dest_ip"] = base.public_ip()
        event["src_port"] = random.randint(1024, 65535)
        event["dest_port"] = random.choice([22, 53, 80, 443, 3389])
        event["protocol"] = random.choice(["tcp", "udp"])
        event["action"] = random.choice(["allowed", "blocked", "teardown", "built"])
        event["user"] = base.username()
        event["duration"] = random.randint(1, 3600)
        event["bytes_in"] = random.randint(64, 500000)
        event["bytes_out"] = random.randint(64, 500000)

    return event


def make_event(
    profile: Dict[str, Any],
    ts: str,
    contracts: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    event = base.make_event(profile, ts, contracts)
    return _batch2_semantics(profile["id"], event)


def write_source(
    profile: Dict[str, Any],
    out: Path,
    count: int,
    start: datetime,
    span: int,
    contracts: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    sourcetype = profile["sourcetypes"][0]
    target = out / profile["target_index"]
    target.mkdir(parents=True, exist_ok=True)
    path = target / f"{profile['id']}.ndjson"
    with path.open("w", encoding="utf-8") as handle:
        for _ in range(count):
            ts = base.timestamp(start, span)
            handle.write(json.dumps(make_event(profile, ts, contracts), separators=(",", ":")) + "\n")
    return {
        "id": profile["id"],
        "index": profile["target_index"],
        "sourcetype": sourcetype,
        "events": count,
        "file": str(path),
        "record_format": RECORD_FORMAT,
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
    contracts = base.load_value_contracts()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=args.days)
    span = args.days * 86400
    manifest = [
        write_source(profile, out, args.events_per_source, start, span, contracts)
        for profile in profiles
    ]
    (out / "manifest.json").write_text(
        json.dumps(
            {
                "generated_at": now.isoformat(),
                "record_format": RECORD_FORMAT,
                "sources": manifest,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(
        f"Generated {len(manifest)} verified searchable-schema datasets / "
        f"{len(manifest) * args.events_per_source:,} events"
    )


if __name__ == "__main__":
    main()

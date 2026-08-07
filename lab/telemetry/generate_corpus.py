#!/usr/bin/env python3
"""Generate schema-authentic lab telemetry only from verified source profiles.

The generator intentionally refuses pending/unverified profiles. It emits NDJSON
records per source/index/sourcetype and a manifest; source-specific event builders
are added as profiles are promoted from documentation-backed schemas.
"""
from __future__ import annotations

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

ROOT = Path(__file__).resolve().parent
REGISTRY = ROOT / "source_registry.json"
MEGABATCH = ROOT / "verified_profiles_megabatch.json"


def load_profiles() -> List[Dict[str, Any]]:
    base = json.loads(REGISTRY.read_text(encoding="utf-8"))["sources"]
    extra = json.loads(MEGABATCH.read_text(encoding="utf-8"))["profiles"]
    by_id = {item["id"]: item for item in base}
    by_id.update({item["id"]: item for item in extra})
    return [p for p in by_id.values() if p.get("status") == "verified"]


def ip(private: bool = False) -> str:
    if private:
        return f"10.{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
    return f"{random.randint(11,223)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"


def timestamp(start: datetime, span_seconds: int) -> str:
    return (start + timedelta(seconds=random.randint(0, span_seconds))).isoformat().replace("+00:00", "Z")


def generic_value(field: str, ts: str) -> Any:
    leaf = field.split(".")[-1].lower()
    if leaf in {"timestamp", "eventtime", "createddatetime", "creationtime", "published", "created_at", "query_timestamp", "requestreceivedtimestamp", "stagetimestamp"}:
        return ts
    if "ip" in leaf or leaf in {"srcaddr", "dstaddr", "clientip", "sourceips"}:
        return ip(leaf.startswith("src") or leaf.startswith("client"))
    if "port" in leaf or leaf in {"sport", "dport", "srcport", "dstport"}:
        return random.choice([22, 53, 80, 443, 3389, 8080])
    if leaf in {"bytes", "bytes_sent", "bytes_received", "packets", "size"}:
        return random.randint(64, 250000)
    if leaf in {"severity"}:
        return random.choice(["low", "medium", "high", "critical"])
    if leaf in {"user", "username", "accountname", "targetusername", "subjectusername"}:
        return f"user{random.randint(1,500):04d}"
    if leaf in {"hostname", "devicename", "computer"}:
        return f"host{random.randint(1,300):03d}.corp.example"
    if leaf in {"action"}:
        return random.choice(["allow", "deny", "success", "failure"])
    return f"sample-{leaf}-{random.randint(1,9999)}"


def assign_nested(event: Dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = event
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


def make_event(profile: Dict[str, Any], ts: str) -> Dict[str, Any]:
    event: Dict[str, Any] = {}
    contracts = profile.get("value_contracts", {})
    for field in profile["raw_fields"]:
        contract = contracts.get(field)
        if isinstance(contract, list) and contract:
            value = random.choice(contract)
        elif isinstance(contract, dict) and contract.get("type") == "number":
            value = round(random.uniform(float(contract.get("min", 0)), float(contract.get("max", 100))), 1)
        else:
            value = generic_value(field, ts)
        assign_nested(event, field, value)
    event.setdefault("dei_lab_event_id", str(uuid.uuid4()))
    return event


def write_source(profile: Dict[str, Any], out: Path, count: int, start: datetime, span: int) -> Dict[str, Any]:
    sourcetype = profile["sourcetypes"][0]
    target = out / profile["target_index"]
    target.mkdir(parents=True, exist_ok=True)
    path = target / f"{profile['id']}.ndjson"
    with path.open("w", encoding="utf-8") as handle:
        for _ in range(count):
            ts = timestamp(start, span)
            wrapper = {"time": ts, "sourcetype": sourcetype, "index": profile["target_index"], "event": make_event(profile, ts)}
            handle.write(json.dumps(wrapper, separators=(",", ":")) + "\n")
    return {"id": profile["id"], "index": profile["target_index"], "sourcetype": sourcetype, "events": count, "file": str(path)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="dist/siem-corpus")
    parser.add_argument("--events-per-source", type=int, default=5000)
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--seed", type=int, default=20260807)
    args = parser.parse_args()
    random.seed(args.seed)
    profiles = load_profiles()
    if not profiles:
        raise SystemExit("No verified profiles available")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=args.days)
    span = args.days * 86400
    manifest = [write_source(p, out, args.events_per_source, start, span) for p in profiles]
    (out / "manifest.json").write_text(json.dumps({"generated_at": now.isoformat(), "sources": manifest}, indent=2), encoding="utf-8")
    print(f"Generated {len(manifest)} verified source datasets / {len(manifest) * args.events_per_source:,} events")


if __name__ == "__main__":
    main()

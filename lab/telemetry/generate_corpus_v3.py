#!/usr/bin/env python3
"""Generate the DEI corpus with event-specific semantic telemetry contracts.

V3 keeps all verified v2 profiles but routes Windows Security and PowerShell
through Microsoft event-specific contracts instead of a single generic field
shape per dataset.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent
V2_PATH = ROOT / "generate_corpus_v2.py"
WINDOWS_PATH = ROOT / "windows_event_contracts.py"
RECORD_FORMAT = "authoritative_searchable_json"


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


v2 = _load_module("dei_generate_corpus_v2", V2_PATH)
windows = _load_module("dei_windows_event_contracts", WINDOWS_PATH)


def load_profiles() -> List[Dict[str, Any]]:
    return v2.load_profiles()


def make_event(
    profile: Dict[str, Any],
    ts: str,
    contracts: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    if profile["id"] in {"windows_security", "windows_powershell"}:
        return windows.make_windows_event(profile["id"], v2.base)
    return v2.make_event(profile, ts, contracts)


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
            ts = v2.base.timestamp(start, span)
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
    contracts = v2.base.load_value_contracts()
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
                "telemetry_contracts": {"windows": windows.contract_metadata()},
                "sources": manifest,
            },
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    print(
        f"Generated {len(manifest)} verified searchable-schema datasets / "
        f"{len(manifest) * args.events_per_source:,} events"
    )


if __name__ == "__main__":
    main()

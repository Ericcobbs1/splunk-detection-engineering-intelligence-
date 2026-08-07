#!/usr/bin/env python3
"""Generate, ingest, and validate the 26-source DEI runtime canary in Splunk."""
from __future__ import annotations

import csv
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Sequence, Set

ROOT = Path(__file__).resolve().parents[2]
TELEMETRY = ROOT / "lab" / "telemetry"
OUT = ROOT / "dist" / "runtime-canary"
GENERATOR = TELEMETRY / "generate_corpus_v3.py"
ROUTING = TELEMETRY / "dataset_routing.json"
CONTRACTS = TELEMETRY / "runtime_validation_contracts.json"
REPORT = OUT / "runtime_validation_report.json"
SPLUNK = Path(os.environ.get("SPLUNK_CLI", "/Applications/Splunk/bin/splunk"))
SPLUNK_AUTH = os.environ.get("SPLUNK_AUTH")


def run(cmd: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(shlex.quote(x) for x in cmd))
    return subprocess.run(list(cmd), text=True, capture_output=True, check=check)


def splunk_args() -> List[str]:
    args: List[str] = []
    if SPLUNK_AUTH:
        args.extend(["-auth", SPLUNK_AUTH])
    return args


def search_csv(spl: str) -> List[Dict[str, str]]:
    cmd = [str(SPLUNK), "search", spl, "-output", "csv"] + splunk_args()
    proc = run(cmd, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())
    return list(csv.DictReader(proc.stdout.splitlines()))


def inventory(index: str, source: str) -> Set[str]:
    escaped_source = source.replace('"', '\\"')
    spl = (
        f'search index="{index}" source="{escaped_source}" earliest=-30m latest=now '
        "| head 200 | fieldsummary | fields field count distinct_count"
    )
    rows = search_csv(spl)
    return {row.get("field", "") for row in rows if row.get("field")}


def event_count(index: str, source: str) -> int:
    escaped_source = source.replace('"', '\\"')
    rows = search_csv(
        f'search index="{index}" source="{escaped_source}" earliest=-30m latest=now | stats count'
    )
    if not rows:
        return 0
    return int(rows[0].get("count", "0") or 0)


def cim_count(model_dataset: str, index: str, source: str) -> int:
    model, dataset = model_dataset.split(".", 1)
    escaped_source = source.replace('"', '\\"')
    spl = (
        f'| datamodel {model} {dataset} search '
        f'| search index="{index}" source="{escaped_source}" '
        "| stats count"
    )
    try:
        rows = search_csv(spl)
    except RuntimeError:
        return 0
    if not rows:
        return 0
    return int(rows[0].get("count", "0") or 0)


def main() -> int:
    if not SPLUNK.exists():
        print(f"Splunk CLI not found: {SPLUNK}", file=sys.stderr)
        return 2

    if OUT.exists():
        import shutil

        shutil.rmtree(OUT)

    run([sys.executable, str(GENERATOR), "--out", str(OUT), "--events-per-source", "25", "--days", "1"])

    manifest = json.loads((OUT / "manifest.json").read_text(encoding="utf-8"))
    routing = json.loads(ROUTING.read_text(encoding="utf-8"))["datasets"]
    contracts = json.loads(CONTRACTS.read_text(encoding="utf-8"))["datasets"]

    results: Dict[str, Any] = {}

    for item in manifest["sources"]:
        dataset = item["id"]
        route = routing[dataset]
        path = Path(item["file"]).resolve()
        cmd = [
            str(SPLUNK),
            "add",
            "oneshot",
            str(path),
            "-index",
            route["index"],
            "-sourcetype",
            route["sourcetype"],
        ] + splunk_args()
        proc = run(cmd, check=False)
        results[dataset] = {
            "index": route["index"],
            "sourcetype": route["sourcetype"],
            "source": str(path),
            "ingest_ok": proc.returncode == 0,
            "ingest_stdout": proc.stdout.strip(),
            "ingest_stderr": proc.stderr.strip(),
        }

    print("Waiting for Splunk indexing/search-time knowledge...")
    time.sleep(10)

    overall = True
    for dataset, result in results.items():
        if not result["ingest_ok"]:
            result.update({"event_count": 0, "field_groups_ok": False, "cim_ok": False, "status": "FAIL"})
            overall = False
            continue

        count = event_count(result["index"], result["source"])
        fields = inventory(result["index"], result["source"])
        spec = contracts[dataset]
        group_results = []
        for group in spec["required_any_groups"]:
            matched = sorted(set(group) & fields)
            group_results.append({"group": group, "matched": matched, "ok": bool(matched)})
        fields_ok = count > 0 and all(x["ok"] for x in group_results)

        probes = []
        for probe in spec.get("cim_probes", []):
            n = cim_count(probe, result["index"], result["source"])
            probes.append({"model_dataset": probe, "count": n, "ok": n > 0})
        cim_required = bool(spec.get("cim_probes"))
        cim_ok = (not cim_required) or any(x["ok"] for x in probes)
        status = "PASS" if fields_ok and cim_ok else "FAIL"
        overall = overall and status == "PASS"
        result.update(
            {
                "event_count": count,
                "extracted_fields": sorted(fields),
                "required_groups": group_results,
                "field_groups_ok": fields_ok,
                "cim_probes": probes,
                "cim_ok": cim_ok,
                "status": status,
            }
        )
        print(f"{dataset:30} {status} events={count} fields={len(fields)} cim={cim_ok}")

    payload = {
        "runtime_verified": overall,
        "datasets_total": len(results),
        "datasets_passed": sum(1 for r in results.values() if r.get("status") == "PASS"),
        "datasets_failed": [k for k, r in results.items() if r.get("status") != "PASS"],
        "results": results,
    }
    REPORT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"\nReport: {REPORT}")
    print("MERGE GATE:", "PASS" if overall else "FAIL")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())

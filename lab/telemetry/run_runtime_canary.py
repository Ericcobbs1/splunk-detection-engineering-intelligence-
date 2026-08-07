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
from typing import Any, Dict, List, Sequence, Set, Tuple

ROOT = Path(__file__).resolve().parents[2]
TELEMETRY = ROOT / "lab" / "telemetry"
OUT = ROOT / "dist" / "runtime-canary"
GENERATOR = TELEMETRY / "generate_corpus_v3.py"
ROUTING = TELEMETRY / "dataset_routing.json"
CONTRACTS = TELEMETRY / "runtime_validation_contracts.json"
REPORT = OUT / "runtime_validation_report.json"
SPLUNK = Path(os.environ.get("SPLUNK_CLI", "/Applications/Splunk/bin/splunk"))
SPLUNK_AUTH = os.environ.get("SPLUNK_AUTH")
INDEX_TIMEOUT_SECONDS = int(os.environ.get("DEI_CANARY_INDEX_TIMEOUT", "120"))
INDEX_POLL_SECONDS = int(os.environ.get("DEI_CANARY_INDEX_POLL", "5"))


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


def scoped_search(index: str, source: str) -> str:
    escaped_source = source.replace('"', '\\"')
    return f'search index="{index}" source="{escaped_source}" earliest=-2d latest=now'


def inventory(index: str, source: str) -> Set[str]:
    rows = search_csv(
        scoped_search(index, source)
        + " | head 200 | fieldsummary | fields field count distinct_count"
    )
    return {row.get("field", "") for row in rows if row.get("field")}


def event_count(index: str, source: str) -> int:
    rows = search_csv(scoped_search(index, source) + " | stats count")
    if not rows:
        return 0
    return int(rows[0].get("count", "0") or 0)


def wait_for_expected_count(index: str, source: str, expected: int) -> Tuple[int, bool, float]:
    """Wait for the current canary source to become fully searchable."""
    started = time.monotonic()
    count = 0
    while True:
        count = event_count(index, source)
        elapsed = time.monotonic() - started
        if count >= expected:
            return count, True, elapsed
        if elapsed >= INDEX_TIMEOUT_SECONDS:
            return count, False, elapsed
        print(
            f"  waiting for indexing: {index} source={source} "
            f"events={count}/{expected}"
        )
        time.sleep(INDEX_POLL_SECONDS)


def cim_count(model_dataset: str, index: str, source: str) -> int:
    model, dataset = model_dataset.split(".", 1)
    escaped_source = source.replace('"', '\\"')
    spl = (
        f'| datamodel {model} {dataset} search '
        f'| search index="{index}" source="{escaped_source}" earliest=-2d latest=now '
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

    OUT.mkdir(parents=True, exist_ok=True)
    run_id = str(int(time.time()))
    run_out = OUT / run_id

    run(
        [
            sys.executable,
            str(GENERATOR),
            "--out",
            str(run_out),
            "--events-per-source",
            "25",
            "--days",
            "1",
        ]
    )

    manifest = json.loads((run_out / "manifest.json").read_text(encoding="utf-8"))
    routing = json.loads(ROUTING.read_text(encoding="utf-8"))["datasets"]
    contracts = json.loads(CONTRACTS.read_text(encoding="utf-8"))["datasets"]
    results: Dict[str, Any] = {}

    for item in manifest["sources"]:
        dataset = item["id"]
        route = routing[dataset]
        path = Path(item["file"]).resolve()
        canary_source = f"dei_runtime_canary:{run_id}:{dataset}"
        cmd = [
            str(SPLUNK),
            "add",
            "oneshot",
            str(path),
            "-index",
            route["index"],
            "-sourcetype",
            route["sourcetype"],
            "-rename-source",
            canary_source,
        ] + splunk_args()
        proc = run(cmd, check=False)
        results[dataset] = {
            "index": route["index"],
            "sourcetype": route["sourcetype"],
            "source": canary_source,
            "file": str(path),
            "expected_events": int(item["events"]),
            "ingest_ok": proc.returncode == 0,
            "ingest_stdout": proc.stdout.strip(),
            "ingest_stderr": proc.stderr.strip(),
        }

    print("Waiting for each canary source to become searchable...")

    overall = True
    for dataset, result in results.items():
        if not result["ingest_ok"]:
            result.update(
                {
                    "event_count": 0,
                    "indexing_complete": False,
                    "field_groups_ok": False,
                    "cim_ok": False,
                    "status": "FAIL",
                }
            )
            overall = False
            continue

        count, indexing_complete, wait_seconds = wait_for_expected_count(
            result["index"], result["source"], result["expected_events"]
        )
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
        status = "PASS" if indexing_complete and fields_ok and cim_ok else "FAIL"
        overall = overall and status == "PASS"
        result.update(
            {
                "event_count": count,
                "indexing_complete": indexing_complete,
                "index_wait_seconds": round(wait_seconds, 2),
                "extracted_fields": sorted(fields),
                "required_groups": group_results,
                "field_groups_ok": fields_ok,
                "cim_probes": probes,
                "cim_ok": cim_ok,
                "status": status,
            }
        )
        print(
            f"{dataset:30} {status} events={count}/{result['expected_events']} "
            f"fields={len(fields)} cim={cim_ok} indexing={indexing_complete}"
        )

    payload = {
        "runtime_verified": overall,
        "run_id": run_id,
        "index_timeout_seconds": INDEX_TIMEOUT_SECONDS,
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

#!/usr/bin/env bash
set -euo pipefail

TARGET_MB="${1:-1024}"
DAYS="${2:-7}"
OUT="${3:-dist/siem-corpus}"
GENERATOR="lab/telemetry/generate_corpus_v3.py"
ROUTING="lab/telemetry/dataset_routing.json"

apply_routing() {
  python3 - "$OUT" "$ROUTING" <<'PY'
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
routing_path = Path(sys.argv[2])
manifest_path = out / "manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
routing = json.loads(routing_path.read_text(encoding="utf-8"))["datasets"]

sources = manifest["sources"]
source_ids = {item["id"] for item in sources}
missing = source_ids - set(routing)
if missing:
    raise SystemExit(f"Missing dedicated routing for: {sorted(missing)}")

for item in sources:
    route = routing[item["id"]]
    item["index"] = route["index"]
    item["sourcetype"] = route["sourcetype"]

indexes = [item["index"] for item in sources]
if len(indexes) != len(set(indexes)):
    raise SystemExit("Dedicated-index policy violation: duplicate indexes detected")

manifest["index_policy"] = "one_dataset_per_index"
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
print(f"Applied dedicated index routing to {len(sources)} datasets")
PY
}

measure_payload_bytes() {
  python3 - "$OUT" <<'PY'
import json, sys
from pathlib import Path
out = Path(sys.argv[1])
manifest = json.loads((out / "manifest.json").read_text())
total = 0
for item in manifest["sources"]:
    p = Path(item["file"])
    if not p.is_absolute():
        # Manifest paths are repo-relative or already rooted under OUT.
        if not p.exists():
            p = Path.cwd() / p
    if not p.exists():
        raise SystemExit(f"Missing corpus payload: {p}")
    total += p.stat().st_size
print(total)
PY
}

mkdir -p "$OUT"

# Start with a representative event count, measure every manifest payload format,
# then scale once. This includes JSON, XML, CSV, syslog, delimited, and text logs.
python3 "$GENERATOR" --out "$OUT" --events-per-source 5000 --days "$DAYS"
apply_routing
ACTUAL_BYTES=$(measure_payload_bytes)

TARGET_BYTES=$((TARGET_MB * 1024 * 1024))
if [[ "$ACTUAL_BYTES" -le 0 ]]; then
  echo "Unable to measure generated corpus size" >&2
  exit 1
fi

SOURCE_COUNT=$(python3 - "$OUT" <<'PY'
import json
import sys
from pathlib import Path
p=Path(sys.argv[1])/'manifest.json'
if not p.exists():
    raise SystemExit(1)
print(len(json.loads(p.read_text())['sources']))
PY
)

BASE_TOTAL_EVENTS=$((SOURCE_COUNT * 5000))
SCALED_TOTAL_EVENTS=$(( (BASE_TOTAL_EVENTS * TARGET_BYTES + ACTUAL_BYTES - 1) / ACTUAL_BYTES ))
EVENTS_PER_SOURCE=$(( (SCALED_TOTAL_EVENTS + SOURCE_COUNT - 1) / SOURCE_COUNT ))

rm -rf "$OUT"
python3 "$GENERATOR" --out "$OUT" --events-per-source "$EVENTS_PER_SOURCE" --days "$DAYS"
apply_routing
FINAL_BYTES=$(measure_payload_bytes)

python3 - "$OUT" "$TARGET_MB" "$EVENTS_PER_SOURCE" "$FINAL_BYTES" <<'PY'
import json,sys
from pathlib import Path
out=Path(sys.argv[1]); target=int(sys.argv[2]); eps=int(sys.argv[3]); size=int(sys.argv[4])
manifest=json.loads((out/'manifest.json').read_text())
manifest['target_mb']=target
manifest['events_per_source']=eps
manifest['actual_bytes']=size
manifest['actual_mb']=round(size/1024/1024,2)
(out/'manifest.json').write_text(json.dumps(manifest,indent=2) + "\n")
print(f"Corpus ready: {manifest['actual_mb']} MB across {len(manifest['sources'])} verified sources")
print(f"Index policy: {manifest.get('index_policy')}")
PY

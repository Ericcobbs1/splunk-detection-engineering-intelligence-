#!/usr/bin/env bash
set -euo pipefail

TARGET_MB="${1:-1024}"
DAYS="${2:-7}"
OUT="${3:-dist/siem-corpus}"

mkdir -p "$OUT"

# Start with a representative event count, measure output, then scale once.
python3 lab/telemetry/generate_corpus.py --out "$OUT" --events-per-source 5000 --days "$DAYS"

ACTUAL_BYTES=$(find "$OUT" -type f -name '*.ndjson' -print0 | xargs -0 stat -f%z 2>/dev/null | awk '{s+=$1} END{print s+0}')
if [[ "$ACTUAL_BYTES" -eq 0 ]]; then
  ACTUAL_BYTES=$(find "$OUT" -type f -name '*.ndjson' -printf '%s\n' 2>/dev/null | awk '{s+=$1} END{print s+0}')
fi

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
python3 lab/telemetry/generate_corpus.py --out "$OUT" --events-per-source "$EVENTS_PER_SOURCE" --days "$DAYS"

FINAL_BYTES=$(find "$OUT" -type f -name '*.ndjson' -print0 | xargs -0 stat -f%z 2>/dev/null | awk '{s+=$1} END{print s+0}')
if [[ "$FINAL_BYTES" -eq 0 ]]; then
  FINAL_BYTES=$(find "$OUT" -type f -name '*.ndjson' -printf '%s\n' 2>/dev/null | awk '{s+=$1} END{print s+0}')
fi

python3 - "$OUT" "$TARGET_MB" "$EVENTS_PER_SOURCE" "$FINAL_BYTES" <<'PY'
import json,sys
from pathlib import Path
out=Path(sys.argv[1]); target=int(sys.argv[2]); eps=int(sys.argv[3]); size=int(sys.argv[4])
manifest=json.loads((out/'manifest.json').read_text())
manifest['target_mb']=target
manifest['events_per_source']=eps
manifest['actual_bytes']=size
manifest['actual_mb']=round(size/1024/1024,2)
(out/'manifest.json').write_text(json.dumps(manifest,indent=2))
print(f"Corpus ready: {manifest['actual_mb']} MB across {len(manifest['sources'])} verified sources")
PY

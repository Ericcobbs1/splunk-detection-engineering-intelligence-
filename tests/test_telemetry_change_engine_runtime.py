"""Execute the browser change-comparison logic with representative scan snapshots."""

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "app" / "appserver" / "static" / "dei_environment_scan_v1.js"


def test_comparison_reports_drift_and_detection_readiness_impact() -> None:
    script = r"""
const fs=require("fs");
const source=fs.readFileSync(process.argv[1],"utf8");
const start=source.indexOf("function lowerMap");
const end=source.indexOf("function collectionEndpoint",start);
if(start<0||end<0) throw new Error("comparison helpers not found");
eval(source.slice(start,end));
const baseline={
  assessment_id:"scan-before",source_types:["aws:cloudtrail","legacy:dns"],
  fields_by_source:{"aws:cloudtrail":["user","action","legacy_field"],"legacy:dns":["query"]},
  fields_by_scope:{"aws::aws:cloudtrail":["user","action","legacy_field"],"dns::legacy:dns":["query"]},
  discovery_rows:[{index:"aws",sourcetype:"aws:cloudtrail",count:1000},{index:"dns",sourcetype:"legacy:dns",count:500}],
  report:{recommendations:[
    {detection_id:"new-ready",name:"New Ready",readiness:"field_gap"},
    {detection_id:"regressed",name:"Regressed",readiness:"production_ready"}
  ]}
};
const current={
  source_types:["aws:cloudtrail","cribl:normalized:dns"],
  fields_by_source:{"aws:cloudtrail":["user","action","new_field"],"cribl:normalized:dns":["query","answer"]},
  fields_by_scope:{"aws::aws:cloudtrail":["user","action","new_field"],"dns::cribl:normalized:dns":["query","answer"]},
  discovery_rows:[{index:"aws",sourcetype:"aws:cloudtrail",count:300},{index:"dns",sourcetype:"cribl:normalized:dns",count:600}],
  report:{recommendations:[
    {detection_id:"new-ready",name:"New Ready",readiness:"production_ready"},
    {detection_id:"regressed",name:"Regressed",readiness:"field_gap"}
  ]}
};
process.stdout.write(JSON.stringify(compareSnapshots(baseline,current)));
"""
    completed = subprocess.run(
        ["node", "-e", script, str(ENGINE)],
        check=True,
        capture_output=True,
        text=True,
    )
    changes = json.loads(completed.stdout)
    assert changes["baseline_assessment_id"] == "scan-before"
    assert changes["new_sources"] == ["cribl:normalized:dns"]
    assert changes["removed_sources"] == ["legacy:dns"]
    assert changes["new_routes"] == [{"index": "dns", "source": "cribl:normalized:dns"}]
    assert changes["removed_routes"] == [{"index": "dns", "source": "legacy:dns"}]
    assert changes["field_changes"] == [{
        "index": "aws",
        "source": "aws:cloudtrail",
        "added_fields": ["new_field"],
        "removed_fields": ["legacy_field"],
    }]
    assert changes["volume_changes"][0]["change_percent"] == -70
    assert changes["volume_changes"][0]["index"] == "aws"
    assert [item["detection_id"] for item in changes["newly_buildable"]] == ["new-ready"]
    assert [item["detection_id"] for item in changes["readiness_regressions"]] == ["regressed"]
    assert changes["action_required"] is True


def test_first_scan_establishes_a_baseline_without_false_findings() -> None:
    source = ENGINE.read_text(encoding="utf-8")
    assert "baseline_available:false" in source
    assert "initial_baseline:true" in source
    assert "action_required:false" in source

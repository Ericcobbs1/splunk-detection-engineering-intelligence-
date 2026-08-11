"""Executable regression coverage for generated SPL metadata integrity."""

import subprocess
from pathlib import Path

GENERATOR = Path("app/appserver/static/detection_query_generator_v5.js")


def test_mitre_metadata_is_clean_and_idempotent() -> None:
    script = r"""
const fs=require("fs");
const source=fs.readFileSync(process.argv[1],"utf8");
const start=source.indexOf("function uniqueValues");
const end=source.indexOf("function artifactRecommendation");
if(start<0 || end<0) throw new Error("metadata helpers were not found");
const $={extend:(target,...values)=>Object.assign(target,...values)};
const MITRE_REFERENCE={"T1059.001":{name:"PowerShell",summary:"PowerShell execution description."}};
function quote(value) {
  return '"'+String(value||"").replace(/\\/g,"\\\\").replace(/"/g,'\\"')+'"';
}
eval(source.slice(start,end));
const item={mitre_techniques:["T1059.001"]};
const analytic='search sourcetype="crowdstrike:events:sensor"\n| table _time host user process command_line';
const legacy=analytic+'\\n| eval mitre_attack_ttp=split("PowerShell", "||"), mitre_attack_id=split("T1059.001", "||")'+
  'n|rShell", "||"), mitre_attack_id=split("T1059.001", "||")';
const repaired=attachPlatformMitreMetadata(legacy,item);
const repeated=attachPlatformMitreMetadata(repaired,item);
function count(value,token){return value.split(token).length-1;}
if(repaired!==repeated) throw new Error("metadata attachment is not idempotent");
for(const field of ["mitre_attack_ttp=","mitre_attack_id=","mitre_attack_description="]) {
  if(count(repaired,field)!==1) throw new Error(field+" must appear exactly once");
}
if(repaired.includes("split(") || repaired.includes('|rShell"') || repaired.includes(String.fromCharCode(92)+"n|")) {
  throw new Error("legacy metadata corruption remains in generated SPL");
}
if(!repaired.includes("command_line\n| eval mitre_attack_ttp=")) {
  throw new Error("metadata is not separated by a real newline");
}
"""
    subprocess.run(["node", "-e", script, str(GENERATOR)], check=True)


def test_powershell_regex_keeps_whitespace_escape() -> None:
    javascript = GENERATOR.read_text(encoding="utf-8")
    assert '(-enc\\\\s|encodedcommand' in javascript
    assert '(-enc\\\\\\\\s|encodedcommand' not in javascript

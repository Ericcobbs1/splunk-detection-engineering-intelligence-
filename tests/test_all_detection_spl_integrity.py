"""Execute the SPL generator contract across every catalog detection."""

import json
import subprocess
from pathlib import Path

from library_helpers import load_catalog

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "app" / "appserver" / "static" / "detection_query_generator_v5.js"


def test_every_catalog_detection_generates_clean_idempotent_spl(tmp_path: Path) -> None:
    catalog = load_catalog()
    catalog_path = tmp_path / "aggregated-catalog.json"
    catalog_path.write_text(json.dumps(catalog), encoding="utf-8")
    script = r"""
const fs=require("fs");
const generatorPath=process.argv[1],catalogPath=process.argv[2];
const source=fs.readFileSync(generatorPath,"utf8");
const catalog=JSON.parse(fs.readFileSync(catalogPath,"utf8"));
const familyStart=source.indexOf("var ANALYTIC_FAMILIES=");
const familyEnd=source.indexOf("function schedule",familyStart);
const metadataStart=source.indexOf("function uniqueValues");
const metadataEnd=source.indexOf("function artifactRecommendation",metadataStart);
const syntaxStart=source.indexOf("function pipelineSyntax");
const syntaxEnd=source.indexOf("function validationResolution",syntaxStart);
if([familyStart,familyEnd,metadataStart,metadataEnd,syntaxStart,syntaxEnd].some(value=>value<0)) {
  throw new Error("generator contract helpers were not found");
}
const $={extend:(target,...values)=>Object.assign(target,...values)};
const MITRE_REFERENCE={};
for(const item of catalog) for(const id of (item.mitre_techniques||[])) {
  MITRE_REFERENCE[id]={name:"Technique "+id,summary:"Description for "+id+"."};
}
function quote(value) {
  return '"'+String(value||"").replace(/\\/g,"\\\\").replace(/"/g,'\\"')+'"';
}
eval(source.slice(familyStart,familyEnd));
eval(source.slice(metadataStart,metadataEnd));
eval(source.slice(syntaxStart,syntaxEnd));
const failures=[];
function count(value,token){return value.split(token).length-1;}
for(const catalogItem of catalog) {
  const item=Object.assign({},catalogItem,{detection_id:catalogItem.id});
  const prelude=normalizedPrelude(item);
  const logic=analyticLogic(item);
  const analytic='search sourcetype="dei:test:'+item.id+'" earliest=-15m@m latest=-2m@m'+
    (prelude?'\n'+prelude:'')+'\n'+logic;
  const generated=attachPlatformMitreMetadata(analytic,item);
  const repeated=attachPlatformMitreMetadata(generated,item);
  const syntax=pipelineSyntax(generated);
  const allowed=new Set(["mitre_attack_ttp","mitre_attack_id","mitre_attack_description"]);
  const observed=new Set(generated.match(/\bmitre_attack_[a-z_]+\b/gi)||[]);
  const errors=[];
  if(analyticFamily(item.id)==="unsupported" || logic.includes("dei_generation_blocker")) errors.push("unsupported analytic family");
  if(generated!==repeated) errors.push("metadata attachment is not idempotent");
  for(const field of allowed) if(count(generated,field+"=")!==1) errors.push(field+" count is not one");
  for(const field of observed) if(!allowed.has(field.toLowerCase())) errors.push("unsupported output "+field);
  if(generated.includes(String.fromCharCode(92)+"n|")) errors.push("literal newline escape");
  if(/mitre_attack_(?:ttp|id|description)\s*=\s*split\s*\(/i.test(generated)) errors.push("legacy split metadata");
  if(!syntax.balancedQuotes) errors.push("unbalanced quotes");
  if(syntax.emptyPipes.length) errors.push("empty pipeline stage");
  if(!generated.trim().split(/\r?\n/).slice(-1)[0].startsWith("| eval mitre_attack_ttp=")) errors.push("metadata is not final");
  if(item.id.includes("powershell") && !generated.includes(String.raw`-enc\s`)) errors.push("PowerShell whitespace escape missing");
  if(errors.length) failures.push(item.id+": "+errors.join(", "));
}
if(failures.length) throw new Error(failures.join("\n"));
console.log("validated "+catalog.length+" detection generators");
"""
    completed = subprocess.run(
        ["node", "-e", script, str(GENERATOR), str(catalog_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert f"validated {len(catalog)} detection generators" in completed.stdout

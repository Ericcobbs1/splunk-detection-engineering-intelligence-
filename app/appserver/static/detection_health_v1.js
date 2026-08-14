require(["jquery","splunkjs/mvc/simplexml/ready!"],function($){
  "use strict";
  var records=[];
  function esc(v){return $("<div>").text(v==null?"":String(v)).html();}
  function state(record){
    var validation=record.validation||{}, stage=record.state||record.status||"draft";
    if(validation.status==="failed")return "failed";
    if(!validation.status)return "unvalidated";
    if(validation.status==="passed" && /production|monitoring|tuning/.test(stage) && !record.health_evidence)return "attention";
    if(validation.status==="passed")return "healthy";
    return "attention";
  }
  function reason(record,s){
    if(s==="failed")return (record.validation&&record.validation.error)||"Historical validation failed.";
    if(s==="unvalidated")return "No successful historical validation evidence is stored.";
    if(s==="attention")return "Validation passed, but operational health evidence has not been recorded.";
    return "Validation evidence is current and no blocking health issue is recorded.";
  }
  function render(){
    var q=String($("#health-filter").val()||"").toLowerCase(), filter=$("#health-state").val();
    var counts={healthy:0,attention:0,failed:0,unvalidated:0};
    records.forEach(function(r){counts[state(r)]++;});
    $("#health-managed").text(records.length);Object.keys(counts).forEach(function(k){$("#health-"+k).text(counts[k]);});
    var total=records.length, ready=counts.healthy, percent=total?Math.round((ready/total)*100):0;
    var healthyEnd=total?(counts.healthy/total)*100:0, attentionEnd=healthyEnd+(total?(counts.attention/total)*100:0), failedEnd=attentionEnd+(total?(counts.failed/total)*100:0);
    $("#health-donut").css({"--health-healthy":healthyEnd+"%","--health-attention":attentionEnd+"%","--health-failed":failedEnd+"%"}).attr("aria-label",total?counts.healthy+" healthy, "+counts.attention+" attention, "+counts.failed+" failed, and "+counts.unvalidated+" unvalidated detections":"No managed detection health evidence");
    $("#health-donut-total").text(total);$("#health-ready-percent").text(percent+"%");$("#health-ready-bar").css("width",percent+"%");
    $(".dei-health-bar").attr("aria-valuenow",percent);$("#health-ready-label").text(ready+" of "+total+" ready");
    Object.keys(counts).forEach(function(k){$("#health-legend-"+k).text(counts[k]);});
    var visible=records.filter(function(r){var s=state(r),hay=[r.name,r.id,r.sourcetypes,(r.mitre_attack||[]).join(" "),reason(r,s)].join(" ").toLowerCase();return (filter==="all"||filter===s)&&(!q||hay.indexOf(q)>=0);});
    $("#health-records").html(visible.length?visible.map(function(r){var s=state(r),id=encodeURIComponent(r.detection_id||r.id||"");return '<article class="dei-health-record" data-health="'+s+'"><div><span>'+esc(s.replace("_"," "))+'</span><h2>'+esc(r.name||r.id||"Detection")+'</h2><p>'+esc(reason(r,s))+'</p><small>'+esc((r.mitre_attack||[]).join(" · ")||"MITRE mapping unavailable")+'</small></div><div class="dei-health-record-actions"><a href="detection_workflow?detection='+id+'">Open guided builder</a><a href="detection_catalog?detection='+id+'#lifecycle-map">Lifecycle evidence</a></div></article>';}).join(""):'<div class="dei-health-empty"><h2>No matching detection health records</h2><p>Run environment discovery and generate or validate a detection to create current evidence.</p><a href="command_center#dei-telemetry">Run intelligence scan →</a></div>');
    $("#health-evidence-status").text(records.length?"Loaded "+records.length+" current lifecycle record"+(records.length===1?"":"s")+".":"No lifecycle evidence exists yet. Run discovery, build a detection, and validate it.");
  }
  function load(){var Store=window.DEILifecycleStore;if(!Store||!Store.load){records=[];render();return;}$("#health-refresh").prop("disabled",true).text("Refreshing…");Store.load().done(function(data){records=Array.isArray(data)?data:[];}).fail(function(){records=[];$("#health-evidence-status").removeClass("ready").addClass("error").text("Detection health could not load. Verify DEI permissions and retry.");}).always(function(){$("#health-refresh").prop("disabled",false).text("Refresh health");render();});}
  $("#health-refresh").on("click",load);$("#health-filter").on("input",render);$("#health-state").on("change",render);load();
});

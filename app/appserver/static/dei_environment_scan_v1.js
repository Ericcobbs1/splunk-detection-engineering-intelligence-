require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";
  var appId="splunk_detection_engineering_intelligence", active=false, scanCollection="dei_scan_summaries";
  var discoverySpl='| tstats count WHERE index=* earliest=-7d latest=now BY index sourcetype | where NOT match(index, "^_") AND isnotnull(sourcetype) | sort - count';
  function emit(stage,message,detail) { $(document).trigger("dei:scan-progress",[{stage:stage,message:message,detail:detail||{}}]); }
  function unique(values) { var seen={}; return (values||[]).filter(function (value) { var key=String(value||"").trim().toLowerCase(); if (!key||seen[key]) { return false; } seen[key]=true; return true; }); }
  function rows(text) { var output=[]; String(text||"").split(/\r?\n/).forEach(function (line) { var parsed; if (!line.trim()) { return; } try { parsed=JSON.parse(line); } catch (error) { return; } if (parsed.result) { output.push(parsed.result); } }); return output; }
  function exportSearch(search,timeout) { return $.ajax({url:Splunk.util.make_url("splunkd","__raw","services","search","jobs","export"),method:"POST",dataType:"text",timeout:timeout||30000,headers:{"X-Splunk-Form-Key":Splunk.util.getConfigValue("FORM_KEY")},data:{search:search,output_mode:"json",preview:"0",dei_force_refresh:"1"}}); }
  function recommendations(payload) { var url=Splunk.util.make_url("splunkd","__raw","servicesNS","-",appId,"dei","v1","recommendations"); return $.ajax({url:url,method:"POST",contentType:"application/json",dataType:"json",timeout:30000,headers:{"X-Splunk-Form-Key":Splunk.util.getConfigValue("FORM_KEY")},data:JSON.stringify(payload)}).then(function (response) { return response&&typeof response.payload==="string"?JSON.parse(response.payload):response; }); }
  function errorMessage(xhr,status) { if (status==="timeout") { return "The intelligence scan timed out. Confirm searchable indexes and retry."; } var response=xhr&&xhr.responseJSON||{}; if (typeof response.payload==="string") { try { response=JSON.parse(response.payload); } catch (error) { response={}; } } return response.detail||response.error||"The intelligence scan failed. Confirm DEI permissions and Splunk search availability, then retry."; }
  function profile(sources) {
    var deferred=$.Deferred(),inventory={},failures=[],cursor=0,running=0,completed=0,requests=[],settled=false;
    function finish() { if (settled) { return; } settled=true; window.clearTimeout(timer); deferred.resolve({inventory:inventory,failures:unique(failures)}); }
    function schedule() { if (settled) { return; } if (cursor>=sources.length&&running===0) { finish(); return; } while (running<6&&cursor<sources.length) { (function (source) { var escaped=String(source).replace(/\\/g,"\\\\").replace(/"/g,'\\"'); running+=1; var request=exportSearch('search index=* earliest=-7d latest=now sourcetype="'+escaped+'" | head 200 | fieldsummary | fields field',12000).done(function (text) { var fields=unique(rows(text).map(function (row) { return row.field; })); if (fields.length) { inventory[source]=fields; } else { failures.push(source); } }).fail(function () { failures.push(source); }).always(function () { running-=1; completed+=1; emit("profile","Profiling fields "+completed+"/"+sources.length,{completed:completed,total:sources.length,source:source}); schedule(); }); requests.push(request); })(sources[cursor]); cursor+=1; } }
    var timer=window.setTimeout(function () { requests.forEach(function (request) { if (request&&request.readyState!==4) { request.abort(); } }); sources.slice(cursor).forEach(function (source) { failures.push(source); }); finish(); },90000);
    if (sources.length) { schedule(); } else { finish(); } return deferred.promise();
  }
  function scanEndpoint(key) {
    var parts=["splunkd","__raw","servicesNS","nobody",appId,"storage","collections","data",scanCollection];
    if (key) { parts.push(encodeURIComponent(key)); }
    return Splunk.util.make_url.apply(Splunk.util,parts);
  }
  function username() { try { return Splunk.util.getConfigValue("USERNAME") || "unknown"; } catch (error) { return "unknown"; } }
  function discoveryExport(discoveryRows) { return (discoveryRows||[]).map(function (row) { return JSON.stringify({result:row}); }).join("\n"); }
  function persistSession(snapshot) {
    try {
      window.sessionStorage.setItem("dei.latestRecommendationReport",JSON.stringify(snapshot.report||{}));
      window.sessionStorage.setItem("dei.latestRecommendationTime",String(snapshot.completed_at_ms||Date.now()));
      window.sessionStorage.setItem("dei.latestDiscoveryExport",discoveryExport(snapshot.discovery_rows));
      window.sessionStorage.setItem("dei.latestDiscoveryTime",String(snapshot.completed_at_ms||Date.now()));
      window.sessionStorage.setItem("dei.latestEnterpriseSecurityEnabled",snapshot.enterprise_security_enabled?"true":"false");
      window.sessionStorage.removeItem("dei.dashboardCleared");
    } catch (error) { /* Persistence failure does not invalidate a completed scan. */ }
  }
  function persist(report,discoveryRows,esEnabled,sources,indexes,profileFailures) {
    var completed=Date.now();
    var snapshot={_key:"latest",assessment_id:"scan-"+completed,completed_at_ms:completed,completed_at:new Date(completed).toISOString(),
      initiated_by:username(),active_sourcetype_count:(sources||[]).length,active_index_count:(indexes||[]).length,
      recommendation_count:(report.recommendations||[]).length,field_profile_failures:profileFailures||[],
      enterprise_security_enabled:esEnabled===true,source_types:sources||[],indexes:indexes||[],
      discovery_rows:discoveryRows||[],report:report};
    persistSession(snapshot);
    var updatePayload=$.extend(true,{},snapshot); delete updatePayload._key;
    $.ajax({url:scanEndpoint("latest"),method:"POST",contentType:"application/json",dataType:"json",timeout:15000,
      headers:{"X-Splunk-Form-Key":Splunk.util.getConfigValue("FORM_KEY")},data:JSON.stringify(updatePayload)})
      .fail(function (xhr) {
        if (xhr&&xhr.status===404) {
          $.ajax({url:scanEndpoint(),method:"POST",contentType:"application/json",dataType:"json",timeout:15000,
            headers:{"X-Splunk-Form-Key":Splunk.util.getConfigValue("FORM_KEY")},data:JSON.stringify(snapshot)});
        }
      });
    return snapshot;
  }
  function hydrate() {
    return $.ajax({url:scanEndpoint("latest"),method:"GET",dataType:"json",timeout:15000,
      headers:{"X-Splunk-Form-Key":Splunk.util.getConfigValue("FORM_KEY")}})
      .done(function (snapshot) {
        var local=Number(window.sessionStorage.getItem("dei.latestRecommendationTime")||0);
        if (snapshot&&Number(snapshot.completed_at_ms||0)>local&&snapshot.report) {
          persistSession(snapshot);
          $(document).trigger("dei:environment-refreshed",[snapshot.report]);
          emit("hydrated","Loaded the latest shared environment assessment.",{assessment_id:snapshot.assessment_id||""});
        }
      });
  }
  function run(options) {
    var settings=options||{},deferred=$.Deferred(); if (active) { deferred.reject({message:"An intelligence scan is already running."}); return deferred.promise(); } active=true; emit("discover","Discovering active Splunk telemetry from the last 7 days.");
    exportSearch(discoverySpl,20000).done(function (text) { var discovered=rows(text),sources=unique(discovered.map(function (row) { return row.sourcetype; })),indexes=unique(discovered.map(function (row) { return row.index; })); if (!sources.length) { var empty="Discovery completed but found no searchable source types. Verify DEI role index permissions and retry."; active=false; emit("failed",empty); deferred.reject({message:empty}); return; } emit("profile","Telemetry inventory complete. Profiling fields 0/"+sources.length,{sources:sources.length,indexes:indexes.length}); profile(sources).done(function (result) { emit("recommend","Evaluating telemetry and field-level detection readiness."); recommendations({sources:sources,fields_by_source:result.inventory,enterprise_security_enabled:settings.enterpriseSecurityEnabled===true,include_unsupported:true}).done(function (report) { persist(report,discovered,settings.enterpriseSecurityEnabled===true,sources,indexes,result.failures); active=false; var message="Analysis complete. Discovered "+sources.length+" source types across "+indexes.length+" indexes and generated "+(report.recommendations||[]).length+" recommendations."; emit("complete",message,{report:report}); $(document).trigger("dei:environment-refreshed",[report]); deferred.resolve(report); }).fail(function (xhr,status) { var message=errorMessage(xhr,status); active=false; emit("failed",message); deferred.reject({message:message}); }); }); }).fail(function (xhr,status) { var message=errorMessage(xhr,status); active=false; emit("failed",message); deferred.reject({message:message}); }); return deferred.promise();
  }
  window.DEIEnvironmentScan={run:run,hydrate:hydrate,isRunning:function () { return active; }};
  $(document).trigger("dei:scan-service-ready");
  hydrate();
});

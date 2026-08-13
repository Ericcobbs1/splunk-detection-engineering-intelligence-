require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";
  var appId="splunk_detection_engineering_intelligence", active=false, scanCollection="dei_scan_summaries",historyCollection="dei_scan_history";
  var discoverySpl='| tstats count WHERE index=* earliest=-7d latest=now BY index sourcetype | where NOT match(index, "^_") AND isnotnull(sourcetype) | sort - count';
  function emit(stage,message,detail) { $(document).trigger("dei:scan-progress",[{stage:stage,message:message,detail:detail||{}}]); }
  function unique(values) { var seen={}; return (values||[]).filter(function (value) { var key=String(value||"").trim().toLowerCase(); if (!key||seen[key]) { return false; } seen[key]=true; return true; }); }
  function list(value) { return Array.isArray(value)?value:(value===undefined||value===null||value===""?[]:[value]); }
  function rows(text) { var output=[]; String(text||"").split(/\r?\n/).forEach(function (line) { var parsed; if (!line.trim()) { return; } try { parsed=JSON.parse(line); } catch (error) { return; } if (parsed.result) { output.push(parsed.result); } }); return output; }
  function exportSearch(search,timeout) { return $.ajax({url:Splunk.util.make_url("splunkd","__raw","services","search","jobs","export"),method:"POST",dataType:"text",timeout:timeout||30000,headers:{"X-Splunk-Form-Key":Splunk.util.getConfigValue("FORM_KEY")},data:{search:search,output_mode:"json",preview:"0",dei_force_refresh:"1"}}); }
  function recommendations(payload) { var url=Splunk.util.make_url("splunkd","__raw","servicesNS","-",appId,"dei","v1","recommendations"); return $.ajax({url:url,method:"POST",contentType:"application/json",dataType:"json",timeout:30000,headers:{"X-Splunk-Form-Key":Splunk.util.getConfigValue("FORM_KEY")},data:JSON.stringify(payload)}).then(function (response) { return response&&typeof response.payload==="string"?JSON.parse(response.payload):response; }); }
  function errorMessage(xhr,status) { if (status==="timeout") { return "The intelligence scan timed out. Confirm searchable indexes and retry."; } var response=xhr&&xhr.responseJSON||{}; if (typeof response.payload==="string") { try { response=JSON.parse(response.payload); } catch (error) { response={}; } } return response.detail||response.error||"The intelligence scan failed. Confirm DEI permissions and Splunk search availability, then retry."; }
  function profile(discoveryRows) {
    var seen={},scopes=[];
    (discoveryRows||[]).forEach(function(row){ var index=String(row.index||"").trim(),source=String(row.sourcetype||"").trim(),key=index.toLowerCase()+"::"+source.toLowerCase(); if(index&&source&&!seen[key]){seen[key]=true;scopes.push({index:index,source:source,key:index+"::"+source});} });
    var deferred=$.Deferred(),inventory={},scopedInventory={},telemetryRoutes=[],failures=[],cursor=0,running=0,completed=0,requests=[],settled=false;
    function result() { return {inventory:inventory,scoped_inventory:scopedInventory,telemetry_routes:telemetryRoutes,failures:unique(failures)}; }
    function finish() { if (settled) { return; } settled=true; window.clearTimeout(timer); deferred.resolve(result()); }
    function schedule() { if (settled) { return; } if (cursor>=scopes.length&&running===0) { finish(); return; } while (running<6&&cursor<scopes.length) { (function (scope) { var escapedIndex=scope.index.replace(/\\/g,"\\\\").replace(/"/g,'\\"'),escapedSource=scope.source.replace(/\\/g,"\\\\").replace(/"/g,'\\"'); running+=1; var search='search index="'+escapedIndex+'" earliest=-7d latest=now sourcetype="'+escapedSource+'" | head 200 | eval __dei_channel=coalesce(Channel, channel) | stats values(*) as *'; var request=exportSearch(search,12000).done(function (text) { var sampled=rows(text)[0]||{},fields=unique(Object.keys(sampled).filter(function(field){return field!=="__dei_channel";})),channels=unique(list(sampled.__dei_channel)); if (fields.length) { scopedInventory[scope.key]=fields; inventory[scope.source]=unique((inventory[scope.source]||[]).concat(fields)); telemetryRoutes.push({index:scope.index,sourcetype:scope.source,channels:channels,fields:fields}); } else { failures.push(scope.key); } }).fail(function () { failures.push(scope.key); }).always(function () { running-=1; completed+=1; emit("profile","Profiling telemetry route "+completed+"/"+scopes.length,{completed:completed,total:scopes.length,index:scope.index,source:scope.source}); schedule(); }); requests.push(request); })(scopes[cursor]); cursor+=1; } }
    var timer=window.setTimeout(function () { if(settled) return; settled=true; requests.forEach(function (request) { if (request&&request.readyState!==4) { request.abort(); } }); scopes.slice(cursor).forEach(function (scope) { failures.push(scope.key); }); deferred.resolve(result()); },90000);
    if (scopes.length) { schedule(); } else { finish(); } return deferred.promise();
  }
  function scanEndpoint(key) {
    var parts=["splunkd","__raw","servicesNS","nobody",appId,"storage","collections","data",scanCollection];
    if (key) { parts.push(encodeURIComponent(key)); }
    return Splunk.util.make_url.apply(Splunk.util,parts);
  }
  function username() { try { return Splunk.util.getConfigValue("USERNAME") || "unknown"; } catch (error) { return "unknown"; } }
  function discoveryExport(discoveryRows) { return (discoveryRows||[]).map(function (row) { return JSON.stringify({result:row}); }).join("\n"); }
  function lowerMap(values) { var mapped={}; (values||[]).forEach(function(value){ var text=String(value||"").trim(); if(text) mapped[text.toLowerCase()]=text; }); return mapped; }
  function routeMap(rows) { var mapped={}; (rows||[]).forEach(function(row){ var index=String(row.index||"").trim(),source=String(row.sourcetype||"").trim(),key=index.toLowerCase()+"::"+source.toLowerCase(); if(index&&source) mapped[key]={index:index,source:source}; }); return mapped; }
  function routeVolumes(rows) { var totals={}; (rows||[]).forEach(function(row){ var index=String(row.index||"").trim().toLowerCase(),source=String(row.sourcetype||"").trim().toLowerCase(),key=index+"::"+source; if(index&&source) totals[key]=(totals[key]||0)+(Number(row.count||0)||0); }); return totals; }
  function recommendationMap(report) { var mapped={}; (report&&report.recommendations||[]).forEach(function(item){ var id=String(item.detection_id||"").trim(); if(id) mapped[id]=item; }); return mapped; }
  function compareSnapshots(baseline,current) {
    if(!baseline||!baseline.assessment_id) return {baseline_available:false,baseline_assessment_id:"",initial_baseline:true,new_sources:[],removed_sources:[],new_routes:[],removed_routes:[],field_changes:[],volume_changes:[],detection_changes:[],newly_buildable:[],readiness_regressions:[],action_required:false,change_count:0};
    var beforeSources=lowerMap(baseline.source_types),afterSources=lowerMap(current.source_types);
    var newSources=Object.keys(afterSources).filter(function(key){return !beforeSources[key];}).map(function(key){return afterSources[key];}).sort();
    var removedSources=Object.keys(beforeSources).filter(function(key){return !afterSources[key];}).map(function(key){return beforeSources[key];}).sort();
    var beforeRoutes=routeMap(baseline.discovery_rows),afterRoutes=routeMap(current.discovery_rows);
    var newRoutes=Object.keys(afterRoutes).filter(function(key){return !beforeRoutes[key];}).map(function(key){return afterRoutes[key];});
    var removedRoutes=Object.keys(beforeRoutes).filter(function(key){return !afterRoutes[key];}).map(function(key){return beforeRoutes[key];});
    var beforeFields=baseline.fields_by_scope||baseline.fields_by_source||{},afterFields=current.fields_by_scope||current.fields_by_source||{},beforeFieldKeys=lowerMap(Object.keys(beforeFields)),afterFieldKeys=lowerMap(Object.keys(afterFields));
    var fieldChanges=[];
    Object.keys(afterFieldKeys).filter(function(key){return beforeFieldKeys[key];}).forEach(function(key){
      var beforeName=beforeFieldKeys[key],afterName=afterFieldKeys[key],oldFields=lowerMap(beforeFields[beforeName]),newFields=lowerMap(afterFields[afterName]);
      var added=Object.keys(newFields).filter(function(field){return !oldFields[field];}).map(function(field){return newFields[field];}).sort();
      var removed=Object.keys(oldFields).filter(function(field){return !newFields[field];}).map(function(field){return oldFields[field];}).sort();
      if(added.length||removed.length) { var scopeParts=afterName.split("::"); fieldChanges.push({index:scopeParts.length>1?scopeParts.shift():"",source:scopeParts.length?scopeParts.join("::"):afterName,added_fields:added,removed_fields:removed}); }
    });
    var beforeVolumes=routeVolumes(baseline.discovery_rows),afterVolumes=routeVolumes(current.discovery_rows),volumeChanges=[];
    Object.keys(afterVolumes).forEach(function(key){ var previous=beforeVolumes[key]||0,currentCount=afterVolumes[key],route=afterRoutes[key]||beforeRoutes[key]||{}; if(previous<100) return; var change=Math.round(((currentCount-previous)/previous)*100); if(Math.abs(change)>=50) volumeChanges.push({index:route.index||"",source:route.source||key,previous_count:previous,current_count:currentCount,change_percent:change}); });
    var beforeRecommendations=recommendationMap(baseline.report),afterRecommendations=recommendationMap(current.report),detectionChanges=[],newlyBuildable=[],regressions=[];
    Object.keys(afterRecommendations).forEach(function(id){ var previous=beforeRecommendations[id],next=afterRecommendations[id]; if(!previous||previous.readiness===next.readiness) return; var change={detection_id:id,name:next.name,previous_readiness:previous.readiness,current_readiness:next.readiness}; detectionChanges.push(change); if(previous.readiness!=="production_ready"&&next.readiness==="production_ready") newlyBuildable.push(change); if(previous.readiness==="production_ready"&&next.readiness!=="production_ready") regressions.push(change); });
    var count=newRoutes.length+removedRoutes.length+fieldChanges.length+volumeChanges.length+detectionChanges.length;
    return {baseline_available:true,baseline_assessment_id:baseline.assessment_id,initial_baseline:false,new_sources:newSources,removed_sources:removedSources,new_routes:newRoutes,removed_routes:removedRoutes,field_changes:fieldChanges,volume_changes:volumeChanges,detection_changes:detectionChanges,newly_buildable:newlyBuildable,readiness_regressions:regressions,action_required:removedRoutes.length>0||fieldChanges.some(function(change){return change.removed_fields.length>0;})||regressions.length>0,change_count:count};
  }
  function collectionEndpoint(collection,key) {
    var parts=["splunkd","__raw","servicesNS","nobody",appId,"storage","collections","data",collection];
    if(key) parts.push(encodeURIComponent(key));
    return Splunk.util.make_url.apply(Splunk.util,parts);
  }
  function loadLatest() { return $.ajax({url:collectionEndpoint(scanCollection,"latest"),method:"GET",dataType:"json",timeout:15000,headers:{"X-Splunk-Form-Key":Splunk.util.getConfigValue("FORM_KEY")}}).then(function(snapshot){return snapshot;},function(){return null;}); }
  function writeRecord(collection,record) {
    var payload=$.extend(true,{},record),key=payload._key; delete payload._key;
    var createPayload=$.extend(true,{},payload,{_key:key});
    return $.ajax({url:collectionEndpoint(collection),method:"POST",contentType:"application/json",dataType:"json",timeout:15000,headers:{"X-Splunk-Form-Key":Splunk.util.getConfigValue("FORM_KEY")},data:JSON.stringify(createPayload)}).then(null,function(xhr){
      if(!xhr||xhr.status!==409) return $.Deferred().reject(xhr).promise();
      return $.ajax({url:collectionEndpoint(collection,key),method:"POST",contentType:"application/json",dataType:"json",timeout:15000,headers:{"X-Splunk-Form-Key":Splunk.util.getConfigValue("FORM_KEY")},data:JSON.stringify(payload)});
    });
  }
  function persistSession(snapshot) {
    try {
      window.sessionStorage.setItem("dei.latestRecommendationReport",JSON.stringify(snapshot.report||{}));
      window.sessionStorage.setItem("dei.latestRecommendationTime",String(snapshot.completed_at_ms||Date.now()));
      window.sessionStorage.setItem("dei.latestDiscoveryExport",discoveryExport(snapshot.discovery_rows));
      window.sessionStorage.setItem("dei.latestDiscoveryTime",String(snapshot.completed_at_ms||Date.now()));
      window.sessionStorage.setItem("dei.latestEnterpriseSecurityEnabled",snapshot.enterprise_security_enabled?"true":"false");
      window.sessionStorage.setItem("dei.latestScanChanges",JSON.stringify(snapshot.change_analysis||{}));
      window.sessionStorage.removeItem("dei.dashboardCleared");
    } catch (error) { /* Persistence failure does not invalidate a completed scan. */ }
  }
  function persist(report,discoveryRows,esEnabled,sources,indexes,profileFailures,fieldsBySource,fieldsByScope,telemetryRoutes,baseline) {
    var completed=Date.now();
    var snapshot={_key:"latest",assessment_id:"scan-"+completed,completed_at_ms:completed,completed_at:new Date(completed).toISOString(),
      initiated_by:username(),active_sourcetype_count:(sources||[]).length,active_index_count:(indexes||[]).length,
      recommendation_count:(report.recommendations||[]).length,field_profile_failures:profileFailures||[],
      enterprise_security_enabled:esEnabled===true,source_types:sources||[],indexes:indexes||[],
      discovery_rows:discoveryRows||[],fields_by_source:fieldsBySource||{},fields_by_scope:fieldsByScope||{},telemetry_routes:telemetryRoutes||[],report:report};
    snapshot.change_analysis=compareSnapshots(baseline,snapshot);
    persistSession(snapshot);
    var history=$.extend(true,{},snapshot,{_key:snapshot.assessment_id});
    return $.when(writeRecord(scanCollection,snapshot),writeRecord(historyCollection,history)).then(
      function(){ snapshot.persistence={durable:true,mode:"Splunk KV Store"}; return snapshot; },
      function(xhr){ snapshot.persistence={durable:false,mode:"browser session",status:xhr&&xhr.status||0}; emit("warning","Analysis completed in this browser, but the shared assessment and immutable history could not both be saved. Resolve KV Store access before treating this scan as durable.",{assessment_id:snapshot.assessment_id,status:snapshot.persistence.status}); return snapshot; }
    );
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
    exportSearch(discoverySpl,20000).done(function (text) {
      var discovered=rows(text),sources=unique(discovered.map(function (row) { return row.sourcetype; })),indexes=unique(discovered.map(function (row) { return row.index; }));
      if (!sources.length) { var empty="Discovery completed but found no searchable source types. Verify DEI role index permissions and retry."; active=false; emit("failed",empty); deferred.reject({message:empty}); return; }
      emit("profile","Telemetry inventory complete. Profiling index, sourcetype, and channel routes.",{sources:sources.length,indexes:indexes.length});
      profile(discovered).done(function (result) {
        emit("recommend","Evaluating route-scoped telemetry and field-level detection readiness.");
        recommendations({sources:sources,fields_by_source:result.inventory,telemetry_routes:result.telemetry_routes,enterprise_security_enabled:settings.enterpriseSecurityEnabled===true,include_unsupported:true}).done(function (report) {
          loadLatest().done(function(baseline){
            persist(report,discovered,settings.enterpriseSecurityEnabled===true,sources,indexes,result.failures,result.inventory,result.scoped_inventory,result.telemetry_routes,baseline).done(function(snapshot){
              active=false;
              var changes=snapshot.change_analysis;
              var message="Analysis complete. Discovered "+sources.length+" source types across "+indexes.length+" indexes and generated "+(report.recommendations||[]).length+" recommendations. "+(changes.baseline_available?changes.change_count+" telemetry or readiness change(s) detected.":"This scan established the initial telemetry baseline.");
              if(!snapshot.persistence.durable) message+=" Shared KV persistence needs attention; this result is available only in the current browser session.";
              emit(snapshot.persistence.durable?"complete":"complete_with_warning",message,{report:report,change_analysis:changes,assessment_id:snapshot.assessment_id,persistence:snapshot.persistence});
              $(document).trigger("dei:environment-refreshed",[report,changes]); deferred.resolve(report);
            });
          });
        }).fail(function (xhr,status) { var message=errorMessage(xhr,status); active=false; emit("failed",message); deferred.reject({message:message}); });
      }).fail(function (xhr,status) { var message=errorMessage(xhr,status); active=false; emit("failed",message); deferred.reject({message:message}); });
    }).fail(function (xhr,status) { var message=errorMessage(xhr,status); active=false; emit("failed",message); deferred.reject({message:message}); });
    return deferred.promise();
  }
  window.DEIEnvironmentScan={run:run,hydrate:hydrate,isRunning:function () { return active; },compareSnapshots:compareSnapshots};
  $(document).trigger("dei:scan-service-ready");
  hydrate();
});

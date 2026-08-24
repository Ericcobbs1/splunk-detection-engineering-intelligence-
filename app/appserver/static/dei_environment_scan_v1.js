require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";
  var appId="splunk_detection_engineering_intelligence", active=false, scanCollection="dei_scan_summaries",historyCollection="dei_scan_history";
  var activeWindowDays=7,defaultWindowDays=30,allowedWindows=[7,30,90],windowStorageKey="dei.telemetryDiscoveryWindowDays";
  function windowDays(value) { var parsed=Number(value); return allowedWindows.indexOf(parsed)!==-1?parsed:defaultWindowDays; }
  function discoveryWindow() { try { return windowDays(window.localStorage.getItem(windowStorageKey)); } catch (error) { return defaultWindowDays; } }
  function saveDiscoveryWindow(value) { var days=windowDays(value); try { window.localStorage.setItem(windowStorageKey,String(days)); } catch (error) { /* Browser persistence is optional. */ } return days; }
  function discoverySpl(days,includeInternalIndexes) { var indexes=includeInternalIndexes?'(index=* OR index=_*)':'index=*',filter=includeInternalIndexes?'| where isnotnull(sourcetype)':'| where NOT match(index, "^_") AND index!="ers" AND isnotnull(sourcetype)'; return '| tstats count latest(_time) AS last_seen WHERE '+indexes+' earliest=-'+windowDays(days)+'d latest=now BY index sourcetype '+filter+' | sort - count'; }
  function freshness(row,nowSeconds) { var age=Math.max(0,(nowSeconds-Number(row.last_seen||0))/86400); return age<=activeWindowDays?"active":"stale"; }
  function inventory(rows,days) { var now=Math.floor(Date.now()/1000),known=rows||[],activeRows=known.filter(function(row){return freshness(row,now)==="active";}),knownSources=unique(known.map(function(row){return row.sourcetype;})),activeSources=unique(activeRows.map(function(row){return row.sourcetype;})),activeMap=lowerMap(activeSources); return {window_days:windowDays(days),active_window_days:activeWindowDays,known_rows:known,active_rows:activeRows,known_sources:knownSources,active_sources:activeSources,known_indexes:unique(known.map(function(row){return row.index;})),active_indexes:unique(activeRows.map(function(row){return row.index;})),stale_sources:knownSources.filter(function(source){return !activeMap[String(source).toLowerCase()];})}; }
  function emit(stage,message,detail) { $(document).trigger("dei:scan-progress",[{stage:stage,message:message,detail:detail||{}}]); }
  function unique(values) { var seen={}; return (values||[]).filter(function (value) { var key=String(value||"").trim().toLowerCase(); if (!key||seen[key]) { return false; } seen[key]=true; return true; }); }
  function list(value) { return Array.isArray(value)?value:(value===undefined||value===null||value===""?[]:[value]); }
  function rows(text) { var output=[]; String(text||"").split(/\r?\n/).forEach(function (line) { var parsed; if (!line.trim()) { return; } try { parsed=JSON.parse(line); } catch (error) { return; } if (parsed.result) { output.push(parsed.result); } }); return output; }
  function exportSearch(search,timeout) { return $.ajax({url:Splunk.util.make_url("splunkd","__raw","services","search","jobs","export"),method:"POST",dataType:"text",timeout:timeout||30000,headers:{"X-Splunk-Form-Key":Splunk.util.getConfigValue("FORM_KEY")},data:{search:search,output_mode:"json",preview:"0",dei_force_refresh:"1"}}); }
  function recommendations(payload) { var url=Splunk.util.make_url("splunkd","__raw","servicesNS","-",appId,"dei","v1","recommendations"); return $.ajax({url:url,method:"POST",contentType:"application/json",dataType:"json",timeout:30000,headers:{"X-Splunk-Form-Key":Splunk.util.getConfigValue("FORM_KEY")},data:JSON.stringify(payload)}).then(function (response) { return response&&typeof response.payload==="string"?JSON.parse(response.payload):response; }); }
  function errorMessage(xhr,status) { if (status==="timeout") { return "The intelligence scan timed out. Confirm searchable indexes and retry."; } var response=xhr&&xhr.responseJSON||{}; if (typeof response.payload==="string") { try { response=JSON.parse(response.payload); } catch (error) { response={}; } } return response.detail||response.error||"The intelligence scan failed. Confirm DEI permissions and Splunk search availability, then retry."; }
  function profile(discoveryRows,days) {
    var seen={},scopes=[];
    (discoveryRows||[]).forEach(function(row){ var index=String(row.index||"").trim(),source=String(row.sourcetype||"").trim(),key=index.toLowerCase()+"::"+source.toLowerCase(); if(index&&source&&!seen[key]){seen[key]=true;scopes.push({index:index,source:source,key:index+"::"+source});} });
    var deferred=$.Deferred(),inventory={},scopedInventory={},telemetryRoutes=[],failures=[],cursor=0,running=0,completed=0,requests=[],settled=false;
    function result() { return {inventory:inventory,scoped_inventory:scopedInventory,telemetry_routes:telemetryRoutes,failures:unique(failures)}; }
    function finish() { if (settled) { return; } settled=true; window.clearTimeout(timer); deferred.resolve(result()); }
    function schedule() { if (settled) { return; } if (cursor>=scopes.length&&running===0) { finish(); return; } while (running<6&&cursor<scopes.length) { (function (scope) { var escapedIndex=scope.index.replace(/\\/g,"\\\\").replace(/"/g,'\\"'),escapedSource=scope.source.replace(/\\/g,"\\\\").replace(/"/g,'\\"'); running+=1; var search='search index="'+escapedIndex+'" earliest=-'+windowDays(days)+'d latest=now sourcetype="'+escapedSource+'" | head 200 | eval __dei_channel=coalesce(Channel, channel) | stats values(*) as *'; var request=exportSearch(search,12000).done(function (text) { var sampled=rows(text)[0]||{},fields=unique(Object.keys(sampled).filter(function(field){return field!=="__dei_channel";})),channels=unique(list(sampled.__dei_channel)); if (fields.length) { scopedInventory[scope.key]=fields; inventory[scope.source]=unique((inventory[scope.source]||[]).concat(fields)); telemetryRoutes.push({index:scope.index,sourcetype:scope.source,channels:channels,fields:fields}); } else { failures.push(scope.key); } }).fail(function () { failures.push(scope.key); }).always(function () { running-=1; completed+=1; emit("profile","Profiling telemetry route "+completed+"/"+scopes.length,{completed:completed,total:scopes.length,index:scope.index,source:scope.source}); schedule(); }); requests.push(request); })(scopes[cursor]); cursor+=1; } }
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
    if(!baseline||!baseline.assessment_id) return {baseline_available:false,baseline_assessment_id:"",initial_baseline:true,new_sources:[],removed_sources:[],new_routes:[],removed_routes:[],freshness_changes:[],field_changes:[],volume_changes:[],detection_changes:[],newly_buildable:[],readiness_regressions:[],action_required:false,change_count:0};
    var beforeSources=lowerMap(baseline.known_source_types||baseline.source_types),afterSources=lowerMap(current.known_source_types||current.source_types);
    var newSources=Object.keys(afterSources).filter(function(key){return !beforeSources[key];}).map(function(key){return afterSources[key];}).sort();
    var removedSources=Object.keys(beforeSources).filter(function(key){return !afterSources[key];}).map(function(key){return beforeSources[key];}).sort();
    var beforeActive=lowerMap(baseline.active_source_types||baseline.source_types),afterActive=lowerMap(current.active_source_types||current.source_types),freshnessChanges=[];
    Object.keys(beforeActive).filter(function(key){return !afterActive[key]&&afterSources[key];}).forEach(function(key){freshnessChanges.push({source:afterSources[key],previous_freshness:"active",current_freshness:"stale",detail:"No events were observed in the last "+current.active_window_days+" days; the source remains in the known inventory."});});
    Object.keys(afterActive).filter(function(key){return !beforeActive[key]&&beforeSources[key];}).forEach(function(key){freshnessChanges.push({source:afterActive[key],previous_freshness:"stale",current_freshness:"active",detail:"Recent events restored active readiness evidence."});});
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
    Object.keys(afterRecommendations).forEach(function(id){ var previous=beforeRecommendations[id],next=afterRecommendations[id]; if(!previous||previous.readiness===next.readiness) return; var change={detection_id:id,name:next.name,previous_readiness:previous.readiness,current_readiness:next.readiness,cause:freshnessChanges.length?"telemetry_age_or_freshness":"telemetry_or_field_evidence"}; detectionChanges.push(change); if(previous.readiness!=="production_ready"&&next.readiness==="production_ready") newlyBuildable.push(change); if(previous.readiness==="production_ready"&&next.readiness!=="production_ready") regressions.push(change); });
    var count=newRoutes.length+removedRoutes.length+freshnessChanges.length+fieldChanges.length+volumeChanges.length+detectionChanges.length;
    return {baseline_available:true,baseline_assessment_id:baseline.assessment_id,initial_baseline:false,new_sources:newSources,removed_sources:removedSources,new_routes:newRoutes,removed_routes:removedRoutes,freshness_changes:freshnessChanges,field_changes:fieldChanges,volume_changes:volumeChanges,detection_changes:detectionChanges,newly_buildable:newlyBuildable,readiness_regressions:regressions,action_required:removedRoutes.length>0||fieldChanges.some(function(change){return change.removed_fields.length>0;})||regressions.length>0,change_count:count};
  }
  function collectionEndpoint(collection,key) {
    var parts=["splunkd","__raw","servicesNS","nobody",appId,"storage","collections","data",collection];
    if(key) parts.push(encodeURIComponent(key));
    return Splunk.util.make_url.apply(Splunk.util,parts);
  }
  function storage(payload) {
    var url=Splunk.util.make_url("splunkd","__raw","servicesNS","-",appId,"dei","v1","storage");
    return $.ajax({url:url,method:"POST",contentType:"application/json",dataType:"json",timeout:30000,headers:{"X-Splunk-Form-Key":Splunk.util.getConfigValue("FORM_KEY")},data:JSON.stringify(payload)}).then(function(response){ return response&&typeof response.payload==="string"?JSON.parse(response.payload):response; });
  }
  function loadLatest() { return storage({resource:"scan",operation:"read"}).then(function(snapshot){return snapshot;},function(){return null;}); }
  function persistSession(snapshot) {
    try {
      window.sessionStorage.setItem("dei.latestRecommendationReport",JSON.stringify(snapshot.report||{}));
      window.sessionStorage.setItem("dei.latestRecommendationTime",String(snapshot.completed_at_ms||Date.now()));
      window.sessionStorage.setItem("dei.latestDiscoveryExport",discoveryExport(snapshot.discovery_rows));
      window.sessionStorage.setItem("dei.latestDiscoveryTime",String(snapshot.completed_at_ms||Date.now()));
      window.sessionStorage.setItem("dei.latestEnterpriseSecurityEnabled",snapshot.enterprise_security_enabled?"true":"false");
      window.sessionStorage.setItem("dei.includeInternalIndexes",snapshot.include_internal_indexes?"true":"false");
      window.sessionStorage.setItem("dei.latestScanChanges",JSON.stringify(snapshot.change_analysis||{}));
      window.sessionStorage.removeItem("dei.dashboardCleared");
    } catch (error) { /* Persistence failure does not invalidate a completed scan. */ }
  }
  function persist(report,knownReport,environment,esEnabled,includeInternalIndexes,profileFailures,fieldsBySource,fieldsByScope,telemetryRoutes,baseline) {
    var completed=Date.now();
    var snapshot={_key:"latest",assessment_id:"scan-"+completed,completed_at_ms:completed,completed_at:new Date(completed).toISOString(),
      initiated_by:username(),discovery_window_days:environment.window_days,active_window_days:environment.active_window_days,
      active_sourcetype_count:environment.active_sources.length,active_index_count:environment.active_indexes.length,
      known_sourcetype_count:environment.known_sources.length,known_index_count:environment.known_indexes.length,
      recommendation_count:(report.recommendations||[]).length,field_profile_failures:profileFailures||[],
      enterprise_security_enabled:esEnabled===true,include_internal_indexes:includeInternalIndexes===true,source_types:environment.active_sources,active_source_types:environment.active_sources,
      known_source_types:environment.known_sources,stale_source_types:environment.stale_sources,indexes:environment.active_indexes,known_indexes:environment.known_indexes,
      discovery_rows:environment.known_rows,active_discovery_rows:environment.active_rows,fields_by_source:fieldsBySource||{},fields_by_scope:fieldsByScope||{},telemetry_routes:telemetryRoutes||[],report:report,known_report:knownReport};
    snapshot.change_analysis=compareSnapshots(baseline,snapshot);
    persistSession(snapshot);
    var history=$.extend(true,{},snapshot,{_key:snapshot.assessment_id});
    return storage({resource:"scan",operation:"upsert",summary:snapshot,history:history}).then(
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
          $(document).trigger("dei:environment-refreshed",[snapshot.report,snapshot.change_analysis||{},snapshot]);
          emit("hydrated","Loaded the latest shared environment assessment.",{assessment_id:snapshot.assessment_id||""});
        }
      });
  }
  function run(options) {
    var settings=options||{},days=saveDiscoveryWindow(settings.windowDays||discoveryWindow()),includeInternalIndexes=settings.includeInternalIndexes===true,deferred=$.Deferred(); if (active) { deferred.reject({message:"An intelligence scan is already running."}); return deferred.promise(); } active=true; emit("discover","Discovering known Splunk telemetry from the last "+days+" days; the last "+activeWindowDays+" days determine active readiness.",{window_days:days,active_window_days:activeWindowDays,include_internal_indexes:includeInternalIndexes});
    exportSearch(discoverySpl(days,includeInternalIndexes),20000).done(function (text) {
      var discovered=rows(text),environment=inventory(discovered,days);
      if (!environment.known_sources.length) { var empty="Discovery completed but found no searchable source types in the selected "+days+"-day window. Verify DEI role index permissions or select a longer window, then retry."; active=false; emit("failed",empty); deferred.reject({message:empty}); return; }
      emit("profile","Known telemetry inventory complete. Profiling index, sourcetype, and channel routes.",{sources:environment.known_sources.length,indexes:environment.known_indexes.length,active_sources:environment.active_sources.length,stale_sources:environment.stale_sources.length});
      profile(environment.active_rows,activeWindowDays).done(function (result) {
        emit("recommend","Evaluating route-scoped telemetry and field-level detection readiness.");
        var activeRouteKeys=routeMap(environment.active_rows),activeRoutes=result.telemetry_routes.filter(function(route){return !!activeRouteKeys[String(route.index||"").toLowerCase()+"::"+String(route.sourcetype||"").toLowerCase()];});
        recommendations({sources:environment.active_sources,fields_by_source:result.inventory,telemetry_routes:activeRoutes,enterprise_security_enabled:settings.enterpriseSecurityEnabled===true,include_unsupported:true}).done(function (report) {
          recommendations({sources:environment.known_sources,fields_by_source:result.inventory,telemetry_routes:result.telemetry_routes,enterprise_security_enabled:settings.enterpriseSecurityEnabled===true,include_unsupported:true}).done(function(knownReport){
            report.known_source_mappings=knownReport.source_mappings||[];
            report.known_unmapped_sources=knownReport.unmapped_sources||[];
            report.stale_source_types=environment.stale_sources;
            loadLatest().done(function(baseline){
              persist(report,knownReport,environment,settings.enterpriseSecurityEnabled===true,includeInternalIndexes,result.failures,result.inventory,result.scoped_inventory,result.telemetry_routes,baseline).done(function(snapshot){
                active=false;
                var changes=snapshot.change_analysis;
                var message="Analysis complete. Found "+environment.known_sources.length+" known source types across "+environment.known_indexes.length+" indexes; "+environment.active_sources.length+" are active and "+environment.stale_sources.length+" are stale. Generated "+(report.recommendations||[]).length+" recommendations from active evidence. "+(changes.baseline_available?changes.change_count+" telemetry, freshness, or readiness change(s) detected.":"This scan established the initial telemetry baseline.");
                if(changes.readiness_regressions&&changes.readiness_regressions.some(function(change){return change.cause==="telemetry_age_or_freshness";})) message+=" One or more readiness downgrades may be caused by telemetry age; review freshness before changing the detection design.";
                if(!snapshot.persistence.durable) message+=" Shared KV persistence needs attention; this result is available only in the current browser session.";
                emit(snapshot.persistence.durable?"complete":"complete_with_warning",message,{report:report,change_analysis:changes,assessment_id:snapshot.assessment_id,persistence:snapshot.persistence,snapshot:snapshot});
                $(document).trigger("dei:environment-refreshed",[report,changes,snapshot]); deferred.resolve(report);
              });
            });
          }).fail(function (xhr,status) { var message=errorMessage(xhr,status); active=false; emit("failed",message); deferred.reject({message:message}); });
        }).fail(function (xhr,status) { var message=errorMessage(xhr,status); active=false; emit("failed",message); deferred.reject({message:message}); });
      }).fail(function (xhr,status) { var message=errorMessage(xhr,status); active=false; emit("failed",message); deferred.reject({message:message}); });
    }).fail(function (xhr,status) { var message=errorMessage(xhr,status); active=false; emit("failed",message); deferred.reject({message:message}); });
    return deferred.promise();
  }
  window.DEIEnvironmentScan={run:run,hydrate:hydrate,isRunning:function () { return active; },compareSnapshots:compareSnapshots,windowDays:discoveryWindow,saveWindow:saveDiscoveryWindow,inventory:inventory,discoverySearch:discoverySpl};
  $(document).trigger("dei:scan-service-ready");
  hydrate();
});

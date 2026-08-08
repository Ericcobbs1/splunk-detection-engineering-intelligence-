require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var REPORT_KEY = "dei.latestRecommendationReport";
  var REPORT_TIME_KEY = "dei.latestRecommendationTime";
  var SELECTED_DETECTION_KEY = "dei.selectedDetectionDraft";
  var report = null;
  var records = [];
  var selectedRecord = null;
  var Store = null;
  var STATE_ORDER = ["draft","testing","peer_review","production","monitoring","tuning","retired"];

  function safeJson(value) { try { return JSON.parse(value || "null"); } catch (error) { return null; } }
  function esc(value) { return String(value == null ? "" : value).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"); }
  function label(value) { return String(value || "unknown").replace(/_/g," ").replace(/w/g,function (c) { return c.toUpperCase(); }); }
  function recommendations() { return report && report.recommendations ? report.recommendations : []; }
  function sourceMappings() { return report && report.source_mappings ? report.source_mappings : []; }
  function recordKey(item) { return String(item && (item.detection_id || item._key || item.id) || "").replace(/^dei-/,""); }
  function recordFor(item) { var key=recordKey(item); return records.filter(function (record) { return recordKey(record)===key; })[0] || null; }

  function observedSourcetypes(item) {
    if (item.sourcetypes && item.sourcetypes.length) { return item.sourcetypes; }
    var matched=(item.observed_sources||[]).map(function (source) { return String(source||"").toLowerCase(); });
    return sourceMappings().filter(function (mapping) {
      return [mapping.canonical_source].concat(mapping.additional_canonical_sources||[]).some(function (source) {
        return matched.indexOf(String(source||"").toLowerCase())!==-1;
      });
    }).map(function (mapping) { return mapping.observed_source; });
  }

  function buildable(item) { return {production_ready:true,field_unverified:true,field_gap:true}[item.readiness]===true; }
  function stateFor(item, record) { return record && record.state ? record.state : "recommendation"; }
  function nextAction(item, record) {
    var state=stateFor(item,record);
    if (state==="recommendation") {
      if (buildable(item)) { return "Generate and save a versioned detection draft"; }
      if (item.readiness==="partial") { return "Onboard the missing required telemetry"; }
      if (item.readiness==="field_gap") { return "Resolve confirmed fields in an engineering draft"; }
      return "Qualify telemetry and field prerequisites";
    }
    if (state==="draft") { return "Complete bounded validation in Detection Builder"; }
    if (state==="testing") { return record.validation && record.validation.status==="passed" ? "Submit validated evidence for peer review" : "Run or repair historical validation"; }
    if (state==="peer_review") { return record.review && record.review.decision==="approved" ? "Record the approved deployment target" : "Approve or return the detection with review comments"; }
    if (state==="production") { return "Record the first production health measurement"; }
    if (state==="monitoring") { return "Record health evidence, tune, or retire"; }
    if (state==="tuning") { return "Revise, validate, and resubmit the new version"; }
    return "Retirement history retained";
  }

  function mergedQueue() {
    var seen={};
    var items=recommendations().map(function (item) {
      var copy=$.extend(true,{},item); var record=recordFor(item);
      copy.lifecycle_record=record; seen[recordKey(item)]=true; return copy;
    });
    records.forEach(function (record) {
      var key=recordKey(record); if (seen[key]) { return; }
      items.push({detection_id:key,name:record.name,capability:record.capability,severity:record.severity,
        readiness:record.source_readiness||"persisted",mitre_techniques:record.mitre_attack||[],
        sourcetypes:record.sourcetypes||[],lifecycle_record:record});
    });
    return items;
  }

  function loadReport() {
    report=safeJson(window.localStorage.getItem(REPORT_KEY));
    var timestamp=Number(window.localStorage.getItem(REPORT_TIME_KEY)||0);
    if (report && report.recommendations) {
      $("#lifecycle-data-status").text("Lifecycle: "+(Store ? Store.mode() : "loading")).addClass("healthy").removeClass("unhealthy");
      $("#lifecycle-analysis-age").text(timestamp ? "Analyzed "+new Date(timestamp).toLocaleString() : "Analysis loaded");
    } else {
      $("#lifecycle-data-status").text("Lifecycle records: "+records.length).toggleClass("healthy",records.length>0).toggleClass("unhealthy",!records.length);
      $("#lifecycle-analysis-age").text(records.length ? "Using persisted lifecycle records" : "No analysis or lifecycle records");
    }
  }

  function countState(state) { return records.filter(function (record) { return record.state===state; }).length; }
  function renderMetrics() {
    var items=recommendations();
    var sources=Number(report && report.observed_source_count||0);
    var verified=items.filter(function (item) { return item.field_validation==="passed"; }).length;
    var mapped=items.filter(function (item) { return (item.mitre_techniques||[]).length>0; }).length;
    var ready=items.filter(function (item) { return item.readiness==="production_ready"; }).length;
    var passed=records.filter(function (record) { return record.validation && record.validation.status==="passed"; }).length;
    var maturity=(report?4:0)+(records.length?1:0)+(passed?1:0)+(countState("production")||countState("monitoring")?1:0);
    $("#life-sources").text(sources); $("#life-opportunities").text(mergedQueue().length);
    $("#life-mitre-mapped").text(mapped); $("#life-field-verified").text(verified);
    $("#life-telemetry-ready").text(ready); $("#life-spl-generated").text(records.length);
    $("#lifecycle-maturity-percent").text(Math.round((maturity/7)*100)+"%");
    $("#stage-discover").text(sources+" sources"); $("#stage-profile").text(verified+" profiled");
    $("#stage-qualify").text(verified+" verified"); $("#stage-recommend").text(items.length+" use cases");
    $("#stage-design").text(records.length+" designed"); $("#stage-generate").text(records.length+" SPL");
    $("#stage-validate").text(passed+" passed");
    $("#state-draft").text(countState("draft")); $("#state-testing").text(countState("testing"));
    $("#state-review").text(countState("peer_review")); $("#state-production").text(countState("production"));
    $("#state-monitoring").text(countState("monitoring")); $("#state-tuning").text(countState("tuning"));
    $("#state-retired").text(countState("retired"));
  }

  function renderQueue() {
    var query=String($("#lifecycle-search").val()||"").toLowerCase();
    var readiness=$("#lifecycle-readiness").val()||"all";
    var stage=$("#lifecycle-stage").val()||"all";
    var all=mergedQueue();
    var items=all.filter(function (item) {
      var record=item.lifecycle_record; var current=stateFor(item,record);
      var haystack=[item.name,item.capability,item.pack_id,observedSourcetypes(item).join(" "),
        (item.mitre_techniques||[]).join(" "),current].join(" ").toLowerCase();
      return (!query||haystack.indexOf(query)!==-1) &&
        (readiness==="all"||item.readiness===readiness) && (stage==="all"||current===stage);
    });
    $("#lifecycle-queue-count").text(items.length+" of "+all.length+" items");
    if (!all.length) {
      $("#lifecycle-work-queue").html('<tr><td colspan="7"><strong>No lifecycle work is available.</strong><br/>Run Analyze Environment in Command Center or restore a persisted lifecycle record.</td></tr>');
      return;
    }
    $("#lifecycle-work-queue").html(items.length ? items.map(function (item) {
      var record=item.lifecycle_record; var state=stateFor(item,record); var sources=observedSourcetypes(item);
      var button=record ? '<button type="button" class="dei-manage-lifecycle" data-detection="'+esc(recordKey(item))+'">Manage</button>' :
        (buildable(item) ? '<button type="button" class="dei-generate-detection" data-detection="'+esc(item.detection_id)+'">Build</button>' : '<span class="dei-generation-blocked">Resolve gaps</span>');
      return "<tr><td><strong>"+esc(item.name)+"</strong><small>"+esc(item.capability||item.pack_id)+"</small></td>"+
        "<td>"+esc(sources.join(" · ")||"No observed match")+"</td>"+
        '<td><span class="dei-lifecycle-readiness '+esc(item.readiness)+'">'+esc(label(item.readiness))+"</span></td>"+
        "<td>"+esc((item.mitre_techniques||[]).join(" · ")||"Not mapped")+"</td>"+
        '<td><span class="dei-lifecycle-stage '+esc(state)+'">'+esc(label(state))+"</span></td>"+
        "<td>"+esc(nextAction(item,record))+"</td><td>"+button+"</td></tr>";
    }).join("") : '<tr><td colspan="7">No items match these filters. <button type="button" class="dei-inline-reset">Reset filters</button></td></tr>');
  }

  function evidence(record) {
    var checks=[
      ["Generated SPL",!!record.spl],["MITRE mapping",(record.mitre_attack||[]).length>0],
      ["Validation passed",record.validation && record.validation.status==="passed"],
      ["Peer approval",record.review && record.review.decision==="approved"],
      ["Deployment reference",record.deployment && record.deployment.external_object_id],
      ["Health evidence",record.monitoring && record.monitoring.last_checked_at],
      ["Retirement reason",record.retirement && record.retirement.reason]
    ];
    return checks.map(function (check) { return '<div class="dei-evidence '+(check[1]?"complete":"pending")+'"><span>'+(check[1]?"✓":"○")+'</span>'+esc(check[0])+"</div>"; }).join("");
  }

  function history(record) {
    var entries=(record.history||[]).slice().reverse();
    return entries.length ? entries.map(function (entry) {
      return '<div class="dei-audit-entry"><strong>'+esc(label(entry.event))+'</strong><span>'+esc(entry.actor||"unknown")+' · '+esc(new Date(entry.at).toLocaleString())+'</span><p>'+esc(entry.detail||"No additional detail")+"</p></div>";
    }).join("") : '<p class="dei-empty">No lifecycle history recorded.</p>';
  }

  function fieldMarkup(record) {
    if (record.state==="testing") {
      return '<label class="dei-action-field"><span>Review submission note</span><textarea id="lifecycle-action-comment" placeholder="Summarize validation evidence and expected analyst behavior."></textarea></label>';
    }
    if (record.state==="peer_review") {
      if (record.review && record.review.decision==="approved") {
        return '<div class="dei-action-fields-row"><label class="dei-action-field"><span>Deployment target</span><select id="lifecycle-deployment-target"><option value="splunk_platform">Splunk saved search</option><option value="enterprise_security">Enterprise Security detection</option><option value="external">External deployment</option></select></label><label class="dei-action-field"><span>External object ID or saved-search name</span><input id="lifecycle-external-id" type="text" placeholder="Required deployment reference"/></label></div>';
      }
      return '<label class="dei-action-field"><span>Peer-review comments</span><textarea id="lifecycle-action-comment" placeholder="Required approval rationale or requested changes."></textarea></label>';
    }
    if (record.state==="production" || record.state==="monitoring") {
      return '<div class="dei-action-fields-row"><label class="dei-action-field"><span>Health</span><select id="lifecycle-health"><option value="healthy">Healthy</option><option value="degraded">Degraded</option><option value="failing">Failing</option></select></label><label class="dei-action-field"><span>Result volume</span><input id="lifecycle-result-volume" type="number" min="0" value="0"/></label><label class="dei-action-field"><span>Runtime ms</span><input id="lifecycle-runtime" type="number" min="0" value="0"/></label></div>';
    }
    if (record.state==="retired") { return '<p class="dei-empty">This record is immutable. History and evidence are retained.</p>'; }
    return '<label class="dei-action-field"><span>Lifecycle note</span><textarea id="lifecycle-action-comment" placeholder="Document the engineering decision."></textarea></label>';
  }

  function buttonMarkup(record) {
    if (record.state==="draft") { return '<button data-action="open_builder">Open Builder</button>'; }
    if (record.state==="testing") {
      return (record.validation && record.validation.status==="passed" ? '<button data-action="submit_review">Submit for peer review</button>' : "")+'<button data-action="open_builder">Open Builder</button>';
    }
    if (record.state==="peer_review") {
      return record.review && record.review.decision==="approved" ?
        '<button data-action="record_deployment">Record deployment</button><button data-action="return_draft">Reopen draft</button>' :
        '<button data-action="approve_review">Approve</button><button data-action="return_draft">Return for changes</button>';
    }
    if (record.state==="production") { return '<button data-action="record_health">Start monitoring</button><button data-action="retire">Retire</button>'; }
    if (record.state==="monitoring") { return '<button data-action="record_health">Record health</button><button data-action="start_tuning">Start tuning</button><button data-action="retire">Retire</button>'; }
    if (record.state==="tuning") { return '<button data-action="open_builder">Open Builder</button><button data-action="retire">Retire</button>'; }
    return "";
  }

  function selectRecord(key) {
    selectedRecord=records.filter(function (record) { return recordKey(record)===key; })[0]||null;
    if (!selectedRecord) { return; }
    $("#lifecycle-action-center").show(); $("#lifecycle-action-title").text(selectedRecord.name);
    $("#lifecycle-action-state").text(label(selectedRecord.state)+" · v"+(selectedRecord.version||1));
    $("#lifecycle-action-summary").text(nextAction(selectedRecord,selectedRecord));
    $("#lifecycle-action-evidence").html(evidence(selectedRecord));
    $("#lifecycle-action-fields").html(fieldMarkup(selectedRecord));
    $("#lifecycle-action-buttons").html(buttonMarkup(selectedRecord));
    $("#lifecycle-action-history").html(history(selectedRecord));
    $("#lifecycle-action-feedback").removeClass("error success").addClass("ready").text("Complete the required evidence before advancing this record.");
    document.getElementById("lifecycle-action-center").scrollIntoView({behavior:"smooth",block:"start"});
  }

  function note() { return String($("#lifecycle-action-comment").val()||"").trim(); }
  function transition(record,to,event,detail,changes) {
    var allowed={draft:["testing"],testing:["peer_review","draft"],peer_review:["production","draft"],
      production:["monitoring","retired"],monitoring:["monitoring","tuning","retired"],tuning:["testing","retired"],retired:[]};
    if ((allowed[record.state]||[]).indexOf(to)===-1) { return $.Deferred().reject("Invalid lifecycle transition").promise(); }
    var next=$.extend(true,{},record,changes||{},{state:to,status:to});
    next=Store.appendHistory(next,event,detail); return Store.write(next);
  }

  function saveAndReload(promise,message) {
    promise.done(function () {
      $("#lifecycle-action-feedback").removeClass("error ready").addClass("success").text(message);
      reloadRecords();
    }).fail(function (error) {
      $("#lifecycle-action-feedback").removeClass("success ready").addClass("error").text(String(error||"Unable to save lifecycle record."));
    });
  }

  function handleAction(action) {
    var record=$.extend(true,{},selectedRecord); var comment=note();
    if (!record) { return; }
    if (action==="open_builder") {
      window.localStorage.setItem(SELECTED_DETECTION_KEY,recordKey(record));
      window.location.href="detection_builder?detection="+encodeURIComponent(recordKey(record)); return;
    }
    if (action==="submit_review") {
      if (!record.validation || record.validation.status!=="passed") { return; }
      if (!comment) { $("#lifecycle-action-feedback").addClass("error").text("A review submission note is required."); return; }
      saveAndReload(transition(record,"peer_review","submitted_for_review",comment,{review:{decision:"pending",submitted_at:new Date().toISOString(),submitted_by:Store.username(),submission_note:comment}}),"Submitted for peer review."); return;
    }
    if (action==="approve_review") {
      if (!comment) { $("#lifecycle-action-feedback").addClass("error").text("Approval rationale is required."); return; }
      var approved=$.extend(true,{},record,{review:$.extend({},record.review,{decision:"approved",reviewed_at:new Date().toISOString(),reviewer:Store.username(),comments:comment})});
      approved=Store.appendHistory(approved,"peer_review_approved",comment); saveAndReload(Store.write(approved),"Peer review approved. Record deployment next."); return;
    }
    if (action==="return_draft") {
      if (!comment) { $("#lifecycle-action-feedback").addClass("error").text("Change rationale is required."); return; }
      saveAndReload(transition(record,"draft","returned_for_changes",comment,{review:{decision:"changes_requested",reviewer:Store.username(),comments:comment},validation:null}),"Returned to Draft."); return;
    }
    if (action==="record_deployment") {
      var target=String($("#lifecycle-deployment-target").val()||""); var external=String($("#lifecycle-external-id").val()||"").trim();
      if (!external) { $("#lifecycle-action-feedback").addClass("error").text("A deployment object ID or saved-search name is required."); return; }
      saveAndReload(transition(record,"production","deployment_recorded",target+": "+external,{deployment:{target:target,external_object_id:external,deployed_at:new Date().toISOString(),deployed_by:Store.username(),enabled_confirmed:true}}),"Production deployment recorded."); return;
    }
    if (action==="record_health") {
      var health=String($("#lifecycle-health").val()||"healthy"); var volume=Number($("#lifecycle-result-volume").val()||0); var runtime=Number($("#lifecycle-runtime").val()||0);
      var monitoring={health:health,result_volume:volume,runtime_ms:runtime,last_checked_at:new Date().toISOString(),checked_by:Store.username()};
      saveAndReload(transition(record,"monitoring","health_measured",health+", "+volume+" results, "+runtime+" ms",{monitoring:monitoring}),"Monitoring evidence recorded."); return;
    }
    if (action==="start_tuning") {
      saveAndReload(transition(record,"tuning","tuning_started",comment||"Analyst initiated tuning",{version:Number(record.version||1)+1,validation:null,review:null}),"Tuning version opened."); return;
    }
    if (action==="retire") {
      var reason=comment; if (!reason) { $("#lifecycle-action-feedback").addClass("error").text("A retirement reason is required in Lifecycle note."); return; }
      saveAndReload(transition(record,"retired","detection_retired",reason,{retirement:{reason:reason,retired_at:new Date().toISOString(),retired_by:Store.username()}}),"Detection retired with history retained.");
    }
  }

  function render() { loadReport(); renderMetrics(); renderQueue(); }
  function reloadRecords() {
    Store.load().done(function (loaded) {
      records=loaded||[]; render();
      if (selectedRecord) { selectRecord(recordKey(selectedRecord)); }
    });
  }
  function initialize(attempt) {
    Store=window.DEILifecycleStore;
    if (!Store && attempt<40) { window.setTimeout(function () { initialize(attempt+1); },50); return; }
    if (!Store) { $("#lifecycle-data-status").text("Lifecycle store unavailable").addClass("unhealthy"); return; }
    reloadRecords();
  }

  $("#lifecycle-work-queue").on("click",".dei-generate-detection",function () {
    var id=String($(this).data("detection")||""); window.localStorage.setItem(SELECTED_DETECTION_KEY,id);
    window.location.href="detection_builder?detection="+encodeURIComponent(id);
  });
  $("#lifecycle-work-queue").on("click",".dei-manage-lifecycle",function () { selectRecord(String($(this).data("detection")||"")); });
  $("#lifecycle-work-queue").on("click",".dei-inline-reset",function () { $("#lifecycle-reset-filters").trigger("click"); });
  $("#lifecycle-action-buttons").on("click","button",function () { handleAction(String($(this).data("action")||"")); });
  $("#lifecycle-reset-filters").on("click",function () { $("#lifecycle-search").val(""); $("#lifecycle-readiness,#lifecycle-stage").val("all"); renderQueue(); });
  $("#lifecycle-search,#lifecycle-readiness,#lifecycle-stage").on("input change",renderQueue);
  $("#lifecycle-workspace-menu").on("change",function () { var destination=$(this).val(); if(destination!=="detection_lifecycle"){window.location.href=destination;} });
  $(window).on("storage",function (event) { if(!event.originalEvent||event.originalEvent.key===REPORT_KEY){render();} });
  initialize(0);
});

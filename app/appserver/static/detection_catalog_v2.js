require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var Store=null; var records=[]; var selected=null;

  function esc(value) { return String(value==null?"":value).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"); }
  function label(value) { return String(value||"unknown").replace(/_/g," ").replace(/\b\w/g,function (c) { return c.toUpperCase(); }); }
  function key(record) { return String(record && (record._key||record.detection_id||record.id)||"").replace(/^dei-/,""); }
  function cataloged(record) { return !!(record && record.state!=="draft" && ((record.catalog && record.catalog.cataloged_at) || ["production","monitoring","retired"].indexOf(record.state)!==-1)); }
  function catalogStatus(record) {
    if (record.state==="retired") { return "retired"; }
    if (record.catalog && record.catalog.status==="disabled") { return "disabled"; }
    if (record.state==="monitoring") { return "monitoring"; }
    if ((record.catalog && record.catalog.status==="enabled") || (record.deployment && record.deployment.enabled)) { return "enabled"; }
    if (record.catalog && ["development","staging"].indexOf(record.catalog.status)!==-1) { return record.catalog.status; }
    return "ready";
  }
  function targetConfig(target) {
    return {
      splunk_platform:{label:"Saved-search name *",placeholder:"DEI - Detection Name - Production",help:"Enter the exact name from Splunk Settings → Searches, reports, and alerts. This records the object; it does not create or enable it."},
      enterprise_security:{label:"ES detection or correlation-search name *",placeholder:"DEI - Detection Name - Production",help:"Enter the exact object name from Enterprise Security → Content Management. Use this target only for an ES-managed detection."},
      external:{label:"External detection object ID *",placeholder:"External platform object ID",help:"Enter the immutable name or ID from the external detection platform and retain its change ticket in the enablement note."}
    }[target]||{label:"Saved-search name *",placeholder:"DEI - Detection Name - Production",help:"Enter the exact name from Splunk Settings → Searches, reports, and alerts."};
  }
  function updateDeploymentWorkflow() {
    var target=String($("#catalog-deployment-target").val()||"splunk_platform"); var environment=String($("#catalog-deployment-environment").val()||"production"); var config=targetConfig(target);
    $("#catalog-external-id-label").text(config.label); $("#catalog-external-id").attr("placeholder",config.placeholder); $("#catalog-external-id-help").text(config.help);
    var targetLabel=target==="enterprise_security"?"Enterprise Security Content Management":target==="external"?"the external platform":"Splunk saved searches";
    $("#catalog-target-help").text("This routes the object to "+targetLabel+"; the environment controls its lifecycle bucket.");
    var button=$("#catalog-action-buttons [data-catalog-action='deploy']");
    button.text(environment==="production"?"Enable in Production":"Record "+label(environment)+" deployment");
  }
  function mitre(record) { return (record.mitre_attack||[]).map(function (item) { return typeof item==="string"?item:(item.id||item.technique_id||""); }).filter(Boolean).join(" · "); }
  function health(record) { return record.monitoring && record.monitoring.health ? label(record.monitoring.health) : "Not measured"; }

  function filteredRecords() {
    var query=String($("#catalog-search").val()||"").toLowerCase(); var status=String($("#catalog-status-filter").val()||"all");
    return records.filter(cataloged).filter(function (record) {
      var deployment=record.deployment||{};
      var haystack=[record.name,key(record),mitre(record),(record.sourcetypes||[]).join(" "),deployment.external_object_id,record.state,catalogStatus(record)].join(" ").toLowerCase();
      return (!query||haystack.indexOf(query)!==-1) && (status==="all"||catalogStatus(record)===status);
    });
  }

  function render() {
    var all=records.filter(cataloged); var visible=filteredRecords();
    $("#catalog-total,#catalog-count-all").text(all.length);
    ["ready","development","staging","enabled","disabled","monitoring"].forEach(function (status) {
      $("#catalog-count-"+status).text(all.filter(function (record) { return catalogStatus(record)===status; }).length);
    });
    $("#catalog-results-summary").text(visible.length+" of "+all.length+" cataloged detection"+(all.length===1?"":"s")+" shown.");
    $("#catalog-data-status").text("Catalog: "+(Store?Store.mode():"unavailable")).toggleClass("healthy",!!Store);
    if (!all.length) {
      $("#catalog-table").html('<tr><td colspan="7"><strong>No approved detections are cataloged yet.</strong><br/>Complete validation and peer approval in Engineering Operations.</td></tr>'); return;
    }
    $("#catalog-table").html(visible.length?visible.map(function (record) {
      var deployment=record.deployment||{}; var status=catalogStatus(record);
      var deploymentState=status==="enabled"||status==="monitoring"?"DEI record: production enabled":status==="disabled"?"DEI record: disabled":"DEI record: not enabled";
      return '<tr data-catalog-status="'+esc(status)+'"><td><strong>'+esc(record.name||key(record))+'</strong><small>'+esc(key(record))+'</small></td><td>'+esc(mitre(record)||"Not mapped")+'</td><td><span class="dei-lifecycle-stage '+esc(record.state)+'">'+esc(label(record.state))+'</span></td><td><span class="dei-catalog-status '+esc(status)+'">'+esc(label(status))+'</span></td><td><span class="dei-deployment-state '+esc(status)+'">'+esc(deploymentState)+'</span><small>'+esc(deployment.external_object_id||"No deployment object recorded")+'</small></td><td>'+esc(health(record))+'</td><td><button class="dei-catalog-manage" type="button" data-key="'+esc(key(record))+'">Manage</button></td></tr>';
    }).join(""):'<tr><td colspan="7">No cataloged detections match these filters. <button class="dei-catalog-inline-reset" type="button">Reset filters</button></td></tr>');
  }

  function evidence(record) {
    var deployment=record.deployment||{}; var review=record.review||{}; var monitoring=record.monitoring||{};
    return '<dl><div><dt>Peer approval</dt><dd>'+esc(review.reviewer||"Recorded")+(review.reviewed_at?" · "+esc(new Date(review.reviewed_at).toLocaleString()):"")+'</dd></div><div><dt>Validation</dt><dd>'+esc(label(record.validation&&record.validation.status||"unknown"))+'</dd></div><div><dt>Deployment</dt><dd>'+esc(deployment.external_object_id||"Awaiting enablement")+'</dd></div><div><dt>Monitoring</dt><dd>'+esc(monitoring.last_checked_at?health(record)+" · "+new Date(monitoring.last_checked_at).toLocaleString():"No baseline recorded")+'</dd></div></dl>';
  }

  function selectRecord(recordKey) {
    selected=records.filter(function (record) { return key(record)===recordKey; })[0]||null; if (!selected) { return; }
    var status=catalogStatus(selected); var deployment=selected.deployment||{};
    $("#catalog-action-panel").prop("hidden",false); $("#catalog-action-title").text(selected.name||key(selected));
    $("#catalog-action-state").removeClass("ready development staging enabled disabled monitoring retired").addClass(status).text((status==="enabled"||status==="monitoring"?"ENABLED":status==="disabled"?"DISABLED":label(status))+" · "+label(selected.state));
    $("#catalog-action-summary").text(["ready","development","staging"].indexOf(status)!==-1?"Peer review is approved. Record or promote the governed deployment object, or return it for changes.":"Manage operational state and continue through monitoring, tuning, or retirement.");
    $("#catalog-action-evidence").html(evidence(selected));
    $("#catalog-deployment-target").val(deployment.target||"splunk_platform"); $("#catalog-deployment-environment").val(deployment.environment||"production"); $("#catalog-external-id").val(deployment.external_object_id||""); $("#catalog-enable-note").val("");
    $("#catalog-enable-fields").toggle(["ready","development","staging"].indexOf(status)!==-1);
    var buttons=["ready","development","staging"].indexOf(status)!==-1?'<button class="primary" data-catalog-action="deploy">Record deployment</button><a href="detection_workflow?detection='+encodeURIComponent(key(selected))+'#lifecycle-action-center">Open peer review and lifecycle</a><button class="danger" data-catalog-action="return_draft">Return for changes</button>':
      status==="disabled"?'<button class="primary" data-catalog-action="reenable">Mark DEI record enabled</button><a href="detection_workflow?detection='+encodeURIComponent(key(selected))+'">Open guided workflow</a>':
      status==="retired"?'<a href="detection_workflow?detection='+encodeURIComponent(key(selected))+'">Review retained history</a>':
      '<button class="danger" data-catalog-action="disable">Mark DEI record disabled</button><a href="detection_workflow?detection='+encodeURIComponent(key(selected))+'">Record health, tune, or retire →</a>';
    $("#catalog-action-buttons").html(buttons); $("#catalog-action-feedback").removeClass("error success").text("Peer-review approval is retained until this version is returned for changes."); updateDeploymentWorkflow();
    document.getElementById("catalog-action-panel").scrollIntoView({behavior:"smooth",block:"start"});
  }

  function save(record,message) {
    Store.write(record).done(function () { $("#catalog-action-feedback").addClass("success").removeClass("error").text(message); $(document).trigger("dei:catalog-action-complete",[record.catalog&&record.catalog.status]); load(); }).fail(function (error) { $("#catalog-action-feedback").addClass("error").removeClass("success").text(String(error&&error.message||error||"Unable to update the catalog.")); });
  }

  function handle(action) {
    if (!selected) { return; } var now=new Date().toISOString(); var copy=$.extend(true,{},selected);
    if (action==="deploy") {
      var external=String($("#catalog-external-id").val()||"").trim(); if (!external) { $("#catalog-action-feedback").addClass("error").text("The exact saved-search or deployment object ID is required before enablement."); return; }
      var target=String($("#catalog-deployment-target").val()||"splunk_platform"); var environment=String($("#catalog-deployment-environment").val()||"production"); var note=String($("#catalog-enable-note").val()||"").trim();
      var production=environment==="production"; copy.state=production?"production":"peer_review"; copy.status=copy.state; copy.deployment={target:target,environment:environment,external_object_id:external,change_reference:note,deployed_at:now,deployed_by:Store.username(),analyst_recorded:true,enabled:production,enabled_at:production?now:null,enabled_by:production?Store.username():null};
      copy.catalog=$.extend({},copy.catalog,{status:production?"enabled":environment,enabled_at:production?now:null,enabled_by:production?Store.username():null}); copy=Store.appendHistory(copy,production?"catalog_detection_enabled":"nonproduction_deployment_recorded",target+" / "+environment+": "+external+(note?" · "+note:"")); save(copy,production?"DEI recorded the referenced Splunk object as enabled and advanced this lifecycle record to Production. Verify the object itself in Splunk Content Management.":"Detection recorded in the "+label(environment)+" bucket. Promote it here when change control is complete."); return;
    }
    if (action==="return_draft") {
      var rationale=String($("#catalog-enable-note").val()||"").trim(); if (!rationale) { $("#catalog-action-feedback").addClass("error").text("A change rationale is required before returning this approved version to Draft."); return; }
      copy.state="draft"; copy.status="draft"; copy.review=$.extend({},copy.review,{decision:"changes_requested",reviewer:Store.username(),comments:rationale}); copy.validation=null; copy.deployment=null; copy.catalog=null; copy=Store.appendHistory(copy,"returned_for_changes",rationale); save(copy,"Detection returned to Draft and removed from active catalog buckets. Prior approval and validation must be completed again."); return;
    }
    if (action==="disable") {
      copy.catalog=$.extend({},copy.catalog,{status:"disabled",disabled_at:now,disabled_by:Store.username()}); copy.deployment=$.extend({},copy.deployment,{enabled:false,disabled_at:now,disabled_by:Store.username()}); copy=Store.appendHistory(copy,"catalog_detection_disabled","DEI lifecycle record marked disabled; external Splunk object unchanged"); save(copy,"DEI marked this lifecycle record disabled. The referenced Splunk object was not changed; verify or disable it separately in Splunk."); return;
    }
    if (action==="reenable") {
      copy.catalog=$.extend({},copy.catalog,{status:"enabled",enabled_at:now,enabled_by:Store.username()}); copy.deployment=$.extend({},copy.deployment,{enabled:true,enabled_at:now,enabled_by:Store.username()}); copy=Store.appendHistory(copy,"catalog_detection_reenabled",copy.deployment.external_object_id||"Existing deployment object"); save(copy,"DEI marked this lifecycle record enabled. The referenced Splunk object was not changed; verify its enabled state separately in Splunk.");
    }
  }

  function load() {
    Store.load().done(function (loaded) {
      records=Array.isArray(loaded)?loaded:[]; render();
      var match=String(window.location.search||"").match(/[?&]detection=([^&]+)/); var requested="";
      if (match) { try { requested=decodeURIComponent(match[1]); } catch (error) { requested=match[1]; } }
      if (requested) { selectRecord(requested); } else if (selected) { selectRecord(key(selected)); }
    });
  }
  function initialize(attempt) { Store=window.DEILifecycleStore; if (!Store&&attempt<40) { window.setTimeout(function () { initialize(attempt+1); },50); return; } if (!Store) { $("#catalog-data-status").text("Catalog unavailable").addClass("unhealthy"); return; } load(); }

  $("#catalog-table").on("click",".dei-catalog-manage",function () { selectRecord(String($(this).data("key")||"")); });
  $("#catalog-table").on("click",".dei-catalog-inline-reset",function () { $("#catalog-reset-filters").trigger("click"); });
  $("#catalog-action-buttons").on("click","button",function () { handle(String($(this).data("catalog-action")||"")); });
  $("#catalog-deployment-target,#catalog-deployment-environment").on("change",updateDeploymentWorkflow);
  $("#catalog-search,#catalog-status-filter").on("input change",render); $("#catalog-refresh").on("click",load);
  $("#catalog-reset-filters").on("click",function () { $("#catalog-search").val(""); $("#catalog-status-filter").val("all"); $("[data-catalog-filter]").removeClass("active").filter('[data-catalog-filter="all"]').addClass("active"); render(); });
  $("[data-catalog-filter]").on("click",function () { var status=String($(this).data("catalog-filter")||"all"); $("[data-catalog-filter]").removeClass("active"); $(this).addClass("active"); $("#catalog-status-filter").val(status); render(); });
  initialize(0);
});

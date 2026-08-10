require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var Store=null; var records=[]; var selected=null;

  function esc(value) { return String(value==null?"":value).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"); }
  function label(value) { return String(value||"unknown").replace(/_/g," ").replace(/\b\w/g,function (c) { return c.toUpperCase(); }); }
  function key(record) { return String(record && (record._key||record.detection_id||record.id)||"").replace(/^dei-/,""); }
  function cataloged(record) { return !!(record && ((record.catalog && record.catalog.cataloged_at) || ["production","monitoring","retired"].indexOf(record.state)!==-1)); }
  function catalogStatus(record) {
    if (record.state==="retired") { return "retired"; }
    if (record.catalog && record.catalog.status==="disabled") { return "disabled"; }
    if (record.state==="monitoring") { return "monitoring"; }
    if ((record.catalog && record.catalog.status==="enabled") || (record.deployment && record.deployment.enabled)) { return "enabled"; }
    return "ready";
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
    ["ready","enabled","disabled","monitoring"].forEach(function (status) {
      $("#catalog-count-"+status).text(all.filter(function (record) { return catalogStatus(record)===status; }).length);
    });
    $("#catalog-results-summary").text(visible.length+" of "+all.length+" cataloged detection"+(all.length===1?"":"s")+" shown.");
    $("#catalog-data-status").text("Catalog: "+(Store?Store.mode():"unavailable")).toggleClass("healthy",!!Store);
    if (!all.length) {
      $("#catalog-table").html('<tr><td colspan="7"><strong>No approved detections are cataloged yet.</strong><br/>Complete validation and peer approval in Engineering Operations.</td></tr>'); return;
    }
    $("#catalog-table").html(visible.length?visible.map(function (record) {
      var deployment=record.deployment||{}; var status=catalogStatus(record);
      return '<tr><td><strong>'+esc(record.name||key(record))+'</strong><small>'+esc(key(record))+'</small></td><td>'+esc(mitre(record)||"Not mapped")+'</td><td><span class="dei-lifecycle-stage '+esc(record.state)+'">'+esc(label(record.state))+'</span></td><td><span class="dei-catalog-status '+esc(status)+'">'+esc(label(status))+'</span></td><td>'+esc(deployment.external_object_id||"Not enabled")+'</td><td>'+esc(health(record))+'</td><td><button class="dei-catalog-manage" type="button" data-key="'+esc(key(record))+'">Manage</button></td></tr>';
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
    $("#catalog-action-state").text(label(status)+" · "+label(selected.state));
    $("#catalog-action-summary").text(status==="ready"?"Record the exact approved deployment object, then enable this detection.":"Manage operational state and continue through monitoring, tuning, or retirement.");
    $("#catalog-action-evidence").html(evidence(selected));
    $("#catalog-deployment-target").val(deployment.target||"splunk_platform"); $("#catalog-deployment-environment").val(deployment.environment||"production"); $("#catalog-external-id").val(deployment.external_object_id||""); $("#catalog-enable-note").val("");
    $("#catalog-enable-fields").toggle(status==="ready");
    var buttons=status==="ready"?'<button class="primary" data-catalog-action="enable">Enable detection</button>':
      status==="disabled"?'<button class="primary" data-catalog-action="reenable">Re-enable detection</button><a href="detection_operations?detection='+encodeURIComponent(key(selected))+'">Open lifecycle record</a>':
      status==="retired"?'<a href="detection_operations?detection='+encodeURIComponent(key(selected))+'">Review retained history</a>':
      '<button class="danger" data-catalog-action="disable">Disable detection</button><a href="detection_operations?detection='+encodeURIComponent(key(selected))+'">Record health, tune, or retire →</a>';
    $("#catalog-action-buttons").html(buttons); $("#catalog-action-feedback").removeClass("error success").text("Catalog changes preserve peer-review and lifecycle history.");
    document.getElementById("catalog-action-panel").scrollIntoView({behavior:"smooth",block:"start"});
  }

  function save(record,message) {
    Store.write(record).done(function () { $("#catalog-action-feedback").addClass("success").removeClass("error").text(message); load(); }).fail(function (error) { $("#catalog-action-feedback").addClass("error").removeClass("success").text(String(error||"Unable to update the catalog.")); });
  }

  function handle(action) {
    if (!selected) { return; } var now=new Date().toISOString(); var copy=$.extend(true,{},selected);
    if (action==="enable") {
      var external=String($("#catalog-external-id").val()||"").trim(); if (!external) { $("#catalog-action-feedback").addClass("error").text("The exact saved-search or deployment object ID is required before enablement."); return; }
      var target=String($("#catalog-deployment-target").val()||"splunk_platform"); var environment=String($("#catalog-deployment-environment").val()||"production"); var note=String($("#catalog-enable-note").val()||"").trim();
      copy.state="production"; copy.status="production"; copy.deployment={target:target,environment:environment,external_object_id:external,change_reference:note,deployed_at:now,deployed_by:Store.username(),analyst_recorded:true,enabled:true,enabled_at:now,enabled_by:Store.username()};
      copy.catalog=$.extend({},copy.catalog,{status:"enabled",enabled_at:now,enabled_by:Store.username()}); copy=Store.appendHistory(copy,"catalog_detection_enabled",target+" / "+environment+": "+external+(note?" · "+note:"")); save(copy,"Detection enabled in the catalog and advanced to Production."); return;
    }
    if (action==="disable") {
      copy.catalog=$.extend({},copy.catalog,{status:"disabled",disabled_at:now,disabled_by:Store.username()}); copy.deployment=$.extend({},copy.deployment,{enabled:false,disabled_at:now,disabled_by:Store.username()}); copy=Store.appendHistory(copy,"catalog_detection_disabled","Disabled from Detection Catalog"); save(copy,"Detection disabled. Lifecycle history and monitoring evidence were retained."); return;
    }
    if (action==="reenable") {
      copy.catalog=$.extend({},copy.catalog,{status:"enabled",enabled_at:now,enabled_by:Store.username()}); copy.deployment=$.extend({},copy.deployment,{enabled:true,enabled_at:now,enabled_by:Store.username()}); copy=Store.appendHistory(copy,"catalog_detection_reenabled",copy.deployment.external_object_id||"Existing deployment object"); save(copy,"Detection re-enabled in the catalog.");
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
  $("#catalog-search,#catalog-status-filter").on("input change",render); $("#catalog-refresh").on("click",load);
  $("#catalog-reset-filters").on("click",function () { $("#catalog-search").val(""); $("#catalog-status-filter").val("all"); $("[data-catalog-filter]").removeClass("active").filter('[data-catalog-filter="all"]').addClass("active"); render(); });
  $("[data-catalog-filter]").on("click",function () { var status=String($(this).data("catalog-filter")||"all"); $("[data-catalog-filter]").removeClass("active"); $(this).addClass("active"); $("#catalog-status-filter").val(status); render(); });
  $("#lifecycle-workspace-menu").on("change",function () { var destination=$(this).val(); if (destination) { window.location.href=destination; } });
  initialize(0);
});

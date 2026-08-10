(function ($) {
  "use strict";

  var findings=[];

  function escapeMarkup(value) {
    return String(value == null ? "" : value).replace(/&/g,"&amp;").replace(/</g,"&lt;")
      .replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
  }

  function safeJson(value, fallback) {
    try { return JSON.parse(value || "null") || fallback; } catch (error) { return fallback; }
  }

  function report() {
    try { return safeJson(window.sessionStorage.getItem("dei.latestRecommendationReport"), {}); }
    catch (error) { return {}; }
  }

  function fallbackArtifacts() {
    try { return safeJson(window.localStorage.getItem("dei.detectionDraftArtifacts"), []); }
    catch (error) { return []; }
  }

  function itemKey(item,index) {
    return String(item.detection_id || item._key || item.id || item.name || ("item-"+index)).replace(/^dei-/,"");
  }

  function recommendationFinding(item,index) {
    var readiness=String(item.readiness || "unknown");
    if (["partial","field_gap","field_unverified","unsupported","requires_es"].indexOf(readiness)===-1) { return null; }
    var key=itemKey(item,index);
    var canBuild=["field_gap","field_unverified"].indexOf(readiness)!==-1;
    return {
      key:key, name:item.name || key, severity:"attention", priority:1, category:"telemetry",
      readiness:readiness, source:item.sourcetype || item.source || item.data_source || "Telemetry evidence",
      mitre:item.mitre_attack_id || item.technique_id || "",
      reason:"Readiness is "+readiness.replace(/_/g," ")+".",
      recommendation:item.next_action || "Resolve the required telemetry or field evidence, then run validation again.",
      evidence:item.field_validation_reason || item.validation_detail || "Required field or telemetry evidence has not been verified.",
      href:canBuild ? "detection_workflow?detection="+encodeURIComponent(key) : "command_center#dei-telemetry",
      action:canBuild ? "Build engineering draft" : "Resolve telemetry evidence"
    };
  }

  function lifecycleFinding(item,index) {
    var key=itemKey(item,index); var name=item.name || key;
    var health=item.monitoring && item.monitoring.health;
    if (item.validation && item.validation.status==="failed") {
      return {key:key,name:name,severity:"critical",priority:3,category:"validation",readiness:item.readiness || "",
        source:item.sourcetype || item.source || "Generated detection",mitre:item.mitre_attack_id || "",
        reason:"The latest bounded SPL validation failed.",
        evidence:item.validation.error || item.validation.message || "Splunk did not accept the current detection search.",
        recommendation:"Open guided builder to review the validation resolution, correct the SPL, and run validation again.",
        href:"detection_workflow?detection="+encodeURIComponent(key),action:"Repair and validate"};
    }
    if (health==="degraded" || health==="failing") {
      return {key:key,name:name,severity:"critical",priority:3,category:"monitoring",readiness:item.readiness || "",
        source:item.sourcetype || item.source || "Operational detection",mitre:item.mitre_attack_id || "",
        reason:"Monitoring health is "+health+".",
        evidence:"Current health evidence indicates degraded execution or analyst outcomes.",
        recommendation:"Review result volume, runtime, analyst outcomes, and tuning evidence before advancing the detection.",
        href:"detection_workflow?detection="+encodeURIComponent(key),action:"Review health evidence"};
    }
    if ((item.state==="production" || item.state==="monitoring") && !(item.monitoring && item.monitoring.last_checked_at)) {
      return {key:key,name:name,severity:"attention",priority:2,category:"monitoring",readiness:item.readiness || "",
        source:item.sourcetype || item.source || "Operational detection",mitre:item.mitre_attack_id || "",
        reason:"This operational detection has no monitoring baseline.",
        evidence:"No last health-check timestamp is recorded for the production artifact.",
        recommendation:"Record result volume, runtime, and analyst outcome evidence to establish the health baseline.",
        href:"detection_workflow?detection="+encodeURIComponent(key),action:"Record health baseline"};
    }
    return null;
  }

  function collect(recommendations, artifacts) {
    var byKey={};
    function add(item) {
      if (!item) { return; }
      if (!byKey[item.key] || item.priority>byKey[item.key].priority) { byKey[item.key]=item; }
    }
    recommendations.forEach(function (item,index) { add(recommendationFinding(item,index)); });
    artifacts.forEach(function (item,index) { add(lifecycleFinding(item,index)); });
    return Object.keys(byKey).map(function (key) { return byKey[key]; }).sort(function (left,right) {
      return right.priority-left.priority || left.name.localeCompare(right.name);
    });
  }

  function filters() {
    return {search:String($("#action-search").val() || "").toLowerCase().trim(),
      severity:String($("#action-severity").val() || "all"),category:String($("#action-category").val() || "all"),
      readiness:String($("#action-readiness").val() || "all")};
  }

  function render() {
    var selected=filters();
    var visible=findings.filter(function (item) {
      var searchable=[item.name,item.key,item.source,item.mitre,item.reason,item.recommendation,item.evidence].join(" ").toLowerCase();
      return (!selected.search || searchable.indexOf(selected.search)!==-1) &&
        (selected.severity==="all" || item.severity===selected.severity) &&
        (selected.category==="all" || item.category===selected.category) &&
        (selected.readiness==="all" || item.readiness===selected.readiness);
    });
    $("#action-count-all").text(findings.length);
    $("#action-count-critical").text(findings.filter(function (item) { return item.severity==="critical"; }).length);
    ["telemetry","validation","monitoring"].forEach(function (category) {
      $("#action-count-"+category).text(findings.filter(function (item) { return item.category===category; }).length);
    });
    $("#action-results-summary").text(visible.length+" of "+findings.length+" finding"+(findings.length===1?"":"s")+" shown, highest priority first.");
    $("#action-empty").prop("hidden",visible.length!==0);
    $("#action-findings").html(visible.map(function (item) {
      var category={telemetry:"Telemetry / field evidence",validation:"Validation failed",monitoring:"Monitoring health"}[item.category];
      return '<article class="dei-action-finding" data-severity="'+escapeMarkup(item.severity)+'">'+
        '<div class="dei-action-finding-head"><div><span class="dei-action-severity">'+escapeMarkup(item.severity)+'</span><span>'+escapeMarkup(category)+'</span></div><small>'+escapeMarkup(item.key)+'</small></div>'+
        '<h3>'+escapeMarkup(item.name)+'</h3><div class="dei-action-meta"><span>'+escapeMarkup(item.source)+'</span>'+
        (item.mitre?'<span>'+escapeMarkup(item.mitre)+'</span>':'')+(item.readiness?'<span>'+escapeMarkup(item.readiness.replace(/_/g," "))+'</span>':'')+'</div>'+
        '<dl><div><dt>Finding</dt><dd>'+escapeMarkup(item.reason)+'</dd></div><div><dt>Evidence</dt><dd>'+escapeMarkup(item.evidence)+'</dd></div><div><dt>Recommended action</dt><dd>'+escapeMarkup(item.recommendation)+'</dd></div></dl>'+
        '<a href="'+escapeMarkup(item.href)+'">'+escapeMarkup(item.action)+' →</a></article>';
    }).join(""));
  }

  function load() {
    $("#action-loading").prop("hidden",false);
    var recommendations=report().recommendations || [];
    var Store=window.DEILifecycleStore;
    var request=Store && Store.load ? Store.load() : $.Deferred().resolve(fallbackArtifacts()).promise();
    request.done(function (records) {
      findings=collect(recommendations,Array.isArray(records)?records:[]);
      render();
    }).fail(function () {
      findings=collect(recommendations,fallbackArtifacts());
      render();
    }).always(function () { $("#action-loading").prop("hidden",true); });
  }

  function applyQueryFilter() {
    var params=new URLSearchParams(window.location.search || "");
    var category=params.get("category"); var severity=params.get("severity");
    if (["telemetry","validation","monitoring"].indexOf(category)!==-1) { $("#action-category").val(category); }
    if (["critical","attention"].indexOf(severity)!==-1) { $("#action-severity").val(severity); }
  }

  $(function () {
    if (!$("#dei-action-center-page").length) { return; }
    applyQueryFilter(); load();
  });
  $(document).on("input change","#action-search,#action-severity,#action-category,#action-readiness",render);
  $(document).on("click","[data-action-summary]",function () {
    var value=String($(this).data("action-summary"));
    $("[data-action-summary]").removeClass("active"); $(this).addClass("active");
    $("#action-severity").val(value==="critical"?"critical":"all");
    $("#action-category").val(["telemetry","validation","monitoring"].indexOf(value)!==-1?value:"all"); render();
  });
  $(document).on("click","#action-reset-filters",function () {
    $("#action-search").val(""); $("#action-severity,#action-category,#action-readiness").val("all");
    $("[data-action-summary]").removeClass("active").filter('[data-action-summary="all"]').addClass("active"); render();
  });
  $(document).on("click","#action-refresh",load);
}(jQuery));

require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var MODE_KEY = "dei.workspaceMode";
  var DENSITY_KEY = "dei.workspaceDensity";
  var MODES = ["analyst", "coverage", "engineering"];

  function safeStorageGet(key, fallback) {
    try { return window.localStorage.getItem(key) || fallback; } catch (error) { return fallback; }
  }

  function safeStorageSet(key, value) {
    try { window.localStorage.setItem(key, value); } catch (error) {
      // Layout remains usable when browser persistence is unavailable.
    }
  }

  function shell() {
    return $(".dei-shell").first();
  }

  function normalizedMode(value) {
    return MODES.indexOf(value) === -1 ? "analyst" : value;
  }

  function applyMode(mode) {
    var value = normalizedMode(mode);
    shell().attr("data-dei-workspace-mode", value);
    $(".dei-view-mode button").each(function () {
      var active = String($(this).data("mode")) === value;
      $(this).toggleClass("active", active).attr("aria-pressed", active ? "true" : "false");
    });
    safeStorageSet(MODE_KEY, value);
    $(document).trigger("dei:workspace-mode-changed", [value]);
  }

  function applyDensity(density) {
    var value = density === "compact" ? "compact" : "comfortable";
    shell().attr("data-dei-density", value);
    $("#dei-density-toggle").toggleClass("active", value === "compact")
      .attr("aria-pressed", value === "compact" ? "true" : "false")
      .text(value === "compact" ? "Comfortable spacing" : "Compact spacing");
    safeStorageSet(DENSITY_KEY, value);
  }

  function toolbar() {
    return [
      '<div class="dei-workspace-controls" aria-label="Workspace layout controls">',
      '<span>Workspace view</span>',
      '<div class="dei-view-mode" role="group" aria-label="Choose workspace view">',
      '<button type="button" data-mode="analyst" aria-pressed="false">Analyst</button>',
      '<button type="button" data-mode="coverage" aria-pressed="false">Coverage</button>',
      '<button type="button" data-mode="engineering" aria-pressed="false">Engineering</button>',
      '</div>',
      '<button id="dei-density-toggle" class="dei-density-toggle" type="button" aria-pressed="false">Compact spacing</button>',
      '</div>'
    ].join("");
  }

  function safeJson(value, fallback) {
    try { return JSON.parse(value || "null") || fallback; } catch (error) { return fallback; }
  }

  function renderHomePipeline() {
    var flow=$("#dei-home-detection-flow");
    if (!flow.length) { return; }
    var report=safeJson(safeStorageGet("dei.latestRecommendationReport", ""), {});
    var recommendations=report.recommendations || [];
    var artifacts=safeJson(safeStorageGet("dei.detectionDraftArtifacts", ""), []);
    var verified=recommendations.filter(function (item) { return item.field_validation==="passed"; }).length;
    var ready=recommendations.filter(function (item) { return item.readiness==="production_ready"; }).length;
    var generated=artifacts.filter(function (item) { return !!item.spl; }).length;
    var passed=artifacts.filter(function (item) { return item.validation && item.validation.status==="passed"; }).length;
    var failed=artifacts.filter(function (item) { return item.validation && item.validation.status==="failed"; }).length;
    var production=artifacts.filter(function (item) { return item.state==="production" || item.state==="monitoring"; }).length;
    var active=artifacts.filter(function (item) {
      return ["draft","testing","peer_review","tuning"].indexOf(item.state)!==-1;
    }).length;
    var unhealthy=artifacts.filter(function (item) {
      var health=item.monitoring && item.monitoring.health;
      return health==="degraded" || health==="failing";
    }).length;
    function itemKey(item,index) {
      return String(item.detection_id || item._key || item.id || item.name || ("item-"+index)).replace(/^dei-/,"");
    }
    var issueKeys={};
    recommendations.forEach(function (item,index) {
      if (["partial","field_gap","field_unverified","unsupported","requires_es"].indexOf(item.readiness)!==-1) {
        issueKeys[itemKey(item,index)]=true;
      }
    });
    artifacts.forEach(function (item,index) {
      var health=item.monitoring && item.monitoring.health;
      if ((item.validation && item.validation.status==="failed") || health==="degraded" || health==="failing") {
        issueKeys[itemKey(item,index)]=true;
      }
    });
    var blocked=Object.keys(issueKeys).length;
    var known={};
    recommendations.concat(artifacts).forEach(function (item,index) {
      known[itemKey(item,index)]=true;
    });
    var useCases=Object.keys(known).length;
    var healthyOperational=artifacts.filter(function (item) {
      return item.monitoring && item.monitoring.health==="healthy";
    }).length;
    var healthState=!useCases?"awaiting":unhealthy||failed?"critical":blocked?"degraded":production||healthyOperational?"healthy":"building";
    var healthLabel={awaiting:"Awaiting data",critical:"Action required",degraded:"Needs attention",healthy:"Healthy",building:"Engineering active"}[healthState];
    var healthDetail=!useCases?"Run environment analysis to establish a baseline":
      healthState==="critical"?(unhealthy+failed)+" failing health or validation item"+(unhealthy+failed===1?"":"s"):
      healthState==="degraded"?blocked+" blocked or incomplete item"+(blocked===1?"":"s"):
      healthState==="healthy"?production+" production detection"+(production===1?"":"s")+" operating without known failures":
      active+" detection"+(active===1?"":"s")+" moving through engineering";
    $("#dei-home-health").text(healthLabel).attr("data-health",healthState).closest(".dei-flow-health-card").attr("data-health",healthState);
    $("#dei-home-health-detail").text(healthDetail);
    $("#dei-home-use-case-count, #dei-topology-core-count").text(useCases);
    $("#dei-home-active-count").text(active);
    $("#dei-home-blocked-count").text(blocked);
    $("#dei-home-production-count").text(production);
    var stageCounts={
      discover:Number(report.observed_source_count || 0),
      profile:verified,
      qualify:ready,
      recommend:recommendations.length,
      design:artifacts.length,
      generate:generated,
      validate:passed
    };
    Object.keys(stageCounts).forEach(function (stage) {
      flow.find('[data-home-flow-stage="'+stage+'"] .dei-flow-stage-count').text(stageCounts[stage]);
    });
    var stages=["discover","profile","qualify","recommend","design","generate","validate"];
    var signals={
      discover:Number(report.observed_source_count || 0)>0,
      profile:verified>0,
      qualify:verified>0,
      recommend:recommendations.length>0,
      design:artifacts.length>0,
      generate:generated>0,
      validate:passed>0
    };
    var current=-1;
    stages.some(function (stage,index) {
      if (!signals[stage]) { current=index; return true; }
      return false;
    });
    stages.forEach(function (stage,index) {
      var state=signals[stage]?"complete":(index===current?"current":"upcoming");
      if (state==="current" && ((stage==="qualify" && recommendations.length>0 && verified===0) ||
          (stage==="design" && recommendations.length>0 && ready===0) ||
          (stage==="validate" && failed>0 && passed===0))) { state="blocked"; }
      flow.find('[data-home-flow-stage="'+stage+'"]').attr("data-pipeline-state",state);
    });
    var progress=current===-1 ? 100 : Math.round((current/(stages.length-1))*100);
    var currentNode=current===-1 ? $() : flow.find('[data-home-flow-stage="'+stages[current]+'"]');
    var state=current===-1 ? "complete" : (currentNode.attr("data-pipeline-state")==="blocked" ? "blocked" : "active");
    flow.css("--dei-flow-progress",progress+"%").attr("data-flow-state",state).toggleClass("has-flow",progress>0);
    $("#dei-home-flow-status").text(current===-1 ? "All evidence stages complete" :
      stages[current].replace(/^./,function (letter) { return letter.toUpperCase(); })+
      (state==="blocked" ? " is blocked by required evidence" : " is the active evidence stage"));
  }

  function initialize() {
    var root = shell();
    var bar = root.find(".dei-product-bar").first();
    if (!root.length || !bar.length || bar.find(".dei-workspace-controls").length) { return; }
    var status = bar.find(".dei-status").first();
    if (status.length) { status.before(toolbar()); } else { bar.append(toolbar()); }
    applyMode(safeStorageGet(MODE_KEY, "analyst"));
    applyDensity(safeStorageGet(DENSITY_KEY, "comfortable"));
    renderHomePipeline();
  }

  $(document).on("click", ".dei-view-mode button", function () {
    applyMode(String($(this).data("mode") || "analyst"));
  });

  $(document).on("keydown", ".dei-view-mode button", function (event) {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") { return; }
    var current = MODES.indexOf(String($(this).data("mode")));
    var next = event.key === "ArrowRight" ? (current + 1) % MODES.length : (current + MODES.length - 1) % MODES.length;
    $(".dei-view-mode button[data-mode='" + MODES[next] + "']").focus().trigger("click");
    event.preventDefault();
  });

  $(document).on("click", "#dei-density-toggle", function () {
    applyDensity(shell().attr("data-dei-density") === "compact" ? "comfortable" : "compact");
  });

  $(document).on("dei:environment-refreshed dei:environment-cleared dei:detection-artifacts-changed", renderHomePipeline);
  $(document).on("dei:environment-refresh-started", function () {
    $("#dei-home-detection-flow").attr("data-flow-state", "active");
    $("#dei-home-flow-status").text("Environment analysis is moving through telemetry discovery");
  });
  $(window).on("storage", function (event) {
    var key=event.originalEvent && event.originalEvent.key;
    if (!key || key==="dei.latestRecommendationReport" || key==="dei.detectionDraftArtifacts") { renderHomePipeline(); }
  });

  initialize();
});

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
      '<span>Experience</span>',
      '<div class="dei-view-mode" role="group" aria-label="Choose workspace view">',
      '<button type="button" data-mode="analyst" aria-pressed="false">Guided</button>',
      '<button type="button" data-mode="coverage" aria-pressed="false">Coverage</button>',
      '<button type="button" data-mode="engineering" aria-pressed="false">Advanced</button>',
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

  function workflowPage() {
    var id=String(shell().attr("id") || "");
    return {
      "dei-home-page":"home",
      "dei-command-center":"environment",
      "dei-mitre-page":"mitre",
      "dei-detection-builder-page":"builder",
      "dei-lifecycle-page":"lifecycle"
    }[id] || "home";
  }

  function workflowSnapshot() {
    var report=safeJson(safeStorageGet("dei.latestRecommendationReport", ""), {});
    var recommendations=report.recommendations || [];
    var artifacts=safeJson(safeStorageGet("dei.detectionDraftArtifacts", ""), []);
    var mapped=recommendations.filter(function (item) { return (item.mitre_techniques || []).length>0; }).length;
    var generated=artifacts.filter(function (item) { return !!item.spl; }).length;
    var validated=artifacts.filter(function (item) {
      return item.validation && item.validation.status==="passed";
    }).length;
    var operational=artifacts.filter(function (item) {
      return item.state==="production" || item.state==="monitoring";
    }).length;
    return {
      report:report,
      recommendations:recommendations,
      artifacts:artifacts,
      discovered:Number(report.observed_source_count || 0)>0,
      reviewed:recommendations.length>0 && mapped>0,
      built:generated>0,
      validated:validated>0,
      operational:operational>0
    };
  }

  function workflowMarkup() {
    var steps=[
      {key:"discover",label:"Discover",detail:"Analyze telemetry",href:"command_center#dei-telemetry"},
      {key:"review",label:"Review",detail:"MITRE and readiness",href:"mitre_coverage"},
      {key:"build",label:"Build",detail:"Generate SPL",href:"detection_builder"},
      {key:"validate",label:"Validate",detail:"Test evidence",href:"detection_builder#builder-validation-title"},
      {key:"operate",label:"Operate",detail:"Approve and monitor",href:"detection_lifecycle"}
    ];
    return [
      '<section id="dei-guided-workflow" class="dei-guided-workflow" aria-labelledby="dei-guided-workflow-title">',
      '<div class="dei-guided-workflow-copy"><p class="dei-kicker">Guided analyst workflow</p>',
      '<h2 id="dei-guided-workflow-title">Your next best action</h2><p id="dei-guided-workflow-help"></p>',
      '<details class="dei-guided-learning"><summary>How this step works</summary><p id="dei-guided-learning-text"></p></details></div>',
      '<ol class="dei-guided-workflow-steps">',
      steps.map(function (step,index) {
        return '<li data-workflow-stage="'+step.key+'"><a href="'+step.href+'"><span>'+(index+1)+'</span><div><strong>'+step.label+'</strong><small>'+step.detail+'</small></div></a></li>';
      }).join(""),
      '</ol>',
      '<div class="dei-guided-workflow-action"><span id="dei-guided-workflow-status">Step 1 of 5</span>',
      '<a id="dei-guided-workflow-cta" href="command_center#dei-telemetry">Analyze telemetry →</a>',
      '<button id="dei-guided-workflow-advanced" type="button">Show advanced tools</button></div>',
      '</section>'
    ].join("");
  }

  function ensureGuidedWorkflow() {
    if ($("#dei-guided-workflow").length) { return; }
    var root=shell();
    if (root.attr("id")==="dei-home-page" && $("#dei-home-pipeline").length) {
      $("#dei-home-pipeline").after(workflowMarkup());
    } else {
      root.find(".dei-product-bar").first().after(workflowMarkup());
    }
  }

  function renderGuidedWorkflow() {
    ensureGuidedWorkflow();
    var snapshot=workflowSnapshot();
    var page=workflowPage();
    var completion={
      discover:snapshot.discovered,
      review:snapshot.reviewed,
      build:snapshot.built,
      validate:snapshot.validated,
      operate:snapshot.operational
    };
    var sequence=["discover","review","build","validate","operate"];
    var actions={
      discover:{label:"Analyze telemetry",href:"command_center#dei-telemetry"},
      review:{label:"Review MITRE coverage",href:"mitre_coverage"},
      build:{label:"Build a detection",href:"detection_builder"},
      validate:{label:"Validate generated SPL",href:"detection_builder#builder-validation-title"},
      operate:{label:"Manage detection lifecycle",href:"detection_lifecycle"}
    };
    var current="operate";
    sequence.some(function (stage) {
      if (!completion[stage]) { current=stage; return true; }
      return false;
    });
    var completeCount=sequence.filter(function (stage) { return completion[stage]; }).length;
    $("#dei-guided-workflow").attr("data-workflow-page",page).attr("data-current-stage",current);
    $("#dei-guided-workflow [data-workflow-stage]").each(function () {
      var stage=String($(this).data("workflow-stage"));
      var state=completion[stage]?"complete":(stage===current?"current":"upcoming");
      $(this).attr("data-workflow-state",state).find("a").attr("aria-current",state==="current"?"step":null);
    });
    var pageHelp={
      home:"Follow one guided path from environment evidence to a monitored detection.",
      environment:"Choose whether Enterprise Security is enabled, run telemetry discovery, then review the saved readiness snapshot.",
      mitre:"Filter Detection Advisor by sourcetype, select a use case, and inspect its technique, tactic, platform, and readiness evidence.",
      builder:"Select a qualified recommendation, generate and review SPL, save the draft, then run bounded historical validation.",
      lifecycle:"Select Manage on a work item and complete the next evidence gate for review, deployment, monitoring, tuning, or retirement."
    };
    var learning={
      home:"DEI preserves evidence as you move between workspaces. Complete the highlighted step, then return here to see the pipeline advance.",
      environment:"Discovery inventories active sourcetypes and representative fields. DEI uses that evidence to determine which detection ideas are ready, incomplete, or unsupported.",
      mitre:"The Advisor links recommended detections to ATT&CK techniques. Start with the sourcetype filter, choose a recommendation, then read the inspector before opening Builder.",
      builder:"Builder converts a qualified recommendation into editable SPL, MITRE fields, scheduling guidance, and optional ES parameters. Validation tests the draft but does not deploy it.",
      lifecycle:"Lifecycle gates prevent a recommendation from being mistaken for a production detection. Evidence, peer approval, deployment references, and health measurements are recorded explicitly."
    };
    $("#dei-guided-workflow-help").text(pageHelp[page]);
    $("#dei-guided-learning-text").text(learning[page]);
    $("#dei-guided-workflow-advanced").text(shell().attr("data-dei-workspace-mode")==="engineering" ? "Return to guided view" : "Show advanced tools");
    $("#dei-guided-workflow-status").text(completeCount===sequence.length ? "Workflow operational" : "Step "+(sequence.indexOf(current)+1)+" of 5");
    $("#dei-guided-workflow-cta").attr("href",actions[current].href).text(actions[current].label+" →");
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
    renderGuidedWorkflow();
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

  $(document).on("click", "#dei-guided-workflow-advanced", function () {
    applyMode(shell().attr("data-dei-workspace-mode")==="engineering" ? "analyst" : "engineering");
    renderGuidedWorkflow();
  });

  $(document).on("dei:environment-refreshed dei:environment-cleared dei:detection-artifacts-changed", function () {
    renderHomePipeline();
    renderGuidedWorkflow();
  });
  $(document).on("dei:environment-refresh-started", function () {
    $("#dei-home-detection-flow").attr("data-flow-state", "active");
    $("#dei-home-flow-status").text("Environment analysis is moving through telemetry discovery");
  });
  $(window).on("storage", function (event) {
    var key=event.originalEvent && event.originalEvent.key;
    if (!key || key==="dei.latestRecommendationReport" || key==="dei.detectionDraftArtifacts") { renderHomePipeline(); renderGuidedWorkflow(); }
  });

  initialize();
});

require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var MODE_KEY = "dei.workspaceMode";
  var DENSITY_KEY = "dei.workspaceDensity";
  var MODES = ["analyst", "coverage", "engineering"];

  function safeStorageGet(key, fallback) {
    try { return window.localStorage.getItem(key) || fallback; } catch (error) { return fallback; }
  }

  function safeSessionGet(key, fallback) {
    try { return window.sessionStorage.getItem(key) || fallback; } catch (error) { return fallback; }
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

  function announceAction(message, state) {
    var notice=$("#dei-interaction-status");
    if (!notice.length) {
      shell().append('<div id="dei-interaction-status" class="dei-interaction-status" role="status" aria-live="polite"></div>');
      notice=$("#dei-interaction-status");
    }
    notice.attr("data-state",state || "info").text(message).addClass("visible");
    window.clearTimeout(announceAction.timer);
    announceAction.timer=window.setTimeout(function () { notice.removeClass("visible"); },4200);
  }

  function advancedActions() {
    var actions={
      home:[
        {label:"Run an environment scan",href:"command_center#dei-telemetry",detail:"Collect current telemetry and field evidence."},
        {label:"Review MITRE coverage",href:"mitre_coverage",detail:"Inspect mapped tactics and recommended use cases."},
        {label:"Open Detection Builder",href:"detection_builder",detail:"Generate and validate reviewable SPL."},
        {label:"Manage lifecycle",href:"detection_lifecycle",detail:"Advance drafts through approval and monitoring."}
      ],
      environment:[
        {label:"Run intelligence scan",target:"#dei-analyze",detail:"Start a fresh seven-day telemetry and field scan."},
        {label:"View intelligence results",href:"environment_insights",detail:"Open readiness, coverage, and telemetry DNA results."},
        {label:"Review MITRE coverage",href:"mitre_coverage",detail:"Continue from telemetry evidence to ATT&CK mapping."}
      ],
      environment_insights:[
        {label:"Run a new scan",href:"command_center#dei-telemetry",detail:"Replace the active session intelligence with fresh evidence."},
        {label:"Review MITRE coverage",href:"mitre_coverage",detail:"Inspect mapped techniques and Detection Advisor recommendations."},
        {label:"Open Detection Builder",href:"detection_builder",detail:"Generate SPL from a telemetry-supported recommendation."}
      ],
      mitre:[
        {label:"Filter Detection Advisor",target:"#mitre-sourcetype-filter",detail:"Narrow recommendations to one observed sourcetype."},
        {label:"Open Detection Builder",href:"detection_builder",detail:"Generate SPL for a selected qualified recommendation."},
        {label:"Manage lifecycle",href:"detection_lifecycle",detail:"Review work-queue readiness and evidence gates."}
      ],
      builder:[
        {label:"Select a recommendation",target:"#builder-detection-select",detail:"Choose a scan-supported detection use case."},
        {label:"Generate detection draft",target:"#builder-generate",detail:"Build editable SPL, MITRE metadata, and schedule guidance."},
        {label:"Run validation",target:"#builder-run-validation",detail:"Execute a bounded historical test after generating a draft."},
        {label:"Manage lifecycle",href:"detection_lifecycle",detail:"Submit validated evidence for review and deployment."}
      ],
      lifecycle:[
        {label:"Search the work queue",target:"#lifecycle-search",detail:"Find a recommendation or persisted detection record."},
        {label:"Reset work-queue filters",target:"#lifecycle-reset-filters",detail:"Restore the complete actionable work queue."},
        {label:"Open Detection Builder",href:"detection_builder",detail:"Generate or revise the selected detection artifact."}
      ]
    };
    return actions[workflowPage()] || actions.home;
  }

  function advancedPanelMarkup() {
    return [
      '<section id="dei-advanced-action-center" class="dei-advanced-action-center" hidden="hidden" aria-labelledby="dei-advanced-action-title">',
      '<div class="dei-advanced-action-head"><div><p class="dei-kicker">Advanced action center</p>',
      '<h2 id="dei-advanced-action-title">Engineering tools and next steps</h2>',
      '<p>Every action below opens a workspace or moves focus to a working control.</p></div>',
      '<button id="dei-advanced-action-close" type="button" aria-label="Close advanced action center">Close</button></div>',
      '<div id="dei-advanced-action-grid" class="dei-advanced-action-grid"></div></section>'
    ].join("");
  }

  function ensureAdvancedPanel() {
    if ($("#dei-advanced-action-center").length) { return; }
    $("#dei-guided-workflow").after(advancedPanelMarkup());
  }

  function renderAdvancedActions() {
    ensureAdvancedPanel();
    $("#dei-advanced-action-grid").html(advancedActions().map(function (action) {
      var attrs=action.href ? 'href="'+action.href+'"' :
        'href="#" role="button" data-dei-focus="'+action.target+'"';
      return '<a class="dei-advanced-action" '+attrs+'><strong>'+action.label+'</strong><span>'+action.detail+'</span><b>→</b></a>';
    }).join(""));
  }

  function openAdvancedTools() {
    applyMode("engineering");
    renderGuidedWorkflow();
    renderAdvancedActions();
    $("#dei-advanced-action-center").prop("hidden",false);
    $("#dei-guided-workflow-advanced").text("Hide advanced tools").attr("aria-expanded","true");
    $("#dei-advanced-action-title").attr("tabindex","-1").focus();
    announceAction("Advanced tools opened. Choose an engineering action or workspace next step.","success");
  }

  function closeAdvancedTools(preserveMode) {
    if (!preserveMode) { applyMode("analyst"); }
    $("#dei-advanced-action-center").prop("hidden",true);
    $("#dei-guided-workflow-advanced").text("Show advanced tools").attr("aria-expanded","false");
    announceAction("Advanced tools closed. Guided workflow remains active.","info");
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
    var report=safeJson(safeSessionGet("dei.latestRecommendationReport", ""), {});
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
      "dei-environment-insights":"environment_insights",
      "dei-mitre-page":"mitre",
      "dei-detection-builder-page":"builder",
      "dei-lifecycle-page":"lifecycle"
    }[id] || "home";
  }

  function workflowSnapshot() {
    var report=safeJson(safeSessionGet("dei.latestRecommendationReport", ""), {});
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
      '<button id="dei-guided-workflow-advanced" type="button" aria-expanded="false" aria-controls="dei-advanced-action-center">Show advanced tools</button></div>',
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
      environment:"Choose whether Enterprise Security is enabled, run telemetry discovery, then continue to the saved environment intelligence results.",
      environment_insights:"Review the persisted readiness snapshot, then continue to MITRE coverage or Builder.",
      mitre:"Filter Detection Advisor by sourcetype, select a use case, and inspect its technique, tactic, platform, and readiness evidence.",
      builder:"Select a qualified recommendation, generate and review SPL, save the draft, then run bounded historical validation.",
      lifecycle:"Select Manage on a work item and complete the next evidence gate for review, deployment, monitoring, tuning, or retirement."
    };
    var learning={
      home:"DEI preserves evidence as you move between workspaces. Complete the highlighted step, then return here to see the pipeline advance.",
      environment:"Discovery inventories active sourcetypes and representative fields. DEI uses that evidence to determine which detection ideas are ready, incomplete, or unsupported.",
      environment_insights:"These widgets are derived from the saved discovery report. Use Refresh to replace the snapshot or Clear to start over.",
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

  var ONBOARDING_KEY = "dei.onboardingDismissed.v1";
  var ONBOARDING_SESSION_KEY = "dei.onboardingSeen.session";

  function safeSessionGet(key) {
    try { return window.sessionStorage.getItem(key) || ""; } catch (error) { return ""; }
  }

  function safeSessionSet(key, value) {
    try { window.sessionStorage.setItem(key, value); } catch (error) {
      // The dialog can still be dismissed when session persistence is unavailable.
    }
  }

  function onboardingMarkup() {
    return [
      '<div id="dei-onboarding-overlay" class="dei-onboarding-overlay" role="presentation">',
      '<section class="dei-onboarding-dialog" role="dialog" aria-modal="true" aria-labelledby="dei-onboarding-title" aria-describedby="dei-onboarding-description">',
      '<button id="dei-onboarding-close" class="dei-onboarding-close" type="button" aria-label="Close welcome guide">×</button>',
      '<div class="dei-onboarding-heading"><p class="dei-kicker">Welcome to DEI</p>',
      '<h2 id="dei-onboarding-title">From telemetry to a monitored detection</h2>',
      '<p id="dei-onboarding-description">Start with one guided path. DEI preserves the evidence and explains each gate as you progress.</p></div>',
      '<ol class="dei-onboarding-path">',
      '<li><span>1</span><div><strong>Discover</strong><p>Analyze sourcetypes and fields in the Splunk environment.</p></div></li>',
      '<li><span>2</span><div><strong>Review</strong><p>Use Detection Advisor to understand readiness and MITRE ATT&amp;CK coverage.</p></div></li>',
      '<li><span>3</span><div><strong>Build</strong><p>Generate and review platform SPL, MITRE context, schedules, and optional ES parameters.</p></div></li>',
      '<li><span>4</span><div><strong>Validate</strong><p>Run bounded historical testing and preserve the result as lifecycle evidence.</p></div></li>',
      '<li><span>5</span><div><strong>Operate</strong><p>Manage peer review, deployment, monitoring, tuning, and retirement.</p></div></li>',
      '</ol>',
      '<div class="dei-onboarding-foot">',
      '<label><input id="dei-onboarding-dismiss-permanently" type="checkbox"/> <span>Do not show this welcome guide again</span></label>',
      '<div><button id="dei-onboarding-not-now" type="button">Explore first</button>',
      '<a id="dei-onboarding-start" href="command_center#dei-telemetry">Start telemetry discovery →</a></div>',
      '</div></section></div>'
    ].join("");
  }

  function showOnboarding() {
    if (workflowPage()!=="home" || safeStorageGet(ONBOARDING_KEY, "")==="true" ||
        safeSessionGet(ONBOARDING_SESSION_KEY)==="true" || $("#dei-onboarding-overlay").length) { return; }
    $("body").append(onboardingMarkup()).addClass("dei-onboarding-open");
    window.setTimeout(function () { $("#dei-onboarding-close").focus(); }, 0);
  }

  function ensureScanContext() {
    if ($("#dei-active-scan-context").length) { return; }
    shell().find(".dei-product-bar").first().after(
      '<section id="dei-active-scan-context" class="dei-active-scan-context" aria-live="polite"></section>'
    );
  }

  function renderScanContext() {
    var report=safeJson(safeSessionGet("dei.latestRecommendationReport", ""), {});
    var timestamp=Number(safeSessionGet("dei.latestRecommendationTime", "0") || 0);
    var sources=Number(report.observed_source_count || 0);
    ensureScanContext();
    if (!timestamp || !sources) {
      $("#dei-active-scan-context").attr("data-state","empty").html(
        '<span><b>No active environment scan</b> — downstream intelligence remains empty until you run discovery.</span>' +
        '<a href="command_center#dei-telemetry">Run intelligence scan →</a>'
      );
      return;
    }
    $("#dei-active-scan-context").attr("data-state","active").html(
      '<span><b>Active environment scan</b> · ' + sources + ' source types · completed ' +
      new Date(timestamp).toLocaleString() + '</span><a href="command_center#dei-telemetry">Run a new scan →</a>'
    );
  }

  function renderEnvironmentSplitState() {
    var report=safeJson(safeSessionGet("dei.latestRecommendationReport", ""), {});
    var ready=Number(report.observed_source_count || 0)>0 || (report.recommendations || []).length>0;
    $("#dei-discovery-result-state").text(ready ? "Analysis ready" : "Waiting for analysis")
      .attr("data-state",ready ? "ready" : "waiting");
    $("#dei-open-environment-insights").toggleClass("ready",ready)
      .attr("aria-label",ready ? "View saved environment intelligence results" :
        "Open environment intelligence results; no saved analysis is currently available");
  }

  function closeOnboarding() {
    if ($("#dei-onboarding-dismiss-permanently").is(":checked")) {
      safeStorageSet(ONBOARDING_KEY, "true");
    }
    safeSessionSet(ONBOARDING_SESSION_KEY, "true");
    $("#dei-onboarding-overlay").remove();
    $("body").removeClass("dei-onboarding-open");
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
    renderEnvironmentSplitState();
    renderScanContext();
    showOnboarding();
  }

  $(document).on("click", ".dei-view-mode button", function () {
    var mode=String($(this).data("mode") || "analyst");
    applyMode(mode);
    if (mode==="engineering") {
      openAdvancedTools();
    } else {
      closeAdvancedTools(true);
      announceAction(mode==="coverage" ?
        "Coverage experience active. Coverage-focused panels and ATT&CK context are prioritized." :
        "Guided experience active. Follow the highlighted next best action.","success");
    }
  });

  $(document).on("keydown", ".dei-view-mode button", function (event) {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") { return; }
    var current = MODES.indexOf(String($(this).data("mode")));
    var next = event.key === "ArrowRight" ? (current + 1) % MODES.length : (current + MODES.length - 1) % MODES.length;
    $(".dei-view-mode button[data-mode='" + MODES[next] + "']").focus().trigger("click");
    event.preventDefault();
  });

  $(document).on("click", "#dei-density-toggle", function () {
    var next=shell().attr("data-dei-density") === "compact" ? "comfortable" : "compact";
    applyDensity(next);
    announceAction((next==="compact" ? "Compact" : "Comfortable")+" spacing applied.","success");
  });

  $(document).on("click", "#dei-guided-workflow-advanced", function () {
    if ($("#dei-advanced-action-center").is(":visible")) {
      closeAdvancedTools(false);
    } else {
      openAdvancedTools();
    }
  });

  $(document).on("click", "#dei-advanced-action-close", function () { closeAdvancedTools(false); });

  $(document).on("click", "[data-dei-focus]", function (event) {
    event.preventDefault();
    var selector=String($(this).attr("data-dei-focus") || "");
    var target=$(selector).first();
    if (!target.length) {
      announceAction("That control is not available on this page. Use the workspace link shown with the action.","error");
      return;
    }
    target[0].scrollIntoView({behavior:"smooth",block:"center"});
    window.setTimeout(function () {
      target.focus();
      target.addClass("dei-action-target");
      window.setTimeout(function () { target.removeClass("dei-action-target"); },1800);
    },350);
    announceAction("Moved to "+$(this).find("strong").text()+". Complete the highlighted control.","success");
  });

  $(document).on("click", "#dei-onboarding-close, #dei-onboarding-not-now", closeOnboarding);
  $(document).on("click", "#dei-onboarding-start", function () {
    if ($("#dei-onboarding-dismiss-permanently").is(":checked")) { safeStorageSet(ONBOARDING_KEY, "true"); }
    safeSessionSet(ONBOARDING_SESSION_KEY, "true");
  });
  $(document).on("keydown", function (event) {
    var overlay=$("#dei-onboarding-overlay");
    if (!overlay.length) { return; }
    if (event.key==="Escape") { closeOnboarding(); return; }
    if (event.key==="Tab") {
      var focusable=overlay.find('a[href],button,input:not([disabled])').filter(":visible");
      if (!focusable.length) { return; }
      var first=focusable[0]; var last=focusable[focusable.length-1];
      if (event.shiftKey && document.activeElement===first) { $(last).focus(); event.preventDefault(); }
      else if (!event.shiftKey && document.activeElement===last) { $(first).focus(); event.preventDefault(); }
    }
  });

  $(document).on("dei:environment-refreshed dei:environment-cleared dei:detection-artifacts-changed", function () {
    renderHomePipeline();
    renderGuidedWorkflow();
    renderEnvironmentSplitState();
    renderScanContext();
  });
  $(document).on("dei:environment-refresh-started", function () {
    $("#dei-home-detection-flow").attr("data-flow-state", "active");
    $("#dei-home-flow-status").text("Environment analysis is moving through telemetry discovery");
  });
  $(window).on("storage", function (event) {
    var key=event.originalEvent && event.originalEvent.key;
    if (!key || key==="dei.latestRecommendationReport" || key==="dei.detectionDraftArtifacts") { renderHomePipeline(); renderGuidedWorkflow(); renderEnvironmentSplitState(); renderScanContext(); }
  });

  initialize();
});

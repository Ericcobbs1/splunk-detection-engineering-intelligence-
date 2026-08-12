require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var MODE_KEY = "dei.workspaceMode";
  var DENSITY_KEY = "dei.workspaceDensity";
  var MODES = ["analyst", "coverage", "engineering"];
  var homeLifecycleRecords = null;
  var homeLifecycleLoading = false;

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
        {label:"Run an environment scan",href:"command_center#dei-telemetry",detail:"Collect current telemetry and field evidence now."},
        {label:"Review MITRE coverage",href:"mitre_coverage",detail:"Inspect mapped tactics and recommended use cases."},
        {label:"Open Guided Detection Builder",href:"detection_workflow",detail:"Generate and validate reviewable SPL."},
        {label:"Continue guided workflow",href:"detection_workflow",detail:"Resume one detection at its exact next required action."}
      ],
      environment:[
        {label:"Run intelligence scan",target:"#dei-analyze",detail:"Start a fresh seven-day telemetry and field scan."},
        {label:"View intelligence results",href:"environment_insights",detail:"Open readiness, coverage, and telemetry DNA results."},
        {label:"Review MITRE coverage",href:"mitre_coverage",detail:"Continue from telemetry evidence to ATT&CK mapping."}
      ],
      environment_insights:[
        {label:"Run a new scan",href:"command_center#dei-telemetry",detail:"Replace the active session intelligence with fresh evidence."},
        {label:"Review MITRE coverage",href:"mitre_coverage",detail:"Inspect mapped techniques and Detection Advisor recommendations."},
        {label:"Open Guided Detection Builder",href:"detection_workflow",detail:"Generate SPL from a telemetry-supported recommendation."}
      ],
      mitre:[
        {label:"Filter Detection Advisor",target:"#mitre-sourcetype-filter",detail:"Narrow recommendations to one observed sourcetype."},
        {label:"Open Guided Detection Builder",href:"detection_workflow",detail:"Generate SPL for a selected qualified recommendation."},
        {label:"Continue guided workflow",href:"detection_workflow",detail:"Resume one detection at its exact next required action."}
      ],
      builder:[
        {label:"Select a recommendation",target:"#builder-detection-select",detail:"Choose a scan-supported detection use case."},
        {label:"Generate detection draft",target:"#builder-generate",detail:"Build editable SPL, MITRE metadata, and schedule guidance."},
        {label:"Run validation",target:"#builder-run-validation",detail:"Execute a bounded historical test after generating a draft."},
        {label:"Continue guided workflow",href:"detection_workflow",detail:"Move this detection through review, catalog, and monitoring."}
      ],
      lifecycle:[
        {label:"Search the work queue",target:"#lifecycle-search",detail:"Find a recommendation or persisted detection record."},
        {label:"Reset work-queue filters",target:"#lifecycle-reset-filters",detail:"Restore the complete actionable work queue."},
        {label:"Open Guided Detection Builder",href:"detection_workflow",detail:"Generate or revise the selected detection artifact."}
      ]
    };
    return actions[workflowPage()] || actions.home;
  }

  function coverageActions() {
    var actions={
      home:[
        {label:"Review environment intelligence",href:"environment_insights",detail:"Inspect telemetry DNA, readiness, and coverage evidence."},
        {label:"Investigate MITRE coverage",href:"mitre_coverage",detail:"Filter recommendations and inspect uncovered ATT&CK behavior."},
        {label:"Review detection action items",href:"detection_action_center",detail:"Open telemetry, validation, and health action items."}
      ],
      environment:[
        {label:"Run intelligence scan",href:"command_center#dei-telemetry",detail:"Generate the evidence required for a real coverage assessment."},
        {label:"Open coverage results",href:"environment_insights",detail:"Review detection potential, telemetry domains, and tactic coverage."},
        {label:"Investigate MITRE coverage",href:"mitre_coverage",detail:"Inspect technique mappings and protection detail."}
      ],
      environment_insights:[
        {label:"Inspect ATT&CK coverage",href:"mitre_coverage",detail:"Move from summary coverage into tactic and technique evidence."},
        {label:"Build a coverage-closing detection",href:"detection_workflow",detail:"Generate SPL for a qualified recommendation."},
        {label:"Run a new assessment",href:"command_center#dei-telemetry",detail:"Replace the current coverage snapshot with fresh telemetry."}
      ],
      mitre:[
        {label:"Filter by sourcetype",target:"#mitre-sourcetype-filter",detail:"Find coverage recommendations supported by one telemetry source."},
        {label:"Inspect the ATT&CK matrix",target:"#mitre-matrix",detail:"Review tactic columns and mapped technique state."},
        {label:"Build a mapped detection",href:"detection_workflow",detail:"Generate SPL with embedded ATT&CK context."}
      ],
      builder:[
        {label:"Review MITRE coverage",href:"mitre_coverage",detail:"Confirm the coverage gap and technique mapping before building."},
        {label:"Select a detection",target:"#builder-detection-select",detail:"Choose a qualified coverage recommendation."},
        {label:"Validate coverage logic",target:"#builder-run-validation",detail:"Test the generated query against current Splunk telemetry."}
      ],
      lifecycle:[
        {label:"Filter telemetry-ready work",target:"#lifecycle-readiness",detail:"Narrow the queue to detections ready for engineering."},
        {label:"Review ATT&CK mappings",href:"mitre_coverage",detail:"Inspect the coverage context behind lifecycle work."},
        {label:"Review pipeline health",target:".dei-pipeline-section",detail:"Inspect blocked stages and evidence requirements."}
      ]
    };
    return actions[workflowPage()] || actions.home;
  }

  function guidedActions() {
    var currentLabel=String($("#dei-guided-workflow-cta").text() || "Continue guided workflow").replace(/\s*→\s*$/,"");
    var currentHref=String($("#dei-guided-workflow-cta").attr("href") || "command_center#dei-telemetry");
    return [
      {label:currentLabel,href:currentHref,detail:String($("#dei-guided-workflow-help").text() || "Complete the highlighted workflow step.")},
      {label:"Open step guidance",target:".dei-guided-learning summary",activate:true,detail:"See what this step does, why it matters, and what evidence it creates."},
      {label:"Review active scan",href:"environment_insights",detail:"Confirm the telemetry and readiness evidence feeding this workflow."}
    ];
  }

  function experiencePanelMarkup() {
    return [
      '<section id="dei-advanced-action-center" class="dei-advanced-action-center" hidden="hidden" aria-labelledby="dei-advanced-action-title">',
      '<div class="dei-advanced-action-head"><div><p id="dei-experience-action-kicker" class="dei-kicker">Experience action center</p>',
      '<h2 id="dei-advanced-action-title">Choose a meaningful next step</h2>',
      '<p id="dei-experience-action-summary">Every action opens a workspace or moves focus to a working control.</p></div>',
      '<button id="dei-advanced-action-close" type="button" aria-label="Close experience action center">Close</button></div>',
      '<div id="dei-advanced-action-grid" class="dei-advanced-action-grid"></div></section>'
    ].join("");
  }

  function ensureExperiencePanel() {
    if ($("#dei-advanced-action-center").length) { return; }
    $("#dei-guided-workflow").after(experiencePanelMarkup());
  }

  function renderExperienceActions(mode) {
    var config={
      analyst:{kicker:"Guided experience",title:"Complete the next required step",summary:"Follow the current evidence gate, or open the explanation before continuing.",actions:guidedActions()},
      coverage:{kicker:"Coverage experience",title:"Investigate and close detection coverage gaps",summary:"Use current telemetry and ATT&CK evidence to choose the next coverage action.",actions:coverageActions()},
      engineering:{kicker:"Advanced experience",title:"Engineering tools and next steps",summary:"Open a workspace or move directly to a working engineering control.",actions:advancedActions()}
    }[mode] || {actions:guidedActions()};
    ensureExperiencePanel();
    $("#dei-experience-action-kicker").text(config.kicker);
    $("#dei-advanced-action-title").text(config.title);
    $("#dei-experience-action-summary").text(config.summary);
    $("#dei-advanced-action-grid").html(config.actions.map(function (action) {
      var attrs=action.href ? 'href="'+action.href+'"' :
        'href="#" role="button" data-dei-focus="'+action.target+'"'+(action.activate?' data-dei-activate="true"':'');
      return '<a class="dei-advanced-action" '+attrs+'><strong>'+action.label+'</strong><span>'+action.detail+'</span><b>→</b></a>';
    }).join(""));
  }

  function openExperienceActions(mode) {
    applyMode(mode);
    renderGuidedWorkflow();
    renderExperienceActions(mode);
    $("#dei-advanced-action-center").prop("hidden",false).attr("data-experience",mode);
    $("#dei-guided-workflow-advanced").text(mode==="engineering" ? "Hide advanced tools" : "Show advanced tools")
      .attr("aria-expanded",mode==="engineering" ? "true" : "false");
    $("#dei-advanced-action-title").attr("tabindex","-1").focus();
    announceAction((mode==="engineering"?"Advanced":mode==="coverage"?"Coverage":"Guided")+" actions opened. Choose a next step below.","success");
  }

  function openAdvancedTools() { openExperienceActions("engineering"); }

  function closeAdvancedTools(preserveMode) {
    if (!preserveMode) { applyMode("analyst"); }
    $("#dei-advanced-action-center").prop("hidden",true);
    $("#dei-guided-workflow-advanced").text("Show advanced tools").attr("aria-expanded","false");
    announceAction("Experience actions closed. The selected workspace view remains available.","info");
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

  function escapeMarkup(value) {
    return String(value == null ? "" : value).replace(/&/g,"&amp;").replace(/</g,"&lt;")
      .replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
  }

  function safeJson(value, fallback) {
    try { return JSON.parse(value || "null") || fallback; } catch (error) { return fallback; }
  }

  function finishHomeRefresh(message, state) {
    $("#dei-home-refresh").prop("disabled",false).attr("aria-busy","false").removeClass("refreshing");
    if (message) { announceAction(message,state); }
  }

  function refreshHomeLifecycleRecords(interactive) {
    var Store=window.DEILifecycleStore;
    if (!$("#dei-home-detection-flow").length || homeLifecycleLoading) { return; }
    if (interactive) {
      $("#dei-home-refresh").prop("disabled",true).attr("aria-busy","true").addClass("refreshing");
      announceAction("Refreshing saved lifecycle, validation, deployment, and health evidence…","info");
    }
    if (!Store || !Store.load) {
      homeLifecycleRecords=safeJson(safeStorageGet("dei.detectionDraftArtifacts", ""), []);
      renderHomePipeline(true);
      if (interactive) { finishHomeRefresh("Pipeline refreshed from the latest browser evidence.","success"); }
      return;
    }
    homeLifecycleLoading=true;
    Store.load().done(function (records) {
      homeLifecycleRecords=Array.isArray(records) ? records : [];
      renderHomePipeline(true);
      if (interactive) { finishHomeRefresh("Pipeline refreshed with the latest lifecycle evidence.","success"); }
    }).fail(function () {
      homeLifecycleRecords=safeJson(safeStorageGet("dei.detectionDraftArtifacts", ""), []);
      renderHomePipeline(true);
      if (interactive) { finishHomeRefresh("Lifecycle service was unavailable. Showing the latest saved browser evidence.","error"); }
    }).always(function () { homeLifecycleLoading=false; });
  }

  function renderHomeHealthActions(issues, healthState) {
    if (issues.length) {
      $("#dei-home-health-action").attr("href","detection_action_center").text("Review "+issues.length+" action item"+(issues.length===1?"":"s")+" →");
      return;
    }
    var empty={
      awaiting:{title:"No active assessment",detail:"Run an intelligence scan to populate the detection pipeline.",href:"command_center#dei-telemetry",action:"Run intelligence scan"},
      building:{title:"Engineering is active",detail:"Review drafts, tests, and approvals in the lifecycle work queue.",href:"detection_catalog",action:"Open lifecycle work queue"},
      healthy:{title:"Operational detections are healthy",detail:"Review monitoring evidence and keep health measurements current.",href:"detection_catalog",action:"Review monitoring evidence"}
    }[healthState] || {title:"Review pipeline evidence",detail:"Inspect current lifecycle records and their next required actions.",href:"detection_lifecycle",action:"Open lifecycle workspace"};
    $("#dei-home-health-action").attr("href",empty.href).text(empty.action+" →");
  }

  function renderHomePipeline(skipLifecycleRefresh) {
    var flow=$("#dei-home-detection-flow");
    if (!flow.length) { return; }
    if (!skipLifecycleRefresh && homeLifecycleRecords===null && !homeLifecycleLoading) {
      refreshHomeLifecycleRecords();
    }
    var report=safeJson(safeSessionGet("dei.latestRecommendationReport", ""), {});
    var recommendations=report.recommendations || [];
    var artifacts=homeLifecycleRecords===null ? [] : homeLifecycleRecords;
    var verified=recommendations.filter(function (item) { return item.field_validation==="passed"; }).length;
    var ready=recommendations.filter(function (item) { return item.readiness==="production_ready"; }).length;
    var buildable=recommendations.filter(function (item) {
      return ["production_ready","field_unverified","field_gap"].indexOf(item.readiness)!==-1;
    }).length;
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
    var missingHealth=artifacts.filter(function (item) {
      return (item.state==="production" || item.state==="monitoring") &&
        !(item.monitoring && item.monitoring.last_checked_at);
    }).length;
    function itemKey(item,index) {
      return String(item.detection_id || item._key || item.id || item.name || ("item-"+index)).replace(/^dei-/,"");
    }
    var issues={};
    function putIssue(key, issue) {
      if (!issues[key] || Number(issue.priority||0)>Number(issues[key].priority||0)) { issues[key]=issue; }
    }
    recommendations.forEach(function (item,index) {
      if (["partial","field_gap","field_unverified","unsupported","requires_es"].indexOf(item.readiness)===-1) { return; }
      var key=itemKey(item,index);
      var canBuild=["field_gap","field_unverified"].indexOf(item.readiness)!==-1;
      putIssue(key,{name:item.name || key,
        reason:"Readiness is "+String(item.readiness||"unknown").replace(/_/g," ")+". "+(item.next_action || "Resolve the required telemetry or field evidence."),
        href:canBuild ? "detection_workflow?detection="+encodeURIComponent(key) : "command_center#dei-telemetry",
        action:canBuild ? "Build engineering draft" : "Resolve telemetry evidence",severity:"attention",priority:1});
    });
    artifacts.forEach(function (item,index) {
      var key=itemKey(item,index); var name=item.name || key;
      var health=item.monitoring && item.monitoring.health;
      if (item.validation && item.validation.status==="failed") {
        putIssue(key,{name:name,reason:"The latest bounded validation failed. Open guided builder to inspect the error, SPL, and schedule.",
          href:"detection_workflow?detection="+encodeURIComponent(key),action:"Repair and validate",severity:"critical",priority:3});
      }
      if (health==="degraded" || health==="failing") {
        putIssue(key,{name:name,reason:"Monitoring health is "+health+". Review result volume, runtime, analyst outcomes, and tuning evidence.",
          href:"detection_workflow?detection="+encodeURIComponent(key),action:"Review health evidence",severity:"critical",priority:3});
      } else if ((item.state==="production" || item.state==="monitoring") &&
          !(item.monitoring && item.monitoring.last_checked_at)) {
        putIssue(key,{name:name,reason:"This operational detection has no recorded monitoring baseline.",
          href:"detection_workflow?detection="+encodeURIComponent(key),action:"Record health baseline",severity:"attention",priority:2});
      }
    });
    var issueItems=Object.keys(issues).map(function (key) { return issues[key]; });
    var blocked=issueItems.length;
    var known={};
    recommendations.concat(artifacts).forEach(function (item,index) { known[itemKey(item,index)]=true; });
    var useCases=Object.keys(known).length;
    var healthyOperational=artifacts.filter(function (item) {
      return item.monitoring && item.monitoring.health==="healthy" && item.monitoring.last_checked_at;
    }).length;
    var healthState=!useCases?"awaiting":unhealthy||failed?"critical":blocked?"degraded":
      production>0 && healthyOperational===production?"healthy":"building";
    var healthLabel={awaiting:"Awaiting data",critical:"Action required",degraded:"Needs attention",healthy:"Healthy",building:"Engineering active"}[healthState];
    var healthDetail=!useCases?"Run an intelligence scan to establish a baseline":
      healthState==="critical"?(unhealthy+failed)+" failing health or validation item"+(unhealthy+failed===1?"":"s"):
      healthState==="degraded"?blocked+" item"+(blocked===1?" requires":"s require")+" telemetry, field, or monitoring evidence":
      healthState==="healthy"?healthyOperational+" monitored detection"+(healthyOperational===1?" is":"s are")+" healthy":
      active+" detection"+(active===1?" is":"s are")+" moving through engineering";
    $("#dei-home-health").text(healthLabel).attr("data-health",healthState).closest(".dei-flow-health-card").attr("data-health",healthState);
    $("#dei-home-health-detail").text(healthDetail);
    $("#dei-home-use-case-count, #dei-topology-core-count").text(useCases);
    $("#dei-home-active-count").text(active);
    $("#dei-home-blocked-count").text(blocked);
    $("#dei-home-production-count").text(production);
    renderHomeHealthActions(issueItems,healthState);
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
      qualify:ready>0,
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
      if (state==="current" && ((stage==="profile" && recommendations.length>0 && verified===0) ||
          (stage==="qualify" && recommendations.length>0 && ready===0) ||
          (stage==="design" && recommendations.length>0 && buildable===0) ||
          (stage==="validate" && failed>0 && passed===0))) { state="blocked"; }
      var count=stageCounts[stage];
      var stageLabel=stage.replace(/^./,function (letter) { return letter.toUpperCase(); });
      flow.find('[data-home-flow-stage="'+stage+'"]').attr("data-pipeline-state",state)
        .attr("role","link").attr("tabindex","0")
        .attr("aria-label",stageLabel+": "+count+" item"+(count===1?"":"s")+", "+state+". Open stage details.")
        .attr("title",stageLabel+" · "+count+" · "+state);
    });
    var progress=current===-1 ? 100 : Math.round((current/(stages.length-1))*100);
    var currentNode=current===-1 ? $() : flow.find('[data-home-flow-stage="'+stages[current]+'"]');
    var state=current===-1 ? "complete" : (currentNode.attr("data-pipeline-state")==="blocked" ? "blocked" : "active");
    flow.css("--dei-flow-progress",progress+"%").attr("data-flow-state",state)
      .attr("data-pipeline-health",healthState).toggleClass("has-flow",progress>0);
    $("#dei-topology-core-health").text(healthDetail);
    $("#dei-topology-core-action").attr("data-health-destination",healthState==="critical" ? "detection_action_center" :
      healthState==="healthy" ? "detection_health" : healthState==="awaiting" ? "command_center#dei-telemetry" : "detection_catalog")
      .attr("aria-label",healthLabel+". "+healthDetail+". Open the related pipeline workspace.")
      .attr("title",healthLabel+" | "+healthDetail);
    var stageStatus=current===-1 ? "All evidence stages complete" :
      stages[current].replace(/^./,function (letter) { return letter.toUpperCase(); })+
      (state==="blocked" ? " blocked" : " active");
    $("#dei-home-flow-status").text(healthLabel+" · "+stageStatus+
      (blocked ? " · "+blocked+" action item"+(blocked===1?"":"s") : ""));
  }

  function workflowPage() {
    var id=String(shell().attr("id") || "");
    return {
      "dei-home-page":"home",
      "dei-command-center":"environment",
      "dei-environment-insights":"environment_insights",
      "dei-mitre-page":"mitre",
      "dei-detection-builder-page":"builder",
      "dei-lifecycle-page":"lifecycle",
      "dei-detection-catalog-page":"catalog",
      "dei-guided-detection-page":"builder"
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
    var cataloged=artifacts.filter(function (item) {
      return item.catalog && item.catalog.cataloged_at;
    }).length;
    return {
      report:report,
      recommendations:recommendations,
      artifacts:artifacts,
      discovered:Number(report.observed_source_count || 0)>0,
      reviewed:recommendations.length>0 && mapped>0,
      built:generated>0,
      validated:validated>0,
      cataloged:cataloged>0,
      operational:operational>0
    };
  }

  function workflowMarkup() {
    var steps=[
      {key:"discover",label:"Discover",detail:"Analyze telemetry",href:"command_center#dei-telemetry"},
      {key:"review",label:"Review",detail:"MITRE and readiness",href:"mitre_coverage"},
      {key:"build",label:"Build",detail:"Generate SPL",href:"detection_workflow"},
      {key:"validate",label:"Validate",detail:"Test evidence",href:"detection_workflow#builder-validation-title"},
      {key:"operate",label:"Operate",detail:"Approve, enable, monitor",href:"detection_catalog"}
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
      build:{label:"Build a detection",href:"detection_workflow"},
      validate:{label:"Validate generated SPL",href:"detection_workflow#builder-validation-title"},
      operate:{label:"Continue guided workflow",href:"detection_workflow"}
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

  var ONBOARDING_SESSION_KEY = "dei.onboardingSeen.session";
  var ONBOARDING_STEP_KEY = "dei.onboardingStep";
  var ONBOARDING_STEPS = [
    {page:"home",target:"#dei-home-pipeline",title:"Read the live detection pipeline",detail:"Use the pipeline as an operational summary of current telemetry and saved lifecycle evidence.",objective:"Identify the current stage, blockers, and the next owned action before opening a detailed workspace.",actions:["Confirm the assessment timestamp and pipeline-health state are current.","Review the action-item count and select the current or blocked stage.","Use Run new scan only for fresh telemetry discovery; use Refresh pipeline for saved lifecycle evidence."],evidence:["A current assessment or an explicit no-assessment state is visible.","The selected stage count and health label have a clear operational owner."],caution:"Pipeline counts are decision support, not proof that every detection is effective or production-ready."},
    {page:"environment",target:"#dei-telemetry",title:"Run telemetry discovery",detail:"Establish whether the available data can support reliable detection engineering.",objective:"Create a current, permission-aware inventory of indexes, sourcetypes, extracted fields, and readiness gaps.",actions:["Confirm whether Enterprise Security is enabled before starting the scan.","Run discovery during an approved window and review unexpected indexes or sourcetypes.","Investigate field-profile failures and distinguish parser, alias, semantic, and telemetry gaps."],evidence:["The assessment records a completion time, initiating user, active indexes, and active sourcetypes.","Required fields are verified or each gap has a documented remediation path."],caution:"Discovery can create search load across accessible indexes. Respect RBAC, workload controls, and production search windows."},
    {page:"mitre",target:".dei-mitre-advisor",title:"Review MITRE coverage",detail:"Prioritize detection opportunities that are supported by observed telemetry.",objective:"Select a defensible ATT&CK use case based on organizational risk, telemetry readiness, and coverage need.",actions:["Filter by the relevant sourcetype and inspect the mapped tactic, technique, and platform.","Prefer production-ready recommendations; review every field-unverified or field-gap condition.","Record why the use case matters and who will own engineering and review."],evidence:["The selected use case has a verified ATT&CK mapping and identified data source.","Readiness, field evidence, priority, and ownership are understood before building."],caution:"ATT&CK mapping shows behavioral coverage intent; it does not measure detection quality, alert fidelity, or adversary prevention."},
    {page:"builder",target:"#workflow-selector-title",title:"Build and validate SPL",detail:"Convert an approved use case into reviewable, testable detection logic.",objective:"Produce bounded SPL with complete metadata, explainable logic, and evidence suitable for peer review.",actions:["Inspect and simplify generated SPL before testing it against production-scale data.","Confirm ATT&CK ID, description, schedule, time range, thresholds, and expected entities.","Run bounded historical validation and document false positives, limitations, and tuning decisions."],evidence:["Validation status and representative results are saved with the draft.","The detection has an owner, peer reviewer, deployment plan, and rollback approach."],caution:"Never enable generated SPL directly in production without human review, performance validation, and change-control approval."},
    {page:"lifecycle",target:"#lifecycle-work-queue",title:"Operate the lifecycle",detail:"Move approved detection evidence through deployment, monitoring, tuning, and retirement.",objective:"Maintain an auditable production record from peer approval through catalog enablement and ongoing health review.",actions:["Complete the required evidence gate before advancing the lifecycle state.","Move approved detections into the catalog, enable them through the authorized deployment process, and remove them from the active queue.","Assign an owner, health baseline, review cadence, tuning triggers, and retirement criteria."],evidence:["Approval, deployment reference, catalog status, and monitoring evidence are recorded.","The detection has measurable health, response ownership, and a scheduled review date."],caution:"State changes must reflect real operational actions. Do not mark a detection production or healthy without deployment and monitoring evidence."}
  ];
  var onboardingStep=0;
  var onboardingReturnFocus=null;

  function onboardingSessionKey() {
    var seed="active-login";
    try {
      seed=String(Splunk.util.getConfigValue("USERNAME")||"unknown")+"|"+
        String(Splunk.util.getConfigValue("FORM_KEY")||"active-login");
    } catch (error) { /* Use the stable fallback when Splunk config is unavailable. */ }
    var hash=2166136261;
    for (var index=0;index<seed.length;index+=1) { hash^=seed.charCodeAt(index); hash=Math.imul(hash,16777619); }
    return ONBOARDING_SESSION_KEY+"."+(hash>>>0).toString(36);
  }

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
      '<section class="dei-onboarding-dialog" role="dialog" aria-modal="false" aria-labelledby="dei-onboarding-title" aria-describedby="dei-onboarding-description">',
      '<button id="dei-onboarding-close" class="dei-onboarding-close" type="button" aria-label="Close welcome guide">&times;</button>',
      '<div class="dei-onboarding-heading"><p id="dei-onboarding-step-label" class="dei-kicker"></p>',
      '<h2 id="dei-onboarding-title"></h2><p id="dei-onboarding-description"></p></div>',
      '<div class="dei-onboarding-production">',
      '<section><h3>Production objective</h3><p id="dei-onboarding-objective"></p></section>',
      '<section><h3>What to do</h3><ul id="dei-onboarding-actions"></ul></section>',
      '<section><h3>Evidence before continuing</h3><ul id="dei-onboarding-evidence"></ul></section>',
      '<aside><strong>Operational caution</strong><p id="dei-onboarding-caution"></p></aside>',
      '</div>',
      '<div class="dei-onboarding-progress" role="progressbar" aria-valuemin="1" aria-valuemax="5"><span id="dei-onboarding-progress-bar"></span></div>',
      '<div class="dei-onboarding-foot">',
      '<span class="dei-onboarding-session-note">Shown once per login session. Press F6 to switch between this guide and the highlighted section.</span>',
      '<div><button id="dei-onboarding-not-now" type="button">Skip tour</button><button id="dei-onboarding-back" type="button">Back</button>',
      '<button id="dei-onboarding-next" type="button">Next →</button></div>',
      '</div></section></div>'
    ].join("");
  }

  function showOnboarding() {
    if (window.DEIReactGuideConfigured || window.DEINextGuide) { return; }
    if (window.DEINextGuide) { return; }
    return; // React is the supported guide surface; do not fall back to the retired long-form modal.
    var active=safeSessionGet(ONBOARDING_STEP_KEY,"");
    if (safeSessionGet(onboardingSessionKey())==="true" || $("#dei-onboarding-overlay").length) { return; }
    if (workflowPage()!=="home" && active==="") { return; }
    onboardingStep=Math.max(0,Math.min(ONBOARDING_STEPS.length-1,Number(active||0)));
    onboardingReturnFocus=document.activeElement;
    $("body").append(onboardingMarkup()).addClass("dei-onboarding-open");
    renderOnboardingStep();
    window.setTimeout(function () { $("#dei-onboarding-close").focus(); }, 0);
  }

  function onboardingPage(step) { return {home:"dei_home",environment:"command_center#dei-telemetry",mitre:"mitre_coverage",builder:"detection_workflow#guided-builder-workspace",lifecycle:"detection_catalog#lifecycle-work-queue"}[step.page]; }

  function restartOnboarding() {
    if (window.DEIReactGuideConfigured || window.DEINextGuide) { return; }
    if (window.DEINextGuide) { window.DEINextGuide.start(); return; }
    return;
    safeSessionSet(onboardingSessionKey(), "false");
    safeSessionSet(ONBOARDING_STEP_KEY, "0");
    onboardingStep=0;
    $("#dei-onboarding-overlay").remove();
    $(".dei-onboarding-target").removeClass("dei-onboarding-target").removeAttr("aria-describedby");
    showOnboarding();
  }

  function renderOnboardingStep() {
    var step=ONBOARDING_STEPS[onboardingStep],target=$(step.target).first();
    $(".dei-onboarding-target").removeClass("dei-onboarding-target").removeAttr("aria-describedby");
    if (workflowPage()!==step.page) { safeSessionSet(ONBOARDING_STEP_KEY,String(onboardingStep)); window.location.href=onboardingPage(step); return; }
    if (target.length) {
      target.addClass("dei-onboarding-target").attr("aria-describedby","dei-onboarding-description");
      target[0].scrollIntoView({behavior:"smooth",block:"center"});
      window.setTimeout(function () { positionOnboardingDialog(target); }, 380);
    } else { positionOnboardingDialog(target); }
    $("#dei-onboarding-step-label").text("Guided walkthrough · "+(onboardingStep+1)+" of "+ONBOARDING_STEPS.length);
    $("#dei-onboarding-title").text(step.title); $("#dei-onboarding-description").text(step.detail);
    $("#dei-onboarding-objective").text(step.objective);
    $("#dei-onboarding-actions").empty(); (step.actions||[]).forEach(function (item) { $("#dei-onboarding-actions").append($("<li>").text(item)); });
    $("#dei-onboarding-evidence").empty(); (step.evidence||[]).forEach(function (item) { $("#dei-onboarding-evidence").append($("<li>").text(item)); });
    $("#dei-onboarding-caution").text(step.caution);
    $("#dei-onboarding-back").prop("disabled",onboardingStep===0); $("#dei-onboarding-next").text(onboardingStep===ONBOARDING_STEPS.length-1?"Finish tour":"Next →");
    $("#dei-onboarding-progress-bar").css("width",((onboardingStep+1)/ONBOARDING_STEPS.length*100)+"%"); $(".dei-onboarding-progress").attr("aria-valuenow",onboardingStep+1);
  }

  function positionOnboardingDialog(target) {
    var dialog=$(".dei-onboarding-dialog");
    if (!dialog.length) { return; }
    var placement="right";
    if (target && target.length && window.innerWidth>900) {
      var bounds=target[0].getBoundingClientRect();
      placement=(bounds.left+bounds.width/2)<window.innerWidth/2 ? "right" : "left";
    } else if (target && target.length) {
      placement=target[0].getBoundingClientRect().top>window.innerHeight/2 ? "top" : "bottom";
    }
    dialog.attr("data-placement",placement);
  }

  function ensureScanContext() {
    if (shell().is("#dei-home-page")) { return; }
    if ($("#dei-active-scan-context").length) { return; }
    shell().find(".dei-product-bar").first().after(
      '<section id="dei-active-scan-context" class="dei-active-scan-context" aria-live="polite"></section>'
    );
  }

  function renderScanContext() {
    var report=safeJson(safeSessionGet("dei.latestRecommendationReport", ""), {});
    var timestamp=Number(safeSessionGet("dei.latestRecommendationTime", "0") || 0);
    var sources=Number(report.observed_source_count || 0);
    if (shell().is("#dei-home-page")) {
      $(".dei-home-flow-actions .dei-open-environment-discovery").text("Open Environment Discovery");
      return;
    }
    ensureScanContext();
    if (!timestamp || !sources) {
      $("#dei-active-scan-context").attr("data-state","empty").html(
        '<span><b>No active environment scan</b> — downstream intelligence remains empty until you run discovery.</span>' +
        '<a class="dei-scan-discovery-link" href="command_center#dei-telemetry">Open Environment Discovery</a>'
      );
      return;
    }
    $("#dei-active-scan-context").attr("data-state","active").html(
      '<span><b>Active environment scan</b> · ' + sources + ' source types · completed ' +
      new Date(timestamp).toLocaleString() + '</span><a class="dei-scan-discovery-link" href="command_center#dei-telemetry">Run new scan in Discovery</a>'
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
    safeSessionSet(onboardingSessionKey(), "true");
    safeSessionSet(ONBOARDING_STEP_KEY, "");
    $("#dei-onboarding-overlay").remove();
    $(".dei-onboarding-target").removeClass("dei-onboarding-target").removeAttr("aria-describedby");
    $("body").removeClass("dei-onboarding-open");
    if (onboardingReturnFocus && document.contains(onboardingReturnFocus)) { window.setTimeout(function () { onboardingReturnFocus.focus(); },0); }
  }

  function initialize() {
    var root = shell();
    var bar = root.find(".dei-product-bar").first();
    if (!root.length) { return; }
    if (bar.length && !bar.find(".dei-workspace-controls").length) {
      var nav=bar.find(".dei-workspace-nav").first();
      var status = bar.find(".dei-status").first();
      var simplifiedBuilder = root.is("#dei-guided-detection-page");
      if (!simplifiedBuilder) {
        if (status.length) { status.before(toolbar()); } else { bar.append(toolbar()); }
      }
    }
    applyMode(safeStorageGet(MODE_KEY, "analyst"));
    applyDensity(safeStorageGet(DENSITY_KEY, "comfortable"));
    renderHomePipeline();
    renderGuidedWorkflow();
    renderEnvironmentSplitState();
    renderScanContext();
    showOnboarding();
    focusDeepLinkedWorkspace();
  }

  function homeStageDetection(stage) {
    var artifacts=Array.isArray(homeLifecycleRecords) ? homeLifecycleRecords : safeJson(safeStorageGet("dei.detectionDraftArtifacts", ""), []);
    var recommendations=(safeJson(safeSessionGet("dei.latestRecommendationReport", ""), {}).recommendations)||[];
    var candidate;
    if (stage==="validate") {
      candidate=artifacts.filter(function (item) { return item.spl && (!item.validation || item.validation.status!=="passed"); })[0];
    } else if (stage==="generate") {
      candidate=recommendations.filter(function (item) {
        return ["production_ready","field_unverified","field_gap"].indexOf(item.readiness)!==-1;
      })[0];
    }
    return candidate ? String(candidate.detection_id || candidate._key || candidate.id || "").replace(/^dei-/,"") : "";
  }

  function homeStageDestination(stage) {
    var destination={discover:"command_center#dei-telemetry",profile:"detection_catalog?pipeline=profile",
      qualify:"detection_catalog?pipeline=qualify",recommend:"mitre_coverage#mitre-detection-list",
      design:"detection_catalog?pipeline=design",generate:"detection_workflow#guided-builder-workspace",
      validate:"detection_workflow#builder-validation-title"}[stage] || "detection_lifecycle";
    var detection=homeStageDetection(stage);
    if (detection) {
      destination="detection_workflow?detection="+encodeURIComponent(detection)+
        (stage==="validate" ? "#builder-validation-title" : "#guided-builder-workspace");
    }
    return destination;
  }

  function focusDeepLinkedWorkspace() {
    var selector=String(window.location.hash||"");
    if(!selector||selector==="#"){return;}
    var target;
    try{target=$(selector).first();}catch(error){return;}
    if(!target.length){return;}
    window.setTimeout(function(){
      target.attr("tabindex","-1");
      target[0].scrollIntoView({behavior:"smooth",block:"center"});
      target.focus().addClass("dei-action-target");
      window.setTimeout(function(){target.removeClass("dei-action-target");},2200);
      announceAction("Opened the specific pipeline workspace for "+target.closest("section,article").find("h1,h2,h3,label").first().text()+".","success");
    },450);
  }

  $(document).on("click keydown", "[data-home-flow-stage]", function (event) {
    if (event.type==="keydown" && event.key!=="Enter" && event.key!==" ") { return; }
    if (event.type==="keydown") { event.preventDefault(); }
    window.location.href=homeStageDestination(String($(this).data("home-flow-stage") || ""));
  });

  $(document).on("click", "#dei-home-refresh", function () {
    if (homeLifecycleLoading) { return; }
    homeLifecycleRecords=null;
    refreshHomeLifecycleRecords(true);
  });

  $(document).on("click", ".dei-view-mode button", function () {
    openExperienceActions(String($(this).data("mode") || "analyst"));
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
    var activate=String($(this).attr("data-dei-activate") || "")==="true";
    window.setTimeout(function () {
      target.attr("tabindex","-1").focus();
      target.addClass("dei-action-target");
      if (activate) { target.trigger("click"); }
      window.setTimeout(function () { target.removeClass("dei-action-target"); },1800);
    },350);
    announceAction("Moved to "+$(this).find("strong").text()+". Complete the highlighted control.","success");
  });

  $(document).on("click", "#dei-onboarding-close, #dei-onboarding-not-now", closeOnboarding);
  $(document).on("click", function (event) {
    if ($("#dei-onboarding-overlay").length && !$(event.target).closest(".dei-onboarding-dialog,.dei-onboarding-target").length) { closeOnboarding(); }
  });
  $(window).on("resize.deiOnboarding", function () { positionOnboardingDialog($(ONBOARDING_STEPS[onboardingStep].target).first()); });
  $(document).on("click", "#dei-home-tour", restartOnboarding);
  $(document).on("click", "#dei-topology-core-action", function () {
    window.location.href=String($(this).attr("data-health-destination") || "detection_lifecycle");
  });
  $(document).on("click", "#dei-onboarding-back", function () { if (onboardingStep>0) { onboardingStep-=1; renderOnboardingStep(); } });
  $(document).on("click", "#dei-onboarding-next", function () { if (onboardingStep<ONBOARDING_STEPS.length-1) { onboardingStep+=1; renderOnboardingStep(); } else { closeOnboarding(); } });
  $(document).on("dei:scan-progress", function (_event,status) {
    if (status.stage==="hydrated") { renderHomePipeline(); renderGuidedWorkflow(); renderEnvironmentSplitState(); renderScanContext(); return; }
    $("#dei-home-flow-status").text(status.message);
    announceAction(status.message,status.stage==="failed"?"error":status.stage==="complete"?"success":"info");
  });
  $(document).on("keydown", function (event) {
    var overlay=$("#dei-onboarding-overlay");
    if (!overlay.length) { return; }
    if (event.key==="Escape") { closeOnboarding(); return; }
    if (event.key==="F6") {
      var dialog=$(".dei-onboarding-dialog"),target=$(ONBOARDING_STEPS[onboardingStep].target).first();
      if ($(event.target).closest(dialog).length && target.length) { target.attr("tabindex","-1").focus(); }
      else { $("#dei-onboarding-close").focus(); }
      event.preventDefault(); return;
    }
    // This coachmark is non-modal so the highlighted controls remain interactive.
  });

  $(document).on("dei:environment-refreshed dei:environment-cleared dei:detection-artifacts-changed", function () {
    homeLifecycleRecords=null;
    renderHomePipeline();
    renderGuidedWorkflow();
    renderEnvironmentSplitState();
    renderScanContext();
  });
  $(document).on("dei:environment-refresh-started", function () {
    $("#dei-home-detection-flow").attr("data-flow-state", "active");
    $("#dei-home-flow-status").text("Environment analysis is moving through telemetry discovery");
  });
  $(window).on("focus", function () {
    if ($("#dei-home-detection-flow").length) { homeLifecycleRecords=null; renderHomePipeline(); }
  });

  $(window).on("storage", function (event) {
    var key=event.originalEvent && event.originalEvent.key;
    if (!key || key==="dei.latestRecommendationReport" || key==="dei.detectionDraftArtifacts") { renderHomePipeline(); renderGuidedWorkflow(); renderEnvironmentSplitState(); renderScanContext(); }
  });

  initialize();
});

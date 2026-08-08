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

  function coverageActions() {
    var actions={
      home:[
        {label:"Review environment intelligence",href:"environment_insights",detail:"Inspect telemetry DNA, readiness, and coverage evidence."},
        {label:"Investigate MITRE coverage",href:"mitre_coverage",detail:"Filter recommendations and inspect uncovered ATT&CK behavior."},
        {label:"Review blocked detections",target:"#dei-home-health-action",activate:true,detail:"Open the exact telemetry, validation, and health action items."}
      ],
      environment:[
        {label:"Run intelligence scan",target:"#dei-analyze",detail:"Generate the evidence required for a real coverage assessment."},
        {label:"Open coverage results",href:"environment_insights",detail:"Review detection potential, telemetry domains, and tactic coverage."},
        {label:"Investigate MITRE coverage",href:"mitre_coverage",detail:"Inspect technique mappings and protection detail."}
      ],
      environment_insights:[
        {label:"Inspect ATT&CK coverage",href:"mitre_coverage",detail:"Move from summary coverage into tactic and technique evidence."},
        {label:"Build a coverage-closing detection",href:"detection_builder",detail:"Generate SPL for a qualified recommendation."},
        {label:"Run a new assessment",href:"command_center#dei-telemetry",detail:"Replace the current coverage snapshot with fresh telemetry."}
      ],
      mitre:[
        {label:"Filter by sourcetype",target:"#mitre-sourcetype-filter",detail:"Find coverage recommendations supported by one telemetry source."},
        {label:"Inspect the ATT&CK matrix",target:"#mitre-matrix",detail:"Review tactic columns and mapped technique state."},
        {label:"Build a mapped detection",href:"detection_builder",detail:"Generate SPL with embedded ATT&CK context."}
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

  function refreshHomeLifecycleRecords() {
    var Store=window.DEILifecycleStore;
    if (!$("#dei-home-detection-flow").length || homeLifecycleLoading) { return; }
    if (!Store || !Store.load) {
      homeLifecycleRecords=safeJson(safeStorageGet("dei.detectionDraftArtifacts", ""), []);
      renderHomePipeline(true);
      return;
    }
    homeLifecycleLoading=true;
    Store.load().done(function (records) {
      homeLifecycleRecords=Array.isArray(records) ? records : [];
      renderHomePipeline(true);
    }).fail(function () {
      homeLifecycleRecords=safeJson(safeStorageGet("dei.detectionDraftArtifacts", ""), []);
      renderHomePipeline(true);
    }).always(function () { homeLifecycleLoading=false; });
  }

  function renderHomeHealthActions(issues, healthState) {
    var list=$("#dei-home-health-actions-list");
    if (!list.length) { return; }
    if (issues.length) {
      list.html(issues.map(function (issue) {
        return '<article class="dei-home-health-issue" data-severity="'+escapeMarkup(issue.severity)+'">' +
          '<div><strong>'+escapeMarkup(issue.name)+'</strong><p>'+escapeMarkup(issue.reason)+'</p></div>' +
          '<a href="'+escapeMarkup(issue.href)+'">'+escapeMarkup(issue.action)+' →</a></article>';
      }).join(""));
      $("#dei-home-health-action").text("Review "+issues.length+" action item"+(issues.length===1?"":"s")+" →");
      return;
    }
    var empty={
      awaiting:{title:"No active assessment",detail:"Run an intelligence scan to populate the detection pipeline.",href:"command_center#dei-telemetry",action:"Run intelligence scan"},
      building:{title:"Engineering is active",detail:"Review drafts, tests, and approvals in the lifecycle work queue.",href:"detection_lifecycle",action:"Open lifecycle work queue"},
      healthy:{title:"Operational detections are healthy",detail:"Review monitoring evidence and keep health measurements current.",href:"detection_lifecycle",action:"Review monitoring evidence"}
    }[healthState] || {title:"Review pipeline evidence",detail:"Inspect current lifecycle records and their next required actions.",href:"detection_lifecycle",action:"Open lifecycle workspace"};
    list.html('<article class="dei-home-health-issue" data-severity="info"><div><strong>'+empty.title+
      '</strong><p>'+empty.detail+'</p></div><a href="'+empty.href+'">'+empty.action+' →</a></article>');
    $("#dei-home-health-action").text(empty.action+" →");
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
        href:canBuild ? "detection_builder?detection="+encodeURIComponent(key) : "command_center#dei-telemetry",
        action:canBuild ? "Build engineering draft" : "Resolve telemetry evidence",severity:"attention",priority:1});
    });
    artifacts.forEach(function (item,index) {
      var key=itemKey(item,index); var name=item.name || key;
      var health=item.monitoring && item.monitoring.health;
      if (item.validation && item.validation.status==="failed") {
        putIssue(key,{name:name,reason:"The latest bounded validation failed. Open Builder to inspect the error, SPL, and schedule.",
          href:"detection_builder?detection="+encodeURIComponent(key),action:"Repair and validate",severity:"critical",priority:3});
      }
      if (health==="degraded" || health==="failing") {
        putIssue(key,{name:name,reason:"Monitoring health is "+health+". Review result volume, runtime, analyst outcomes, and tuning evidence.",
          href:"detection_lifecycle?detection="+encodeURIComponent(key),action:"Review health evidence",severity:"critical",priority:3});
      } else if ((item.state==="production" || item.state==="monitoring") &&
          !(item.monitoring && item.monitoring.last_checked_at)) {
        putIssue(key,{name:name,reason:"This operational detection has no recorded monitoring baseline.",
          href:"detection_lifecycle?detection="+encodeURIComponent(key),action:"Record health baseline",severity:"attention",priority:2});
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
      flow.find('[data-home-flow-stage="'+stage+'"]').attr("data-pipeline-state",state)
        .attr("role","link").attr("tabindex","0");
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
    var nav=bar.find(".dei-workspace-nav").first();
    if (nav.length && !nav.find('a[href="detection_health"]').length) { nav.append('<a href="detection_health">Health</a>'); }
    var status = bar.find(".dei-status").first();
    if (status.length) { status.before(toolbar()); } else { bar.append(toolbar()); }
    applyMode(safeStorageGet(MODE_KEY, "analyst"));
    applyDensity(safeStorageGet(DENSITY_KEY, "comfortable"));
    renderHomePipeline();
    renderGuidedWorkflow();
    renderEnvironmentSplitState();
    renderScanContext();
    showOnboarding();
    focusDeepLinkedWorkspace();
  }

  function homeStageDestination(stage) {
    return {discover:"command_center#dei-telemetry",profile:"environment_insights#dei-coverage-section",
      qualify:"environment_insights#recommendations",recommend:"mitre_coverage#mitre-detection-list",
      design:"detection_builder#builder-detection-select",generate:"detection_builder#detection-generator",
      validate:"detection_builder#builder-validation-title"}[stage] || "detection_lifecycle";
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

  $(document).on("click", "#dei-home-health-action", function () {
    var panel=$("#dei-home-health-actions"); var open=panel.prop("hidden");
    panel.prop("hidden",!open); $(this).attr("aria-expanded",open?"true":"false");
    if (open) { $("#dei-home-health-actions-title").attr("tabindex","-1").focus(); }
  });
  $(document).on("click", "#dei-home-health-actions-close", function () {
    $("#dei-home-health-actions").prop("hidden",true);
    $("#dei-home-health-action").attr("aria-expanded","false").focus();
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

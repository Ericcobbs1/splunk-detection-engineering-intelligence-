require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var REPORT_KEY = "dei.latestRecommendationReport";
  var REPORT_TIME_KEY = "dei.latestRecommendationTime";
  var report = null;
  var ARTIFACT_KEY = "dei.detectionDraftArtifacts";

  function artifacts() {
    var value = safeJson(window.localStorage.getItem(ARTIFACT_KEY));
    return Array.isArray(value) ? value : [];
  }

  function safeJson(value) {
    try { return JSON.parse(value || "null"); } catch (error) { return null; }
  }

  function esc(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function recommendations() {
    return report && report.recommendations ? report.recommendations : [];
  }

  function sourceMappings() {
    return report && report.source_mappings ? report.source_mappings : [];
  }

  function observedSourcetypes(item) {
    var matched = (item.observed_sources || []).map(function (source) {
      return String(source || "").toLowerCase();
    });
    return sourceMappings().filter(function (mapping) {
      var canonical = [mapping.canonical_source].concat(
        mapping.additional_canonical_sources || []
      ).map(function (source) { return String(source || "").toLowerCase(); });
      return canonical.some(function (source) { return matched.indexOf(source) !== -1; });
    }).map(function (mapping) { return mapping.observed_source; });
  }

  function engineeringStage(item) {
    if (item.readiness === "production_ready") { return "design"; }
    if (item.readiness === "partial" ||
        item.readiness === "field_gap" ||
        item.readiness === "field_unverified") { return "qualify"; }
    return "discover";
  }

  function nextAction(item) {
    if (item.readiness === "production_ready") {
      return "Create Open Detection Definition and generate reviewable SPL";
    }
    if (item.readiness === "field_gap") {
      return "Add extraction, alias, or calculated field for confirmed gaps";
    }
    if (item.readiness === "field_unverified") {
      return "Collect a representative field sample and verify prerequisites";
    }
    if (item.readiness === "partial") {
      return "Onboard the missing required telemetry";
    }
    if (item.readiness === "requires_enterprise_security") {
      return "Enable ES enhancement or design a platform-first implementation";
    }
    return "Onboard and qualify required telemetry";
  }

  function readinessLabel(value) {
    if (value === "production_ready") { return "Telemetry ready"; }
    return String(value || "unknown").replace(/_/g, " ");
  }

  function loadReport() {
    report = safeJson(window.localStorage.getItem(REPORT_KEY));
    var timestamp = Number(window.localStorage.getItem(REPORT_TIME_KEY) || 0);
    if (report && report.recommendations) {
      $("#lifecycle-data-status").text("Analysis: loaded").addClass("healthy").removeClass("unhealthy");
      $("#lifecycle-analysis-age").text(timestamp ? "Analyzed " + new Date(timestamp).toLocaleString() : "Analysis loaded");
    } else {
      $("#lifecycle-data-status").text("Analysis: required").addClass("unhealthy").removeClass("healthy");
      $("#lifecycle-analysis-age").text("No analysis loaded");
    }
  }

  function renderMetrics() {
    var items = recommendations();
    var sources = Number(report && report.observed_source_count || 0);
    var verified = items.filter(function (item) { return item.field_validation === "passed"; }).length;
    var mapped = items.filter(function (item) { return (item.mitre_techniques || []).length > 0; }).length;
    var ready = items.filter(function (item) { return item.readiness === "production_ready"; }).length;
    var profiled = items.filter(function (item) {
      return item.field_validation && item.field_validation !== "not_evaluated";
    }).length;
    var generated = artifacts().length;
    var maturityStages = report ? 4 : 0;
    if (ready) { maturityStages += 1; }
    if (generated) { maturityStages += 1; }
    var maturity = Math.round((maturityStages / 7) * 100);

    $("#life-sources").text(sources);
    $("#life-opportunities").text(items.length);
    $("#life-mitre-mapped").text(mapped);
    $("#life-field-verified").text(verified);
    $("#life-telemetry-ready").text(ready);
    $("#life-spl-generated").text(generated);
    $("#lifecycle-maturity-percent").text(maturity + "%");

    $("#stage-discover").text(sources + " sources");
    $("#stage-profile").text(profiled + " profiled");
    $("#stage-qualify").text(verified + " verified");
    $("#stage-recommend").text(items.length + " use cases");
    $("#stage-design").text(ready + " ready");
    $("#stage-generate").text(generated + " SPL");
    $("#state-draft").text(generated);
    $("#stage-validate").text("0 passed");
  }

  function renderQueue() {
    var query = String($("#lifecycle-search").val() || "").toLowerCase();
    var readiness = $("#lifecycle-readiness").val() || "all";
    var stage = $("#lifecycle-stage").val() || "all";
    var items = recommendations().filter(function (item) {
      var sources = observedSourcetypes(item);
      var haystack = [
        item.name, item.capability, item.pack_id,
        sources.join(" "), (item.mitre_techniques || []).join(" ")
      ].join(" ").toLowerCase();
      return (!query || haystack.indexOf(query) !== -1) &&
        (readiness === "all" || item.readiness === readiness) &&
        (stage === "all" || engineeringStage(item) === stage);
    });

    $("#lifecycle-queue-count").text(items.length + " items");
    $("#lifecycle-work-queue").html(items.length ? items.map(function (item) {
      var sources = observedSourcetypes(item);
      var techniques = item.mitre_techniques || [];
      var stageName = engineeringStage(item);
      return "<tr>" +
        "<td><strong>" + esc(item.name) + "</strong><small>" + esc(item.capability || item.pack_id) + "</small></td>" +
        "<td>" + esc(sources.join(" · ") || "No observed match") + "</td>" +
        '<td><span class="dei-lifecycle-readiness ' + esc(item.readiness) + '">' + esc(readinessLabel(item.readiness)) + "</span></td>" +
        "<td>" + esc(techniques.join(" · ") || "Not mapped") + "</td>" +
        '<td><span class="dei-lifecycle-stage ' + stageName + '">' + esc(stageName) + "</span></td>" +
        "<td>" + esc(nextAction(item)) + "</td>" +
        '<td>' + (item.readiness === "production_ready" ? '<button type="button" class="dei-generate-detection" data-detection="' + esc(item.detection_id) + '">Generate</button>' : '<span class="dei-generation-blocked">Resolve gaps</span>') + "</td></tr>";
    }).join("") : '<tr><td colspan="7">No detection opportunities match the current lifecycle filters.</td></tr>');
  }

  function render() {
    loadReport();
    renderMetrics();
    renderQueue();
  }

  $("#lifecycle-search, #lifecycle-readiness, #lifecycle-stage").on("input change", renderQueue);
  $(document).on("dei:detection-artifacts-changed", function () { renderMetrics(); });

  $(window).on("storage", function (event) {
    if (!event.originalEvent || [REPORT_KEY, REPORT_TIME_KEY, ARTIFACT_KEY].indexOf(event.originalEvent.key) !== -1) {
      render();
    }
  });

  render();
});

require([
  "jquery",
  "splunkjs/mvc/searchmanager",
  "splunkjs/mvc/simplexml/ready!"
], function ($, SearchManager) {
  "use strict";

  var appId = "splunk_detection_engineering_intelligence";
  var pendingAnalysis = false;
  var discoveryTimer = null;
  var discoveryHandled = false;

  function endpoint() {
    var parts = Array.prototype.slice.call(arguments);
    return Splunk.util.make_url.apply(
      Splunk.util,
      ["splunkd", "__raw", "servicesNS", "-", appId].concat(parts)
    );
  }

  var endpoints = {
    health: endpoint("dei", "v1", "health"),
    recommendations: endpoint("dei", "v1", "recommendations")
  };

  var discoverySearch = new SearchManager({
    id: "dei_environment_discovery",
    search: [
      "| tstats count WHERE index=* earliest=-7d latest=now BY index sourcetype",
      '| where NOT like(index, "_%") AND isnotnull(sourcetype)',
      "| sort - count"
    ].join(" "),
    preview: false,
    cache: false,
    autostart: false
  });

  var discoveryResults = discoverySearch.data("results", {
    count: 1000,
    output_mode: "json"
  });

  function parsePayload(response) {
    if (response && typeof response.payload === "string") {
      return JSON.parse(response.payload);
    }
    return response || {};
  }

  function postJson(url, payload) {
    return $.ajax({
      url: url,
      method: "POST",
      contentType: "application/json",
      dataType: "json",
      headers: {
        "X-Splunk-Form-Key": Splunk.util.getConfigValue("FORM_KEY")
      },
      data: JSON.stringify(payload)
    }).then(parsePayload);
  }

  function setStatus(message, healthy) {
    var status = $("#dei-api-status");
    status.text(message);
    status.css("color", healthy ? "#45e6c1" : "#ff6b7a");
  }

  function uniqueValues(values) {
    var seen = {};
    return values.filter(function (value) {
      var normalized = String(value || "").trim();
      var key = normalized.toLowerCase();
      if (!normalized || seen[key]) {
        return false;
      }
      seen[key] = true;
      return true;
    });
  }

  function resultRows(data) {
    if (data && Array.isArray(data.results)) {
      return data.results;
    }
    if (data && Array.isArray(data.fields) && Array.isArray(data.rows)) {
      return data.rows.map(function (row) {
        var item = {};
        data.fields.forEach(function (field, index) {
          item[field] = row[index];
        });
        return item;
      });
    }
    return [];
  }

  function readinessLabel(value) {
    return value.replace(/_/g, " ");
  }

  function renderDomains(recommendations) {
    var counts = {};
    recommendations.forEach(function (item) {
      counts[item.pack_id] = (counts[item.pack_id] || 0) + 1;
    });
    var maximum = Math.max.apply(null, Object.keys(counts).map(function (key) {
      return counts[key];
    }).concat([1]));
    var html = Object.keys(counts).sort().map(function (packId) {
      var percent = Math.round((counts[packId] / maximum) * 100);
      return [
        '<div class="dei-domain">',
        '<div class="dei-domain-row"><span>', packId, "</span><strong>",
        counts[packId], "</strong></div>",
        '<div class="dei-bar"><span style="width:', percent, '%"></span></div>',
        "</div>"
      ].join("");
    }).join("");
    $("#coverage-domains").html(
      html || '<p class="dei-empty">No supported domains found.</p>'
    );
  }

  function renderRecommendations(report) {
    var recommendations = report.recommendations || [];
    var html = recommendations.slice(0, 8).map(function (item) {
      var missing = item.missing_sources && item.missing_sources.length
        ? "Missing: " + item.missing_sources.join(", ")
        : "Telemetry requirements satisfied";
      return [
        '<article class="dei-recommendation">',
        '<div class="dei-rec-top"><div>',
        '<h3 class="dei-rec-title">', item.name, "</h3>",
        '<p class="dei-rec-meta">', item.capability, " · ", item.severity, " · ",
        item.pack_id, "</p></div>",
        '<span class="dei-rec-score">', item.score, "</span></div>",
        '<span class="dei-readiness ', item.readiness, '">',
        readinessLabel(item.readiness), "</span>",
        '<p class="dei-rec-why">', item.why, "</p>",
        '<p class="dei-rec-meta">', missing, "</p>",
        "</article>"
      ].join("");
    }).join("");
    $("#recommendation-count").text(recommendations.length + " results");
    $("#recommendations").html(
      html || '<p class="dei-empty">No recommendations matched the current telemetry.</p>'
    );
    renderDomains(recommendations);
  }

  function renderReport(report) {
    var ready = report.production_ready_count || 0;
    var partial = report.partial_count || 0;
    var unsupported = report.unsupported_count || 0;
    var total = ready + partial + unsupported;
    var potential = total ? Math.round(((ready + partial * 0.5) / total) * 100) : 0;
    $("#metric-sources").text(report.observed_source_count || 0);
    $("#metric-ready").text(ready);
    $("#metric-partial").text(partial);
    $("#metric-potential").text(potential + "%");
    $("#coverage-value").text(potential + "%");
    $("#coverage-ring").css("--dei-coverage", potential + "%");
    $("#coverage-label").text(
      potential >= 75 ? "Strong" : potential >= 40 ? "Developing" : "Limited"
    );
    renderRecommendations(report);
  }

  function errorDetail(xhr) {
    var response = xhr.responseJSON || {};
    var payload = response.payload;
    if (typeof payload === "string") {
      try {
        response = JSON.parse(payload);
      } catch (error) {
        response = {};
      }
    }
    return response.detail || response.error ||
      "Request failed with HTTP " + (xhr.status || "unknown") + ".";
  }

  function clearDiscoveryTimer() {
    if (discoveryTimer) {
      window.clearTimeout(discoveryTimer);
      discoveryTimer = null;
    }
  }

  function resetAnalyzeButton() {
    $("#dei-analyze").prop("disabled", false).text("Analyze environment");
  }

  function discoveryFailure(message) {
    clearDiscoveryTimer();
    discoveryHandled = true;
    pendingAnalysis = false;
    $("#dei-feedback").text(message);
    resetAnalyzeButton();
  }

  function runRecommendations(sources, indexCount) {
    var feedback = $("#dei-feedback");
    $("#dei-analyze").text("Analyzing...");
    feedback.text("Normalizing discovered telemetry and evaluating detection readiness.");
    postJson(endpoints.recommendations, {
      sources: sources,
      enterprise_security_enabled: $("#dei-es-enabled").is(":checked"),
      include_unsupported: true
    }).done(function (report) {
      var unmapped = report.unmapped_sources || [];
      renderReport(report);
      setStatus("API status: healthy", true);
      feedback.text(
        "Analysis complete. Discovered " + sources.length + " source types across " +
        indexCount + " indexes; " + unmapped.length + " unmapped."
      );
    }).fail(function (xhr) {
      feedback.text(errorDetail(xhr));
    }).always(resetAnalyzeButton);
  }

  function handleDiscovery(data) {
    var rows = resultRows(data);
    if (!rows.length) {
      return false;
    }
    clearDiscoveryTimer();
    discoveryHandled = true;
    var sources = uniqueValues(rows.map(function (row) { return row.sourcetype; }));
    var indexes = uniqueValues(rows.map(function (row) { return row.index; }));
    $("#dei-sources").val(sources.join("\n"));
    if (pendingAnalysis) {
      pendingAnalysis = false;
      if (!sources.length) {
        discoveryFailure("No searchable source types were discovered.");
        return true;
      }
      runRecommendations(sources, indexes.length);
    } else {
      $("#dei-feedback").text(
        "Discovered " + sources.length + " active source types across " +
        indexes.length + " indexes."
      );
    }
    return true;
  }

  function discoverEnvironment(analyzeAfterDiscovery) {
    pendingAnalysis = analyzeAfterDiscovery;
    discoveryHandled = false;
    clearDiscoveryTimer();
    if (analyzeAfterDiscovery) {
      $("#dei-analyze").prop("disabled", true).text("Discovering...");
      $("#dei-feedback").text("Discovering active Splunk telemetry from the last 7 days.");
    }
    discoveryTimer = window.setTimeout(function () {
      if (!discoveryHandled) {
        discoveryFailure("Telemetry discovery timed out after 30 seconds.");
      }
    }, 30000);
    discoverySearch.startSearch();
  }

  discoveryResults.on("data", function () {
    handleDiscovery(discoveryResults.data());
  });

  discoverySearch.on("search:done", function () {
    if (discoveryHandled) {
      return;
    }
    window.setTimeout(function () {
      if (!discoveryHandled && !handleDiscovery(discoveryResults.data())) {
        discoveryFailure("Telemetry discovery completed but returned no searchable source types.");
      }
    }, 100);
  });

  discoverySearch.on("search:error", function () {
    discoveryFailure("Unable to discover searchable Splunk telemetry.");
  });

  discoverySearch.on("search:cancelled", function () {
    discoveryFailure("Telemetry discovery was cancelled before completion.");
  });

  $("#dei-analyze").on("click", function () {
    discoverEnvironment(true);
  });

  $.ajax({
    url: endpoints.health,
    method: "GET",
    dataType: "json"
  }).then(parsePayload).done(function (health) {
    setStatus("API status: " + (health.status || "healthy"), true);
  }).fail(function () {
    setStatus("API status: awaiting analysis", false);
  });

  discoverEnvironment(false);
});

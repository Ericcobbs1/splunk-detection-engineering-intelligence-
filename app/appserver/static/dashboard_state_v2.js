require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var REPORT_KEY = "dei.latestRecommendationReport";
  var REPORT_TIME_KEY = "dei.latestRecommendationTime";
  var DISCOVERY_KEY = "dei.latestDiscoveryExport";
  var DISCOVERY_TIME_KEY = "dei.latestDiscoveryTime";
  var ES_KEY = "dei.latestEnterpriseSecurityEnabled";
  var CLEAR_KEY = "dei.dashboardCleared";
  var DISCOVERY_TOKEN = "| tstats count WHERE index=* earliest=-7d latest=now BY index sourcetype";
  var originalAjax = $.ajax;
  var forceRefresh = false;
  var globalRefreshInProgress = false;
  var activeEnvironmentRequests = [];

  function setGlobalRefreshState(active) {
    var button = $("#dei-refresh-environment");
    globalRefreshInProgress = active;
    button.prop("disabled", active).attr("aria-busy", active ? "true" : "false");
    $("#dei-clear-environment").prop("disabled", active);
    button.html(active
      ? "<span>⟳</span> Refreshing entire page..."
      : "<span>↻</span> Refresh environment");
  }

  function clearPersistedDashboard() {
    activeEnvironmentRequests.slice().forEach(function (request) {
      if (request && request.readyState !== 4) { request.abort(); }
    });
    activeEnvironmentRequests = [];
    [REPORT_KEY, REPORT_TIME_KEY, DISCOVERY_KEY, DISCOVERY_TIME_KEY, ES_KEY].forEach(function (key) {
      try { window.sessionStorage.removeItem(key); } catch (error) {
        // Storage failures must not prevent the visible dashboard reset.
      }
    });
    try { window.sessionStorage.setItem(CLEAR_KEY, "true"); } catch (error) {
      // The visible reset still applies when storage is unavailable.
    }
    forceRefresh = false;
    setGlobalRefreshState(false);
    $("#metric-sources, #metric-ready, #metric-partial").text("0");
    $("#metric-understanding, #metric-potential, #coverage-value").text("0%");
    $("#coverage-ring").css("--dei-coverage", "0%");
    $("#coverage-label").text("Not analyzed");
    $("#portfolio-total").text("0 opportunities");
    $("#portfolio-ready, #portfolio-partial, #portfolio-field-gaps, #portfolio-unverified").text("0");
    $("#dei-sources").val("");
    $("#dei-es-enabled").prop("checked", false);
    $("#recommendations").empty();
    $("#recommendation-count").text("");
    $("#environment-snapshot-age").text("No saved snapshot");
    $("#dei-analyze").prop("disabled", false).html("<span>Run intelligence scan</span><b>→</b>");
    $("#dei-feedback").text("Scan data cleared. Select Run intelligence scan to analyze this environment.");
    $(document).trigger("dei:environment-cleared");
  }

  function safeJson(value) {
    try { return JSON.parse(value || "null"); } catch (error) { return null; }
  }

  function unique(values) {
    var seen = {};
    return (values || []).filter(function (value) {
      var key = String(value || "").toLowerCase();
      if (!key || seen[key]) { return false; }
      seen[key] = true;
      return true;
    });
  }

  function parseDiscovery(text) {
    var rows = [];
    String(text || "").split(/\r?\n/).forEach(function (line) {
      var parsed;
      if (!line.trim()) { return; }
      try { parsed = JSON.parse(line); } catch (error) { return; }
      if (parsed && parsed.result) { rows.push(parsed.result); }
    });
    return {
      sources: unique(rows.map(function (row) { return row.sourcetype; })),
      indexes: unique(rows.map(function (row) { return row.index; }))
    };
  }

  function isDiscoveryRequest(options) {
    var search = options && options.data && options.data.search;
    return String(search || "").indexOf(DISCOVERY_TOKEN) !== -1;
  }

  $.ajax = function (options) {
    var cached;
    var deferred;
    var request;
    if (!isDiscoveryRequest(options)) {
      return originalAjax.apply($, arguments);
    }

    cached = window.sessionStorage.getItem(DISCOVERY_KEY);
    if (window.sessionStorage.getItem(CLEAR_KEY) === "true" && !forceRefresh) {
      deferred = $.Deferred();
      window.setTimeout(function () { deferred.resolve("", "success", {responseText: ""}); }, 0);
      return deferred.promise();
    }
    if (cached && !forceRefresh) {
      deferred = $.Deferred();
      window.setTimeout(function () { deferred.resolve(cached, "success", {responseText: cached}); }, 0);
      return deferred.promise();
    }

    forceRefresh = false;
    request = originalAjax.apply($, arguments);
    request.done(function (text) {
      try {
        window.sessionStorage.setItem(DISCOVERY_KEY, String(text || ""));
        window.sessionStorage.setItem(DISCOVERY_TIME_KEY, String(Date.now()));
        window.sessionStorage.removeItem(CLEAR_KEY);
      } catch (error) {
        // Storage failures must not affect discovery.
      }
    });
    return request;
  };

  function isEnvironmentRequest(settings) {
    var url = String(settings && settings.url || "");
    return url.indexOf("/search/jobs/export") !== -1 ||
      url.indexOf("/dei/v1/recommendations") !== -1;
  }

  $(document).ajaxSend(function (_event, xhr, settings) {
    if (isEnvironmentRequest(settings)) { activeEnvironmentRequests.push(xhr); }
  });

  $(document).ajaxComplete(function (_event, xhr) {
    activeEnvironmentRequests = activeEnvironmentRequests.filter(function (request) {
      return request !== xhr && request && request.readyState !== 4;
    });
  });

  function renderDomains(recommendations) {
    var counts = {};
    var maximum;
    var html;
    (recommendations || []).forEach(function (item) {
      counts[item.pack_id] = (counts[item.pack_id] || 0) + 1;
    });
    maximum = Math.max.apply(null, Object.keys(counts).map(function (key) { return counts[key]; }).concat([1]));
    html = Object.keys(counts).sort().map(function (packId) {
      var percent = Math.round((counts[packId] / maximum) * 100);
      return '<div class="dei-domain"><div class="dei-domain-row"><span>' + packId + '</span><strong>' + counts[packId] + '</strong></div><div class="dei-bar"><span style="width:' + percent + '%"></span></div></div>';
    }).join("");
    $("#coverage-domains").html(html || '<p class="dei-empty">No supported domains found.</p>');
  }

  function renderSavedReport(report) {
    var ready;
    var partial;
    var unsupported;
    var observed;
    var unmapped;
    var understood;
    var understanding;
    var total;
    var potential;
    if (!report || !report.recommendations) { return; }

    ready = report.production_ready_count || 0;
    partial = report.partial_count || 0;
    unsupported = report.unsupported_count || 0;
    observed = report.observed_source_count || 0;
    unmapped = (report.unmapped_sources || []).length;
    understood = Math.max(0, observed - unmapped);
    understanding = observed ? Math.round((understood / observed) * 100) : 0;
    total = ready + partial + unsupported;
    potential = total ? Math.round(((ready + partial * 0.5) / total) * 100) : 0;

    $("#metric-sources").text(observed);
    $("#metric-understanding").text(understanding + "%");
    $("#metric-ready").text(ready);
    $("#metric-partial").text(partial);
    $("#metric-potential").text(potential + "%");
    $("#coverage-value").text(potential + "%");
    $("#coverage-ring").css("--dei-coverage", potential + "%");
    $("#coverage-label").text(potential >= 75 ? "Strong" : potential >= 40 ? "Developing" : "Limited");
    $("#portfolio-total").text(total + " opportunities");
    $("#portfolio-ready").text(ready);
    $("#portfolio-partial").text(partial);
    $("#portfolio-field-gaps").text(report.field_gap_count || 0);
    $("#portfolio-unverified").text(report.field_unverified_count || 0);
    renderDomains(report.recommendations);
  }

  function renderSavedDiscovery() {
    var cached = window.sessionStorage.getItem(DISCOVERY_KEY);
    var parsed;
    if (!cached) { return; }
    parsed = parseDiscovery(cached);
    $("#dei-sources").val(parsed.sources.join("\n"));
    if (parsed.sources.length) {
      $("#dei-feedback").text("Loaded saved environment snapshot: " + parsed.sources.length + " source types across " + parsed.indexes.length + " indexes. Data remains unchanged until Refresh environment is selected.");
    }
  }

  function renderSnapshotAge() {
    var timestamp = Number(window.sessionStorage.getItem(REPORT_TIME_KEY) || window.sessionStorage.getItem(DISCOVERY_TIME_KEY) || 0);
    if (!timestamp) {
      $("#environment-snapshot-age").text("No saved snapshot");
      return;
    }
    $("#environment-snapshot-age").text("Snapshot · " + new Date(timestamp).toLocaleString());
  }

  function restoreSnapshot() {
    renderSavedDiscovery();
    renderSavedReport(safeJson(window.sessionStorage.getItem(REPORT_KEY)));
    renderSnapshotAge();
    if (window.sessionStorage.getItem(ES_KEY) === "true") {
      $("#dei-es-enabled").prop("checked", true);
    }
    if (window.sessionStorage.getItem(REPORT_KEY)) {
      $("#dei-analyze").find("span").text("Refresh environment");
    }
  }

  $(document).ajaxSuccess(function (_event, _xhr, settings, data) {
    var url = String(settings && settings.url || "");
    var payload = data;
    if (url.indexOf("/dei/v1/recommendations") === -1) { return; }
    if (payload && typeof payload.payload === "string") {
      payload = safeJson(payload.payload);
    }
    if (!payload || !payload.recommendations) { return; }
    try {
      window.sessionStorage.setItem(REPORT_KEY, JSON.stringify(payload));
      window.sessionStorage.setItem(REPORT_TIME_KEY, String(Date.now()));
      window.sessionStorage.setItem(ES_KEY, $("#dei-es-enabled").is(":checked") ? "true" : "false");
    } catch (error) {
      // Storage failures must not affect analysis.
    }
    window.setTimeout(function () {
      renderSavedReport(payload);
      renderSavedDiscovery();
      renderSnapshotAge();
      $(document).trigger("dei:environment-refreshed", [payload]);
      setGlobalRefreshState(false);
      $("#dei-analyze").find("span").text("Refresh environment");
    }, 0);
  });

  $("#dei-clear-environment").on("click", function () {
    if (globalRefreshInProgress) { return; }
    clearPersistedDashboard();
  });

  $("#dei-refresh-environment").on("click", function () {
    if (globalRefreshInProgress) { return; }
    forceRefresh = true;
    setGlobalRefreshState(true);
    $(document).trigger("dei:environment-refresh-started");
    if ($("#dei-analyze").length) {
      $("#dei-analyze").trigger("click");
    } else {
      window.location.href = "command_center#dei-telemetry";
    }
  });

  $(document).ajaxError(function (_event, _xhr, settings) {
    var url = String(settings && settings.url || "");
    if (globalRefreshInProgress && url.indexOf("/dei/v1/recommendations") !== -1) {
      setGlobalRefreshState(false);
    }
  });

  $("#dei-analyze").on("click", function () {
    forceRefresh = true;
    try { window.sessionStorage.removeItem(CLEAR_KEY); } catch (error) {
      // A new analysis still proceeds when storage is unavailable.
    }
  });

  if ($("#dei-command-center").length) {
    $("#dei-sources").val("");
    $("#dei-es-enabled").prop("checked", false);
    $("#dei-feedback").text("No scan data is loaded. Select Run intelligence scan to analyze this Splunk environment.");
  } else {
    restoreSnapshot();
  }
});

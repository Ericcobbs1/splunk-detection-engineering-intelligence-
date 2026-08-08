require([
  "jquery",
  "splunkjs/mvc/simplexml/ready!"
], function ($) {
  "use strict";

  var appId = "splunk_detection_engineering_intelligence";
  var fieldSampleEvents = 200;
  var fieldDiscoveryConcurrency = 6;
  var fieldSearchTimeoutMs = 12000;
  var fieldDiscoveryTimeoutMs = 90000;

  function endpoint() {
    var parts = Array.prototype.slice.call(arguments);
    return Splunk.util.make_url.apply(
      Splunk.util,
      ["splunkd", "__raw", "servicesNS", "-", appId].concat(parts)
    );
  }

  var endpoints = {
    health: endpoint("dei", "v1", "health"),
    recommendations: endpoint("dei", "v1", "recommendations"),
    discovery: Splunk.util.make_url(
      "splunkd", "__raw", "services", "search", "jobs", "export"
    )
  };

  var discoverySpl = [
    "| tstats count WHERE index=* earliest=-7d latest=now BY index sourcetype",
    '| where NOT match(index, "^_") AND isnotnull(sourcetype)',
    "| sort - count"
  ].join(" ");

  var riskDataModelSpl = [
    "| from datamodel:Risk.All_Risk",
    '| where _time >= relative_time(now(), "-7d")',
    "| head " + fieldSampleEvents,
    "| fieldsummary",
    "| fields field"
  ].join(" ");

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
      timeout: 30000,
      headers: {"X-Splunk-Form-Key": Splunk.util.getConfigValue("FORM_KEY")},
      data: JSON.stringify(payload)
    }).then(parsePayload);
  }

  function exportSearch(search, timeout) {
    return $.ajax({
      url: endpoints.discovery,
      method: "POST",
      dataType: "text",
      timeout: timeout || 30000,
      headers: {"X-Splunk-Form-Key": Splunk.util.getConfigValue("FORM_KEY")},
      data: {search: search, output_mode: "json", preview: "0"}
    });
  }

  function setStatus(message, healthy) {
    var status = $("#dei-api-status");
    status.text(message);
    status.removeClass("healthy unhealthy").addClass(healthy ? "healthy" : "unhealthy");
  }

  function uniqueValues(values) {
    var seen = {};
    return values.filter(function (value) {
      var normalized = String(value || "").trim();
      var key = normalized.toLowerCase();
      if (!normalized || seen[key]) { return false; }
      seen[key] = true;
      return true;
    });
  }

  function parseExportRows(text) {
    var rows = [];
    String(text || "").split(/\r?\n/).forEach(function (line) {
      var trimmed = line.trim();
      var parsed;
      if (!trimmed) { return; }
      try { parsed = JSON.parse(trimmed); } catch (error) { return; }
      if (parsed && parsed.result) {
        rows.push(parsed.result);
      } else if (parsed && (parsed.sourcetype || parsed.field)) {
        rows.push(parsed);
      }
    });
    return rows;
  }

  function escapeSearchValue(value) {
    return String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function discoverFieldInventory(sources, onProgress) {
    return new Promise(function (resolve) {
      var inventory = {};
      var failures = [];
      var requests = [];
      var cursor = 0;
      var active = 0;
      var completed = 0;
      var settled = false;

      function finish(timedOut) {
        if (settled) { return; }
        settled = true;
        requests.forEach(function (request) {
          if (request && request.readyState !== 4) { request.abort(); }
        });
        resolve({inventory: inventory, failures: uniqueValues(failures), timedOut: timedOut});
      }

      var overallTimer = window.setTimeout(function () {
        sources.slice(cursor).forEach(function (source) { failures.push(source); });
        finish(true);
      }, fieldDiscoveryTimeoutMs);

      function finishOrSchedule() {
        if (settled) { return; }
        if (cursor >= sources.length && active === 0) {
          window.clearTimeout(overallTimer);
          finish(false);
          return;
        }
        while (active < fieldDiscoveryConcurrency && cursor < sources.length) {
          (function (source) {
            var isEsRisk = source.toLowerCase() === "modular_alerts:risk";
            var fieldSpl = isEsRisk ? riskDataModelSpl : [
              'search index=* earliest=-7d latest=now sourcetype="' + escapeSearchValue(source) + '"',
              "| head " + fieldSampleEvents,
              "| fieldsummary",
              "| fields field"
            ].join(" ");
            var request;
            active += 1;
            request = exportSearch(fieldSpl, fieldSearchTimeoutMs).done(function (text) {
              var fieldRows = parseExportRows(text);
              if (isEsRisk) {
                $("#dei-es-enabled").prop("checked", true);
              }
              if (fieldRows.length) {
                inventory[source] = uniqueValues(fieldRows.map(function (row) {
                  return row.field;
                }));
              } else {
                failures.push(source);
              }
            }).fail(function () {
              failures.push(source);
            }).always(function () {
              if (settled) { return; }
              active -= 1;
              completed += 1;
              if (onProgress) { onProgress(completed, sources.length, source); }
              finishOrSchedule();
            });
            requests.push(request);
          })(sources[cursor]);
          cursor += 1;
        }
      }

      if (!sources.length) {
        window.clearTimeout(overallTimer);
        finish(false);
        return;
      }
      finishOrSchedule();
    });
  }

  function readinessLabel(value) {
    return String(value || "unknown").replace(/_/g, " ");
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
        '<div class="dei-domain-row"><span>', escapeHtml(packId), "</span><strong>", counts[packId], "</strong></div>",
        '<div class="dei-bar"><span style="width:', percent, '%"></span></div>',
        "</div>"
      ].join("");
    }).join("");
    $("#coverage-domains").html(html || '<p class="dei-empty">No supported domains found.</p>');
  }

  function fieldGapText(item) {
    var missingFields = item.missing_fields || {};
    var parts = Object.keys(missingFields).map(function (source) {
      return source + ": " + missingFields[source].join(", ");
    });
    return parts.length ? "Field gaps: " + parts.join("; ") : "";
  }

  function fieldState(item) {
    if (item.field_validation === "passed") { return {label: "Fields verified", css: "verified"}; }
    if (item.field_validation === "failed") { return {label: "Field gap", css: "gap"}; }
    if (item.field_validation === "unverified") { return {label: "Fields unverified", css: "unverified"}; }
    return {label: "Fields not evaluated", css: "neutral"};
  }

  function detailText(item) {
    if (item.missing_sources && item.missing_sources.length) {
      return "Missing telemetry: " + item.missing_sources.join(", ");
    }
    if (item.field_validation === "failed") {
      return fieldGapText(item);
    }
    if (item.field_validation === "unverified") {
      return "No recent field sample for: " + (item.unverified_field_sources || []).join(", ");
    }
    if (item.field_validation === "passed") {
      return "Telemetry and field requirements satisfied";
    }
    return "Telemetry requirements satisfied; fields not evaluated";
  }

  function renderMitre(techniques) {
    var values = techniques || [];
    if (!values.length) { return '<span class="dei-technique muted">No MITRE mapping</span>'; }
    return values.slice(0, 4).map(function (technique) {
      return '<span class="dei-technique">' + escapeHtml(technique) + "</span>";
    }).join("");
  }

  function renderRecommendations(report) {
    var recommendations = report.recommendations || [];
    var html = recommendations.slice(0, 10).map(function (item, index) {
      var validation = fieldState(item);
      return [
        '<article class="dei-recommendation">',
        '<div class="dei-rec-rank">', String(index + 1).padStart(2, "0"), "</div>",
        '<div class="dei-rec-body">',
        '<div class="dei-rec-top"><div>',
        '<div class="dei-rec-badges">',
        '<span class="dei-severity ', escapeHtml(item.severity), '">', escapeHtml(item.severity), "</span>",
        '<span class="dei-readiness ', escapeHtml(item.readiness), '">', escapeHtml(readinessLabel(item.readiness)), "</span>",
        '<span class="dei-field-state ', validation.css, '">', validation.label, "</span>",
        "</div>",
        '<h3 class="dei-rec-title">', escapeHtml(item.name), "</h3>",
        '<p class="dei-rec-meta">', escapeHtml(item.capability), " · ", escapeHtml(item.pack_id), "</p></div>",
        '<div class="dei-score-block"><span>Score</span><strong>', escapeHtml(item.score), "</strong></div></div>",
        '<p class="dei-rec-why">', escapeHtml(item.why), "</p>",
        '<div class="dei-rec-footer"><div class="dei-techniques">', renderMitre(item.mitre_techniques), "</div>",
        '<p class="dei-rec-detail">', escapeHtml(detailText(item)), "</p></div>",
        "</div></article>"
      ].join("");
    }).join("");
    $("#recommendation-count").text(recommendations.length + " results");
    $("#recommendations").html(html || '<p class="dei-empty">No recommendations matched the current telemetry.</p>');
    renderDomains(recommendations);
  }

  function renderPortfolio(report, total) {
    $("#portfolio-total").text(total + " opportunities");
    $("#portfolio-ready").text(report.production_ready_count || 0);
    $("#portfolio-partial").text(report.partial_count || 0);
    $("#portfolio-field-gaps").text(report.field_gap_count || 0);
    $("#portfolio-unverified").text(report.field_unverified_count || 0);
  }

  function renderReport(report) {
    var ready = report.production_ready_count || 0;
    var partial = report.partial_count || 0;
    var unsupported = report.unsupported_count || 0;
    var observed = report.observed_source_count || 0;
    var unmapped = (report.unmapped_sources || []).length;
    var understood = Math.max(0, observed - unmapped);
    var understanding = observed ? Math.round((understood / observed) * 100) : 0;
    var total = ready + partial + unsupported;
    var potential = total ? Math.round(((ready + partial * 0.5) / total) * 100) : 0;

    $("#metric-sources").text(observed);
    $("#metric-understanding").text(understanding + "%");
    $("#metric-ready").text(ready);
    $("#metric-partial").text(partial);
    $("#metric-potential").text(potential + "%");
    $("#coverage-value").text(potential + "%");
    $("#coverage-ring").css("--dei-coverage", potential + "%");
    $("#coverage-label").text(potential >= 75 ? "Strong" : potential >= 40 ? "Developing" : "Limited");
    renderPortfolio(report, total);
    renderRecommendations(report);
  }

  function errorDetail(xhr) {
    var response = xhr.responseJSON || {};
    var payload = response.payload;
    if (typeof payload === "string") {
      try { response = JSON.parse(payload); } catch (error) { response = {}; }
    }
    return response.detail || response.error || "Request failed with HTTP " + (xhr.status || "unknown") + ".";
  }

  function resetAnalyzeButton() {
    $("#dei-analyze").prop("disabled", false).text("Run intelligence scan");
  }

  function runRecommendations(sources, indexCount, fieldsBySource, profilingFailures) {
    var feedback = $("#dei-feedback");
    var esEnabled = $("#dei-es-enabled").is(":checked");
    $("#dei-analyze").text("Analyzing...");
    feedback.text("Evaluating telemetry and field-level detection readiness.");
    postJson(endpoints.recommendations, {
      sources: sources,
      fields_by_source: fieldsBySource,
      enterprise_security_enabled: esEnabled,
      include_unsupported: true
    }).done(function (report) {
      var unmapped = report.unmapped_sources || [];
      var observed = report.observed_source_count || sources.length;
      var understood = Math.max(0, observed - unmapped.length);
      var understanding = observed ? Math.round((understood / observed) * 100) : 0;
      var fieldGaps = report.field_gap_count || 0;
      var unverified = report.field_unverified_count || 0;
      var profileNote = profilingFailures && profilingFailures.length
        ? "; " + profilingFailures.length + " source type(s) could not be field-profiled and were treated as unverified"
        : "";
      renderReport(report);
      setStatus("API status: healthy", true);
      feedback.text(
        "Analysis complete. Discovered " + sources.length + " source types across " + indexCount +
        " indexes; " + understood + " mapped, " + unmapped.length + " unmapped (" + understanding +
        "% telemetry understanding); Enterprise Security " + (esEnabled ? "enabled" : "not enabled") +
        "; " + fieldGaps + " detections have confirmed field gaps; " + unverified +
        " are field-unverified because no recent sample was available" + profileNote + "."
      );
    }).fail(function (xhr) {
      feedback.text(errorDetail(xhr));
    }).always(resetAnalyzeButton);
  }

  function discoverEnvironment(analyzeAfterDiscovery) {
    var button = $("#dei-analyze");
    var feedback = $("#dei-feedback");

    if (analyzeAfterDiscovery) {
      button.prop("disabled", true).text("Discovering...");
    }
    feedback.text("Discovering active Splunk telemetry from the last 7 days.");

    exportSearch(discoverySpl, 20000).done(function (text) {
      var rows = parseExportRows(text);
      var sources = uniqueValues(rows.map(function (row) { return row.sourcetype; }));
      var indexes = uniqueValues(rows.map(function (row) { return row.index; }));
      $("#dei-sources").val(sources.join("\n"));

      if (!sources.length) {
        feedback.text("Telemetry discovery completed but returned no searchable source types.");
        resetAnalyzeButton();
        return;
      }

      if (!analyzeAfterDiscovery) {
        feedback.text("Discovered " + sources.length + " active source types across " + indexes.length + " indexes.");
        resetAnalyzeButton();
        return;
      }

      button.text("Profiling fields 0/" + sources.length);
      feedback.text(
        "Telemetry inventory complete. Profiling 0/" + sources.length +
        " source types; slow sources will be marked unverified instead of blocking analysis."
      );
      discoverFieldInventory(sources, function (completed, total, source) {
        button.text("Profiling fields " + completed + "/" + total);
        feedback.text(
          "Profiling fields " + completed + "/" + total + ". Last completed: " + source + "."
        );
      }).then(function (result) {
        if (result.timedOut) {
          feedback.text(
            "Field profiling reached its 90-second ceiling. Continuing analysis with completed samples; " +
            result.failures.length + " source type(s) will be field-unverified."
          );
        }
        runRecommendations(sources, indexes.length, result.inventory, result.failures);
      });
    }).fail(function (xhr, statusText) {
      feedback.text(statusText === "timeout"
        ? "Telemetry inventory timed out after 20 seconds."
        : "Telemetry discovery failed: " + errorDetail(xhr));
      resetAnalyzeButton();
    });
  }

  $("#dei-analyze").on("click", function () { discoverEnvironment(true); });

  $.ajax({url: endpoints.health, method: "GET", dataType: "json", timeout: 10000})
    .then(parsePayload).done(function (health) {
      setStatus("API status: " + (health.status || "healthy"), true);
    }).fail(function () {
      setStatus("API status: awaiting analysis", false);
    });

  $("#dei-sources").val("");
  $("#dei-feedback").text("No scan data is loaded. Select Run intelligence scan to analyze this Splunk environment.");
});
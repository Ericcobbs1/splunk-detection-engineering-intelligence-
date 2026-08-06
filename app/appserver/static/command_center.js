require([
  "jquery",
  "splunkjs/mvc/simplexml/ready!"
], function ($) {
  "use strict";

  var appId = "splunk_detection_engineering_intelligence";
  var fieldSampleEvents = 200;
  var fieldDiscoveryConcurrency = 4;

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
    status.css("color", healthy ? "#45e6c1" : "#ff6b7a");
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

  function discoverFieldInventory(sources) {
    return new Promise(function (resolve, reject) {
      var inventory = {};
      var failures = [];
      var cursor = 0;
      var active = 0;

      function finishOrSchedule() {
        if (cursor >= sources.length && active === 0) {
          if (failures.length) {
            reject(failures);
          } else {
            resolve(inventory);
          }
          return;
        }
        while (active < fieldDiscoveryConcurrency && cursor < sources.length) {
          (function (source) {
            var fieldSpl = [
              'search earliest=-7d latest=now sourcetype="' + escapeSearchValue(source) + '"',
              "| head " + fieldSampleEvents,
              "| fieldsummary",
              "| fields field"
            ].join(" ");
            active += 1;
            exportSearch(fieldSpl, 30000).done(function (text) {
              inventory[source] = uniqueValues(parseExportRows(text).map(function (row) {
                return row.field;
              }));
            }).fail(function () {
              failures.push(source);
            }).always(function () {
              active -= 1;
              finishOrSchedule();
            });
          })(sources[cursor]);
          cursor += 1;
        }
      }

      if (!sources.length) {
        resolve(inventory);
        return;
      }
      finishOrSchedule();
    });
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
        '<div class="dei-domain-row"><span>', packId, "</span><strong>", counts[packId], "</strong></div>",
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

  function renderRecommendations(report) {
    var recommendations = report.recommendations || [];
    var html = recommendations.slice(0, 8).map(function (item) {
      var detail;
      if (item.missing_sources && item.missing_sources.length) {
        detail = "Missing telemetry: " + item.missing_sources.join(", ");
      } else if (item.field_validation === "failed") {
        detail = fieldGapText(item);
      } else if (item.field_validation === "passed") {
        detail = "Telemetry and field requirements satisfied";
      } else {
        detail = "Telemetry requirements satisfied; fields not evaluated";
      }
      return [
        '<article class="dei-recommendation">',
        '<div class="dei-rec-top"><div>',
        '<h3 class="dei-rec-title">', item.name, "</h3>",
        '<p class="dei-rec-meta">', item.capability, " · ", item.severity, " · ", item.pack_id, "</p></div>",
        '<span class="dei-rec-score">', item.score, "</span></div>",
        '<span class="dei-readiness ', item.readiness, '">', readinessLabel(item.readiness), "</span>",
        '<p class="dei-rec-why">', item.why, "</p>",
        '<p class="dei-rec-meta">', detail, "</p>",
        "</article>"
      ].join("");
    }).join("");
    $("#recommendation-count").text(recommendations.length + " results");
    $("#recommendations").html(html || '<p class="dei-empty">No recommendations matched the current telemetry.</p>');
    renderDomains(recommendations);
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
    $("#dei-analyze").prop("disabled", false).text("Analyze environment");
  }

  function runRecommendations(sources, indexCount, fieldsBySource) {
    var feedback = $("#dei-feedback");
    $("#dei-analyze").text("Analyzing...");
    feedback.text("Evaluating telemetry and field-level detection readiness.");
    postJson(endpoints.recommendations, {
      sources: sources,
      fields_by_source: fieldsBySource,
      enterprise_security_enabled: $("#dei-es-enabled").is(":checked"),
      include_unsupported: true
    }).done(function (report) {
      var unmapped = report.unmapped_sources || [];
      var observed = report.observed_source_count || sources.length;
      var understood = Math.max(0, observed - unmapped.length);
      var understanding = observed ? Math.round((understood / observed) * 100) : 0;
      var fieldGaps = report.field_gap_count || 0;
      renderReport(report);
      setStatus("API status: healthy", true);
      feedback.text(
        "Analysis complete. Discovered " + sources.length + " source types across " + indexCount +
        " indexes; " + understood + " mapped, " + unmapped.length + " unmapped (" + understanding +
        "% telemetry understanding); " + fieldGaps + " detections have field gaps."
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

    exportSearch(discoverySpl, 30000).done(function (text) {
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

      button.text("Profiling fields...");
      feedback.text(
        "Sampling up to " + fieldSampleEvents + " events per source type to validate detection fields."
      );
      discoverFieldInventory(sources).then(function (fieldsBySource) {
        runRecommendations(sources, indexes.length, fieldsBySource);
      }).catch(function (failures) {
        feedback.text(
          "Field discovery failed for " + failures.length + " source type(s): " + failures.join(", ") +
          ". Analysis stopped rather than assuming field readiness."
        );
        resetAnalyzeButton();
      });
    }).fail(function (xhr, statusText) {
      feedback.text(statusText === "timeout"
        ? "Telemetry discovery timed out after 30 seconds."
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

  discoverEnvironment(false);
});

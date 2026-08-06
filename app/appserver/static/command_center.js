require([
  "jquery",
  "splunkjs/mvc/simplexml/ready!"
], function ($) {
  "use strict";

  var endpoints = {
    health: Splunk.util.make_url("splunkd", "__raw", "services", "dei", "v1", "health"),
    recommendations: Splunk.util.make_url(
      "splunkd",
      "__raw",
      "services",
      "dei",
      "v1",
      "recommendations"
    )
  };

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
      data: JSON.stringify(payload)
    }).then(parsePayload);
  }

  function setStatus(message, healthy) {
    var status = $("#dei-api-status");
    status.text(message);
    status.css("color", healthy ? "#45e6c1" : "#ff6b7a");
  }

  function normalizeSources(value) {
    var seen = {};
    return value
      .split(/[\n,]+/)
      .map(function (source) {
        return source.trim();
      })
      .filter(function (source) {
        var key = source.toLowerCase();
        if (!source || seen[key]) {
          return false;
        }
        seen[key] = true;
        return true;
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

    var html = Object.keys(counts)
      .sort()
      .map(function (packId) {
        var percent = Math.round((counts[packId] / maximum) * 100);
        return [
          '<div class="dei-domain">',
          '<div class="dei-domain-row"><span>', packId, "</span><strong>",
          counts[packId], "</strong></div>",
          '<div class="dei-bar"><span style="width:', percent, '%"></span></div>',
          "</div>"
        ].join("");
      })
      .join("");

    $("#coverage-domains").html(html || '<p class="dei-empty">No supported domains found.</p>');
  }

  function renderRecommendations(report) {
    var recommendations = report.recommendations || [];
    var visible = recommendations.slice(0, 8);
    var html = visible.map(function (item) {
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
    $("#coverage-label").text(potential >= 75 ? "Strong" : potential >= 40 ? "Developing" : "Limited");
    renderRecommendations(report);
  }

  function analyze() {
    var sources = normalizeSources($("#dei-sources").val() || "");
    var button = $("#dei-analyze");
    var feedback = $("#dei-feedback");

    if (!sources.length) {
      feedback.text("Enter at least one source type.");
      return;
    }

    button.prop("disabled", true).text("Analyzing...");
    feedback.text("Evaluating telemetry against the detection catalog.");

    postJson(endpoints.recommendations, {
      payload: {
        sources: sources,
        enterprise_security_enabled: $("#dei-es-enabled").is(":checked"),
        include_unsupported: true
      }
    }).done(function (report) {
      renderReport(report);
      feedback.text("Analysis complete. Recommendations are ranked by readiness and priority.");
    }).fail(function (xhr) {
      var detail = xhr.responseJSON && xhr.responseJSON.detail;
      feedback.text(detail || "Unable to complete the analysis.");
    }).always(function () {
      button.prop("disabled", false).text("Analyze environment");
    });
  }

  $("#dei-analyze").on("click", analyze);

  $.ajax({
    url: endpoints.health,
    method: "GET",
    dataType: "json"
  }).then(parsePayload).done(function (health) {
    setStatus("API status: " + (health.status || "healthy"), true);
  }).fail(function () {
    setStatus("API status: unavailable", false);
  });
});

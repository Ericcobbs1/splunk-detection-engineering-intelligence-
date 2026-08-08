require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var REPORT_KEY = "dei.latestRecommendationReport";
  var DISCOVERY_KEY = "dei.latestDiscoveryExport";
  var ES_KEY = "dei.latestEnterpriseSecurityEnabled";
  var COLORS = ["#5ce1c2", "#6ea8ff", "#8bd5ca", "#a6da95", "#eed49f", "#91d7e3", "#c6a0f6", "#f5a97f"];
  var TACTICS = [
    ["Recon", "Reconnaissance"], ["Resource", "Resource Development"], ["Initial", "Initial Access"],
    ["Execution", "Execution"], ["Persist", "Persistence"], ["Priv Esc", "Privilege Escalation"],
    ["Defense", "Defense Evasion"], ["Cred Access", "Credential Access"], ["Discovery", "Discovery"],
    ["Lat Move", "Lateral Movement"], ["Collect", "Collection"], ["C2", "Command and Control"],
    ["Exfil", "Exfiltration"], ["Impact", "Impact"], ["Def Impair", "Defense Impairment"]
  ];
  var TECHNIQUE_TACTICS = {
    "T1110.003":["Credential Access"], "T1110":["Credential Access"], "T1558.003":["Credential Access"],
    "T1059.001":["Execution"], "T1059":["Execution"],
    "T1098":["Persistence","Privilege Escalation"],
    "T1078.004":["Initial Access","Persistence","Privilege Escalation","Defense Evasion"],
    "T1562.008":["Defense Impairment"], "T1685.002":["Defense Impairment"],
    "T1530":["Collection"], "T1567":["Exfiltration"], "T1021":["Lateral Movement"],
    "T1548.003":["Privilege Escalation","Defense Evasion"], "T1071.004":["Command and Control"],
    "T1190":["Initial Access"], "T1041":["Exfiltration"], "T1566":["Initial Access"],
    "T1078":["Initial Access","Persistence","Privilege Escalation","Defense Evasion"],
    "T1136":["Persistence"], "T1218":["Defense Evasion"], "T1087":["Discovery"],
    "T1057":["Discovery"], "T1005":["Collection"], "T1486":["Impact"]
  };

  function safeJson(value) {
    try { return JSON.parse(value || "null"); } catch (error) { return null; }
  }

  function esc(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function parseDiscovery(text) {
    var rows = [];
    var indexes = {};
    var sources = {};
    var events = 0;
    String(text || "").split(/\r?\n/).forEach(function (line) {
      var parsed;
      if (!line.trim()) { return; }
      try { parsed = JSON.parse(line); } catch (error) { return; }
      parsed = parsed && parsed.result ? parsed.result : parsed;
      if (!parsed) { return; }
      rows.push(parsed);
      if (parsed.index) { indexes[String(parsed.index)] = true; }
      if (parsed.sourcetype) { sources[String(parsed.sourcetype)] = true; }
      events += Number(parsed.count || 0) || 0;
    });
    return {rows:rows,indexes:Object.keys(indexes),sources:Object.keys(sources),events:events};
  }

  function domainCounts(report) {
    var counts = {};
    (report && report.recommendations || []).forEach(function (item) {
      var key = String(item.pack_id || "other");
      counts[key] = (counts[key] || 0) + 1;
    });
    return counts;
  }

  function renderDomains(report) {
    var counts = domainCounts(report);
    var entries = Object.keys(counts).map(function (key) { return [key, counts[key]]; })
      .sort(function (a, b) { return b[1] - a[1]; });
    var total = entries.reduce(function (sum, item) { return sum + item[1]; }, 0) || 1;
    var max = entries.length ? entries[0][1] : 1;
    var topHtml = entries.slice(0, 3).map(function (item) {
      var width = Math.round((item[1] / max) * 100);
      return '<div class="dei-top-domain"><span>' + esc(item[0]) + '</span><b><i style="width:' + width + '%"></i></b><strong>' + item[1] + '</strong></div>';
    }).join("");
    $("#env-top-domains").html(topHtml || '<p class="dei-empty">No telemetry domains available.</p>');
    $("#env-domain-count").text(entries.length);

    var cursor = 0;
    var segments = [];
    var legend = entries.slice(0, 8).map(function (item, index) {
      var pct = Math.round((item[1] / total) * 100);
      var start = cursor;
      cursor += (item[1] / total) * 100;
      segments.push(COLORS[index % COLORS.length] + " " + start.toFixed(2) + "% " + cursor.toFixed(2) + "%");
      return '<div class="dei-domain-legend-row"><i style="background:' + COLORS[index % COLORS.length] + '"></i><span>' + esc(item[0]) + '</span><strong>' + pct + '%</strong></div>';
    }).join("");
    if (entries.length > 8) {
      legend += '<div class="dei-domain-legend-row"><i style="background:#53687d"></i><span>+' + (entries.length - 8) + ' more</span><strong></strong></div>';
    }
    $("#env-domain-legend").html(legend || '<p class="dei-empty">No domain distribution available.</p>');
    $("#env-domain-donut").css("background", segments.length ? "conic-gradient(" + segments.join(",") + ")" : "#1d3347");
  }

  function readinessWeight(readiness) {
    if (readiness === "production_ready") { return 1; }
    if (readiness === "partial" || readiness === "field_gap" || readiness === "field_unverified") { return 0.5; }
    return 0;
  }

  function tacticData(report) {
    var data = {};
    TACTICS.forEach(function (t) { data[t[1]] = {weighted:0,total:0,techniques:{}}; });
    (report && report.recommendations || []).forEach(function (item) {
      (item.mitre_techniques || []).forEach(function (technique) {
        var key = String(technique || "").toUpperCase();
        var tactics = TECHNIQUE_TACTICS[key] || [];
        tactics.forEach(function (tactic) {
          if (!data[tactic]) { return; }
          data[tactic].weighted += readinessWeight(item.readiness);
          data[tactic].total += 1;
          data[tactic].techniques[key] = true;
        });
      });
    });
    return data;
  }

  function renderTactics(report) {
    var data = tacticData(report);
    var covered = 0;
    var partial = 0;
    var uncovered = 0;
    var noData = 0;
    var bars = TACTICS.map(function (tactic) {
      var stat = data[tactic[1]];
      var pct = stat.total ? Math.round((stat.weighted / stat.total) * 100) : 0;
      var state;
      if (!stat.total) { state = "nodata"; noData += 1; }
      else if (pct >= 75) { state = "covered"; covered += 1; }
      else if (pct > 0) { state = "partial"; partial += 1; }
      else { state = "uncovered"; uncovered += 1; }
      return '<div class="dei-tactic-bar ' + state + '" title="' + esc(tactic[1]) + ': ' + (stat.total ? pct + '% weighted readiness' : 'no mapped detections') + '"><span class="dei-tactic-bar-value">' + (stat.total ? pct + '%' : '—') + '</span><div class="dei-tactic-bar-track"><i class="dei-tactic-bar-fill" style="height:' + (stat.total ? Math.max(8, pct) : 6) + '%"></i></div><span class="dei-tactic-bar-label">' + esc(tactic[0]) + '</span></div>';
    }).join("");
    $("#env-tactic-bars").html(bars);
    $("#env-tactics-covered").text(covered);
    $("#env-tactics-partial").text(partial);
    $("#env-tactics-uncovered").text(uncovered);
    var coveredEnd = (covered / 15) * 100;
    var partialEnd = ((covered + partial) / 15) * 100;
    var uncoveredEnd = ((covered + partial + uncovered) / 15) * 100;
    $("#env-tactic-donut").css("background", "conic-gradient(var(--dei-success) 0 " + coveredEnd + "%,var(--dei-warning) " + coveredEnd + "% " + partialEnd + "%,var(--dei-danger) " + partialEnd + "% " + uncoveredEnd + "%,#33465a " + uncoveredEnd + "% 100%)");
  }

  function renderSnapshot(report) {
    var discovery = parseDiscovery(window.localStorage.getItem(DISCOVERY_KEY));
    $("#env-index-count").text(discovery.indexes.length + " indexes");
    $("#env-source-count").text(discovery.sources.length + " source types");
    $("#env-event-count").text(discovery.events.toLocaleString());
    $("#env-detection-count").text((report && report.recommendations || []).length);
    $("#env-es-state").text(window.localStorage.getItem(ES_KEY) === "true" ? "Enabled" : "Not enabled");
  }

  function render(reportOverride) {
    var report = reportOverride || safeJson(window.localStorage.getItem(REPORT_KEY));
    if (!report || !report.recommendations) {
      renderSnapshot(null);
      return;
    }
    renderDomains(report);
    renderTactics(report);
    renderSnapshot(report);
  }

  $(document).ajaxSuccess(function (_event, _xhr, settings) {
    var url = String(settings && settings.url || "");
    if (url.indexOf("/dei/v1/recommendations") !== -1) {
      window.setTimeout(render, 25);
    }
  });

  $(document).on("dei:environment-refreshed", function (_event, report) {
    render(report);
  });

  $(document).on("dei:environment-refresh-started", function () {
    $("#dei-coverage-section").attr("aria-busy", "true");
  });

  $(document).on("dei:environment-refreshed", function () {
    $("#dei-coverage-section").attr("aria-busy", "false");
  });

  $(document).ajaxError(function (_event, _xhr, settings) {
    var url = String(settings && settings.url || "");
    if (url.indexOf("/dei/v1/recommendations") !== -1) {
      $("#dei-coverage-section").attr("aria-busy", "false");
    }
  });

  $(window).on("storage", function (event) {
    if (!event.originalEvent || [REPORT_KEY, DISCOVERY_KEY, ES_KEY].indexOf(event.originalEvent.key) !== -1) {
      render();
    }
  });

  render();
});

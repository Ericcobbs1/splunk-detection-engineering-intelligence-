require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var STORAGE_KEY = "dei.latestRecommendationReport";
  var STORAGE_TIME_KEY = "dei.latestRecommendationTime";

  var tactics = [
    {id:"TA0043", name:"Reconnaissance", count:12, description:"Adversaries gather information that can support targeting and future operations."},
    {id:"TA0042", name:"Resource Development", count:9, description:"Adversaries establish infrastructure, accounts, capabilities, and other resources used in operations."},
    {id:"TA0001", name:"Initial Access", count:11, description:"Adversaries establish an initial foothold in the target environment."},
    {id:"TA0002", name:"Execution", count:20, description:"Adversaries run malicious or unauthorized code."},
    {id:"TA0003", name:"Persistence", count:22, description:"Adversaries preserve access across interruptions, credential changes, or restarts."},
    {id:"TA0004", name:"Privilege Escalation", count:13, description:"Adversaries obtain higher permissions or stronger administrative control."},
    {id:"TA0005", name:"Stealth", count:30, description:"Adversaries conceal activity and attempt to appear normal or trustworthy."},
    {id:"TA0112", name:"Defense Impairment", count:18, description:"Adversaries weaken, disrupt, or manipulate security controls and defensive visibility."},
    {id:"TA0006", name:"Credential Access", count:17, description:"Adversaries steal, guess, or otherwise obtain account credentials."},
    {id:"TA0007", name:"Discovery", count:34, description:"Adversaries learn about systems, identities, services, and environment structure."},
    {id:"TA0008", name:"Lateral Movement", count:9, description:"Adversaries move between systems, identities, services, and trust boundaries."},
    {id:"TA0009", name:"Collection", count:17, description:"Adversaries gather data and information relevant to their objectives."},
    {id:"TA0011", name:"Command and Control", count:18, description:"Adversaries communicate with compromised assets to direct activity."},
    {id:"TA0010", name:"Exfiltration", count:9, description:"Adversaries move data outside trusted boundaries."},
    {id:"TA0040", name:"Impact", count:15, description:"Adversaries disrupt, manipulate, or destroy systems, services, and data."}
  ];

  var techniqueMap = {
    "T1110": {name:"Brute Force", tactics:["TA0006"]},
    "T1110.003": {name:"Password Spraying", parent:"T1110", tactics:["TA0006"]},
    "T1558.003": {name:"Kerberoasting", parent:"T1558", tactics:["TA0006"]},
    "T1059.001": {name:"PowerShell", parent:"T1059", tactics:["TA0002"]},
    "T1098": {name:"Account Manipulation", tactics:["TA0003","TA0004"]},
    "T1078": {name:"Valid Accounts", tactics:["TA0001","TA0003","TA0004","TA0005"]},
    "T1078.004": {name:"Cloud Accounts", parent:"T1078", tactics:["TA0001","TA0003","TA0004","TA0005"]},
    "T1562.008": {name:"Disable or Modify Cloud Logs", parent:"T1562", tactics:["TA0112"]},
    "T1530": {name:"Data from Cloud Storage", tactics:["TA0009"]},
    "T1567": {name:"Exfiltration Over Web Service", tactics:["TA0010"]},
    "T1021": {name:"Remote Services", tactics:["TA0008"]},
    "T1548.003": {name:"Sudo and Sudo Caching", parent:"T1548", tactics:["TA0004"]},
    "T1071.004": {name:"DNS", parent:"T1071", tactics:["TA0011"]},
    "T1190": {name:"Exploit Public-Facing Application", tactics:["TA0001"]},
    "T1041": {name:"Exfiltration Over C2 Channel", tactics:["TA0010"]},
    "T1566": {name:"Phishing", tactics:["TA0001"]},
    "T1610": {name:"Deploy Container", tactics:["TA0002"]}
  };

  var protectionText = {
    TA0001:"Protects the entry boundary by surfacing behaviors associated with gaining an initial foothold.",
    TA0002:"Protects workloads and endpoints by exposing malicious or unauthorized execution.",
    TA0003:"Protects long-term control of identities and systems by detecting foothold-preservation activity.",
    TA0004:"Protects privileged access by identifying attempts to obtain stronger permissions.",
    TA0005:"Protects analyst visibility and trust by detecting activity intended to blend in or evade scrutiny.",
    TA0112:"Protects defensive visibility by identifying attempts to disable, weaken, or manipulate security controls.",
    TA0006:"Protects identities and credentials from guessing, theft, cracking, and abuse.",
    TA0007:"Protects environment knowledge by detecting adversary enumeration and discovery behavior.",
    TA0008:"Protects trust boundaries by identifying movement between systems, accounts, and services.",
    TA0009:"Protects sensitive information during adversary staging and collection.",
    TA0011:"Protects communications channels by surfacing command-and-control behavior.",
    TA0010:"Protects data boundaries by detecting attempts to move information outside trusted systems.",
    TA0040:"Protects business operations and data from disruptive or destructive activity.",
    TA0043:"Provides early visibility into targeting and information-gathering activity.",
    TA0042:"Provides visibility into adversary preparation and resource establishment before intrusion activity."
  };

  var report = null;
  var selected = null;

  function escapeHtml(value) {
    return String(value == null ? "" : value).replace(/&/g,"&amp;").replace(/</g,"&lt;")
      .replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
  }

  function loadReport() {
    try { report = JSON.parse(window.localStorage.getItem(STORAGE_KEY) || "null"); }
    catch (error) { report = null; }
    var timestamp = Number(window.localStorage.getItem(STORAGE_TIME_KEY) || 0);
    if (report && report.recommendations) {
      $("#mitre-data-status").text("Analysis: loaded").addClass("healthy").removeClass("unhealthy");
      if (timestamp) { $("#mitre-analysis-age").text("Analyzed " + new Date(timestamp).toLocaleString()); }
    } else {
      $("#mitre-data-status").text("Analysis: required").addClass("unhealthy").removeClass("healthy");
      $("#mitre-analysis-age").text("No analysis loaded");
    }
  }

  function activeTactics(item) {
    var active = {};
    (item.mitre_techniques || []).forEach(function (id) {
      var technique = techniqueMap[id];
      if (technique) { technique.tactics.forEach(function (tactic) { active[tactic] = true; }); }
    });
    return active;
  }

  function renderMatrix() {
    var active = selected ? activeTactics(selected) : {};
    var covered = Object.keys(active).length;
    $("#mitre-covered-tactics").text(covered + " / 15 covered");
    $("#mitre-matrix-context").text(selected ? selected.name + " · " + (selected.mitre_techniques || []).join(", ") : "Select a detection to map its effective coverage.");
    $("#mitre-matrix").html(tactics.map(function (tactic) {
      var mapped = selected ? (selected.mitre_techniques || []).filter(function (id) {
        return techniqueMap[id] && techniqueMap[id].tactics.indexOf(tactic.id) !== -1;
      }) : [];
      return '<article class="dei-matrix-tactic ' + (active[tactic.id] ? "covered" : "") + '">' +
        '<div class="dei-matrix-tactic-head"><span>' + tactic.id + '</span><strong>' + escapeHtml(tactic.name) + '</strong><b>' + tactic.count + ' techniques</b></div>' +
        '<p>' + escapeHtml(tactic.description) + '</p>' +
        '<div class="dei-matrix-techniques">' + (mapped.length ? mapped.map(function (id) {
          var meta = techniqueMap[id] || {name:"Mapped technique"};
          return '<button type="button" class="dei-mapped-technique" data-technique="' + escapeHtml(id) + '"><span>' + escapeHtml(id) + '</span><strong>' + escapeHtml(meta.name) + '</strong></button>';
        }).join("") : '<small>No selected detection coverage</small>') + '</div></article>';
    }).join(""));
  }

  function renderInspector(item, focusTechnique) {
    if (!item) { return; }
    var techniques = item.mitre_techniques || [];
    var active = activeTactics(item);
    var focus = focusTechnique || techniques[0];
    var meta = focus ? techniqueMap[focus] : null;
    $("#mitre-inspector-title").text(item.name);
    var tacticCards = Object.keys(active).map(function (id) {
      var tactic = tactics.filter(function (entry) { return entry.id === id; })[0];
      return '<div class="dei-inspector-outcome"><strong>' + escapeHtml(tactic ? tactic.name : id) + '</strong><p>' + escapeHtml(protectionText[id] || "Provides defensive visibility at this ATT&CK stage.") + '</p></div>';
    }).join("");
    var techniqueCards = techniques.length ? techniques.map(function (id) {
      var t = techniqueMap[id] || {name:"Mapped ATT&CK technique", tactics:[]};
      return '<button type="button" class="dei-inspector-technique ' + (id === focus ? "active" : "") + '" data-technique="' + escapeHtml(id) + '"><span>' + escapeHtml(id) + '</span><strong>' + escapeHtml(t.name) + '</strong>' + (t.parent ? '<small>Sub-technique of ' + escapeHtml(t.parent) + '</small>' : '') + '</button>';
    }).join("") : '<p class="dei-empty">No ATT&amp;CK technique is currently mapped to this detection.</p>';
    var attackLink = focus ? "https://attack.mitre.org/techniques/" + focus.replace(".", "/") + "/" : "https://attack.mitre.org/matrices/enterprise/";
    $("#mitre-inspector-body").html(
      '<section class="dei-inspector-section"><span class="dei-protection-label">Detection state</span><div class="dei-inspector-badges"><span class="dei-readiness ' + escapeHtml(item.readiness) + '">' + escapeHtml(String(item.readiness || "unknown").replace(/_/g," ")) + '</span><span class="dei-severity ' + escapeHtml(item.severity) + '">' + escapeHtml(item.severity) + '</span><span class="dei-field-state neutral">' + escapeHtml(String(item.field_validation || "not evaluated").replace(/_/g," ")) + '</span></div></section>' +
      '<section class="dei-inspector-section"><span class="dei-protection-label">Why it matters</span><p>' + escapeHtml(item.why || "") + '</p></section>' +
      '<section class="dei-inspector-section"><span class="dei-protection-label">ATT&amp;CK techniques</span><div class="dei-inspector-techniques">' + techniqueCards + '</div><a class="dei-attack-link" target="_blank" rel="noopener noreferrer" href="' + attackLink + '">Open selected technique on MITRE ATT&amp;CK ↗</a></section>' +
      (meta ? '<section class="dei-inspector-section dei-technique-focus"><span class="dei-protection-label">Selected technique</span><h3>' + escapeHtml(focus + " · " + meta.name) + '</h3>' + (meta.parent ? '<p>Sub-technique of <strong>' + escapeHtml(meta.parent) + '</strong>.</p>' : '<p>Enterprise ATT&amp;CK technique.</p>') + '</section>' : '') +
      '<section class="dei-inspector-section"><span class="dei-protection-label">What this protects</span><div class="dei-inspector-outcomes">' + (tacticCards || '<p class="dei-empty">No tactic protection outcome available.</p>') + '</div></section>'
    );
  }

  function renderDetectionList() {
    var query = String($("#mitre-filter").val() || "").toLowerCase();
    var readiness = $("#mitre-readiness-filter").val() || "all";
    var items = report && report.recommendations ? report.recommendations.filter(function (item) {
      var matchesText = !query || (item.name + " " + item.capability + " " + (item.mitre_techniques || []).join(" ")).toLowerCase().indexOf(query) !== -1;
      var matchesReadiness = readiness === "all" || item.readiness === readiness;
      return matchesText && matchesReadiness;
    }) : [];
    $("#mitre-detection-count").text(items.length);
    $("#mitre-detection-list").html(items.length ? items.map(function (item) {
      return '<button type="button" class="dei-advisor-item ' + (selected && selected.detection_id === item.detection_id ? "selected" : "") + '" data-detection="' + escapeHtml(item.detection_id) + '"><div><span class="dei-severity ' + escapeHtml(item.severity) + '">' + escapeHtml(item.severity) + '</span><span class="dei-readiness ' + escapeHtml(item.readiness) + '">' + escapeHtml(String(item.readiness).replace(/_/g," ")) + '</span></div><strong>' + escapeHtml(item.name) + '</strong><small>' + escapeHtml((item.mitre_techniques || []).join(" · ") || "No ATT&CK mapping") + '</small></button>';
    }).join("") : '<p class="dei-empty">No detections match the current filters.</p>');
  }

  $("#mitre-filter, #mitre-readiness-filter").on("input change", renderDetectionList);
  $("#mitre-detection-list").on("click", ".dei-advisor-item", function () {
    var id = $(this).data("detection");
    selected = (report.recommendations || []).filter(function (item) { return item.detection_id === id; })[0];
    renderDetectionList(); renderMatrix(); renderInspector(selected);
  });
  $("#mitre-matrix, #mitre-inspector-body").on("click", "[data-technique]", function () {
    renderInspector(selected, $(this).data("technique"));
  });

  loadReport();
  renderDetectionList();
  if (report && report.recommendations && report.recommendations.length) { selected = report.recommendations[0]; }
  renderDetectionList(); renderMatrix(); renderInspector(selected);
});

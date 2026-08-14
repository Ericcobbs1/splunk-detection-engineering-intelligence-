require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var STORAGE_KEY = "dei.latestRecommendationReport";
  var STORAGE_TIME_KEY = "dei.latestRecommendationTime";
  var ATTACK_SNAPSHOT = "Bundled ATT&CK reference reviewed 2026-08-07";

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
    "T1110": {name:"Brute Force", tactics:["TA0006"], platforms:"Containers, ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS", summary:"Systematic credential guessing or cracking used to obtain valid account access.", detection:"Look for repeated or distributed authentication failures, unusual account targeting, and credential-use patterns that deviate from baseline.", mitigation:"Use MFA, strong password policy, account-use controls, and lockout/conditional-access protections.", version:"2.8", modified:"12 May 2026"},
    "T1110.003": {name:"Password Spraying", parent:"T1110", tactics:["TA0006"], platforms:"Containers, ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS", summary:"A small set of commonly used passwords is tried across many accounts to obtain valid credentials while reducing per-account lockout risk.", detection:"Correlate authentication failures across many identities from common infrastructure or repeated password patterns within a bounded time window.", mitigation:"Use MFA, conditional access, account-use policy, strong passwords, and carefully tuned lockout controls.", strategy:"DET0487", version:"1.8", modified:"24 October 2025"},
    "T1558.003": {name:"Kerberoasting", parent:"T1558", tactics:["TA0006"], platforms:"Windows", summary:"Service tickets are requested for SPNs so service-account material can be attacked offline and potentially expose reusable credentials.", detection:"Monitor anomalous Kerberos TGS requests, especially RC4/etype 0x17 use, unusual ticket volume, and service accounts requested outside normal baselines.", mitigation:"Prefer AES Kerberos encryption, use long managed service-account credentials, rotate secrets, and minimize service-account privilege.", strategy:"DET0157", version:"1.3", modified:"24 October 2025"},
    "T1059.001": {name:"PowerShell", parent:"T1059", tactics:["TA0002"], platforms:"Windows", summary:"PowerShell commands, scripts, or the underlying automation interfaces are abused to execute code, perform discovery, or retrieve payloads.", detection:"Inspect script-block content, encoded or obfuscated commands, unusual parent/child process relationships, remote invocation, and network activity associated with PowerShell execution.", mitigation:"Constrain administrative scripting, apply application control, enable detailed PowerShell logging, and limit privileged use.", modified:"12 May 2026"},
    "T1098": {name:"Account Manipulation", tactics:["TA0003","TA0004"], platforms:"Containers, ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS", summary:"Accounts, credentials, groups, roles, or permissions are changed to preserve access or obtain stronger privileges.", detection:"Correlate account and role changes with unusual timing, initiating principals, processes, privilege transitions, or API activity.", mitigation:"Apply least privilege, MFA, privileged-account management, user-account governance, segmentation, and tight control over account modification rights.", strategy:"DET0096", version:"2.8", modified:"12 May 2026"},
    "T1078": {name:"Valid Accounts", tactics:["TA0001","TA0003","TA0004","TA0005"], platforms:"Containers, ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS", summary:"Legitimate credentials are abused to gain access, persist, elevate privileges, or blend into normal activity.", detection:"Identify anomalous login geography, time, device, protocol, privilege use, service-account behavior, and activity inconsistent with the account baseline.", mitigation:"Use MFA, conditional access, credential rotation, privileged-account controls, and rapid retirement of inactive accounts.", strategy:"DET0560", version:"3.0", modified:"12 May 2026"},
    "T1078.004": {name:"Cloud Accounts", parent:"T1078", tactics:["TA0001","TA0003","TA0004","TA0005"], platforms:"IaaS, Identity Provider, Office Suite, SaaS", summary:"Compromised or misused cloud identities are used to access services and maintain trusted-looking access.", detection:"Look for impossible travel, legacy authentication, abnormal API scope, unusual privileged activity, and cloud-service usage that departs from the user baseline.", mitigation:"Require MFA, conditional access, modern authentication, routine privilege review, JIT access, and unique rotated credentials.", strategy:"DET0546", modified:"12 May 2026"},
    "T1562.008": {name:"Disable or Modify Cloud Log", currentId:"T1685.002", parent:"T1685", tactics:["TA0112"], platforms:"IaaS, Identity Provider, Office Suite, SaaS", summary:"Cloud logging or audit integrations are disabled or altered to reduce defensive visibility before or during malicious activity.", detection:"Alert on API or administrative events that stop, delete, downgrade, bypass, or materially change cloud audit and logging services.", mitigation:"Limit permissions to change logging, continuously validate required audit settings, and protect central log destinations from administrative tampering.", strategy:"DET0289", version:"1.0", modified:"12 May 2026", superseded:"Catalog mapping T1562.008 now resolves to current ATT&CK T1685.002."},
    "T1530": {name:"Data from Cloud Storage", tactics:["TA0009"], platforms:"IaaS, Office Suite, SaaS", summary:"Cloud object or document storage is accessed to collect sensitive organizational data.", detection:"Monitor unusual object reads, bulk downloads, atypical API access, new principals, abnormal locations, and access to sensitive storage outside established patterns.", mitigation:"Apply least privilege, private-by-default storage controls, strong identity protection, access reviews, and monitoring for public or overly broad permissions.", version:"2.2", modified:"12 May 2026"},
    "T1567": {name:"Exfiltration Over Web Service", tactics:["TA0010"], platforms:"ESXi, Linux, Office Suite, SaaS, Windows, macOS", summary:"Legitimate external web services are used as a channel to move data out of the organization and blend with expected encrypted traffic.", detection:"Look for unusual upload volume, new web-service destinations, atypical user agents, suspicious processes initiating transfers, and deviations from normal egress behavior.", mitigation:"Control approved web services, inspect egress where appropriate, apply DLP, and restrict unsanctioned external storage or webhook destinations.", version:"1.5", modified:"12 May 2026"},
    "T1021": {name:"Remote Services", tactics:["TA0008"], platforms:"ESXi, IaaS, Linux, Windows, macOS", summary:"Remote access services such as RDP, SSH, SMB, WinRM, VNC, or cloud remote services are used to move between systems or services.", detection:"Correlate remote logons with unusual source hosts, accounts, time windows, service use, privileged activity, and subsequent process execution.", mitigation:"Restrict remote administration paths, segment management networks, require MFA where supported, and limit privileged remote-service access.", version:"1.6", modified:"24 October 2025"},
    "T1548.003": {name:"Sudo and Sudo Caching", parent:"T1548", tactics:["TA0004"], platforms:"Linux, macOS", summary:"Sudo configuration, cached authorization, or elevated command execution is abused to gain higher privileges.", detection:"Monitor unusual sudo invocation, unexpected users gaining elevation, changes to sudoers policy, and privileged commands inconsistent with normal administration.", mitigation:"Restrict sudoers policy, minimize broad NOPASSWD rules, require strong authentication, and audit privileged command use.", modified:"12 May 2026"},
    "T1071.004": {name:"DNS", parent:"T1071", tactics:["TA0011"], platforms:"ESXi, Linux, Network Devices, Windows, macOS", summary:"DNS is abused for command-and-control traffic by embedding commands or data within otherwise common DNS queries and responses.", detection:"Detect high-volume or encoded subdomains, unusual query length or entropy, rare resolvers, beaconing patterns, and non-standard processes issuing DNS queries.", mitigation:"Force approved resolvers, filter untrusted domains, use DNS monitoring/NIDS, and restrict direct external DNS where practical.", strategy:"DET0400", version:"1.4", modified:"12 May 2026"},
    "T1190": {name:"Exploit Public-Facing Application", tactics:["TA0001"], platforms:"Containers, IaaS, Linux, Network Devices, Windows, macOS", summary:"Internet-facing applications or services are exploited through software weaknesses or unsafe exposed functionality to gain access.", detection:"Correlate suspicious requests and application errors with post-exploitation process creation, outbound connections, or new persistence behavior.", mitigation:"Patch exposed software rapidly, scan continuously, segment public services, minimize service-account privilege, and use protective gateway controls.", strategy:"DET0080", modified:"12 May 2026"},
    "T1041": {name:"Exfiltration Over C2 Channel", tactics:["TA0010"], platforms:"Linux, Network Devices, Windows, macOS", summary:"Data is stolen using an existing command-and-control channel instead of establishing a separate exfiltration path.", detection:"Measure unusual outbound transfer volume, encoded or staged data, beacon channels that shift to sustained transfer, and sensitive-host egress to C2 infrastructure.", mitigation:"Restrict egress, inspect known C2 patterns, segment sensitive systems, and reduce access to data that compromised processes can read."},
    "T1566": {name:"Phishing", tactics:["TA0001"], platforms:"Identity Provider, Linux, Office Suite, SaaS, Windows, macOS", summary:"Electronically delivered social engineering is used to induce a victim to open content, follow a link, call an adversary, or otherwise enable access.", detection:"Correlate suspicious inbound mail, links, attachments, sender anomalies, and subsequent endpoint or network behavior after message delivery.", mitigation:"Use secure mail controls, sender authentication, user training, attachment/link analysis, and protective isolation for untrusted content.", strategy:"DET0070", version:"2.7", modified:"12 May 2026"},
    "T1610": {name:"Deploy Container", tactics:["TA0002"], platforms:"Containers", summary:"A new container or workload is deployed to execute malicious code, bypass controls, or establish access within containerized infrastructure.", detection:"Detect unapproved images, privileged containers, risky host mounts/namespaces, unusual principals, and suspicious create-to-start-to-network or process chains.", mitigation:"Apply least privilege and RBAC, restrict privileged runtime settings, enforce approved images, segment workloads, and monitor control-plane changes.", strategy:"DET0249", version:"2.0", modified:"12 May 2026"}
  };

  var protectionText = {
    TA0001:"Protects the entry boundary by surfacing behaviors associated with gaining an initial foothold.", TA0002:"Protects workloads and endpoints by exposing malicious or unauthorized execution.",
    TA0003:"Protects long-term control of identities and systems by detecting foothold-preservation activity.", TA0004:"Protects privileged access by identifying attempts to obtain stronger permissions.",
    TA0005:"Protects analyst visibility and trust by detecting activity intended to blend in or evade scrutiny.", TA0112:"Protects defensive visibility by identifying attempts to disable, weaken, or manipulate security controls.",
    TA0006:"Protects identities and credentials from guessing, theft, cracking, and abuse.", TA0007:"Protects environment knowledge by detecting adversary enumeration and discovery behavior.",
    TA0008:"Protects trust boundaries by identifying movement between systems, accounts, and services.", TA0009:"Protects sensitive information during adversary staging and collection.",
    TA0011:"Protects communications channels by surfacing command-and-control behavior.", TA0010:"Protects data boundaries by detecting attempts to move information outside trusted systems.",
    TA0040:"Protects business operations and data from disruptive or destructive activity.", TA0043:"Provides early visibility into targeting and information-gathering activity.",
    TA0042:"Provides visibility into adversary preparation and resource establishment before intrusion activity."
  };

  var report = null;
  var selected = null;

  function escapeHtml(value) {
    return String(value == null ? "" : value).replace(/&/g,"&amp;").replace(/</g,"&lt;")
      .replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
  }

  function tacticName(id) {
    var match = tactics.filter(function (entry) { return entry.id === id; })[0];
    return match ? match.name : id;
  }

  function loadReport() {
    try { report = JSON.parse(window.sessionStorage.getItem(STORAGE_KEY) || "null"); }
    catch (error) { report = null; }
    var timestamp = Number(window.sessionStorage.getItem(STORAGE_TIME_KEY) || 0);
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
    (item && item.mitre_techniques || []).forEach(function (id) {
      var technique = techniqueMap[id];
      if (technique) { technique.tactics.forEach(function (tactic) { active[tactic] = true; }); }
    });
    return active;
  }

  function renderPortfolioCoverage() {
    var covered = {};
    var actionable = {production_ready:true, partial:true, field_gap:true, field_unverified:true};
    (report && report.recommendations || []).forEach(function (item) {
      if (!actionable[item.readiness]) { return; }
      Object.keys(activeTactics(item)).forEach(function (id) { covered[id] = true; });
    });
    var count = Object.keys(covered).length;
    var percent = Math.round((count / tactics.length) * 100);
    $("#mitre-coverage-percent").text(percent + "%");
    $("#mitre-portfolio-covered").text(count + " of " + tactics.length + " tactics");
    $("#mitre-coverage-donut").css("--mitre-coverage", percent + "%");
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
      return '<article class="dei-matrix-tactic ' + (active[tactic.id] ? "covered" : "not-applicable") + '">' +
        '<div class="dei-matrix-tactic-head"><span>' + tactic.id + '</span><strong>' + escapeHtml(tactic.name) + '</strong><b>' + tactic.count + ' techniques</b></div>' +
        '<p>' + escapeHtml(tactic.description) + '</p>' +
        '<div class="dei-matrix-techniques">' + (mapped.length ? mapped.map(function (id) {
          var meta = techniqueMap[id] || {name:"Mapped technique"};
          return '<button type="button" class="dei-mapped-technique" data-technique="' + escapeHtml(id) + '"><span>' + escapeHtml(meta.currentId || id) + '</span><strong>' + escapeHtml(meta.name) + '</strong></button>';
        }).join("") : '<small>No selected detection coverage</small>') + '</div></article>';
    }).join(""));
  }

  function renderInspector(item, focusTechnique) {
    if (!item) {
      $("#mitre-inspector-title").text("Select a detection");
      $("#mitre-inspector-body").html('<p class="dei-empty">Select a finding to inspect its offline ATT&amp;CK reference and protection outcomes.</p>');
      return;
    }
    var techniques = item.mitre_techniques || [];
    var active = activeTactics(item);
    var focus = focusTechnique || techniques[0];
    var meta = focus ? techniqueMap[focus] : null;
    $("#mitre-inspector-title").text(item.name);
    var tacticCards = Object.keys(active).map(function (id) {
      return '<div class="dei-inspector-outcome"><strong>' + escapeHtml(tacticName(id)) + '</strong><p>' + escapeHtml(protectionText[id] || "Provides defensive visibility at this ATT&CK stage.") + '</p></div>';
    }).join("");
    var techniqueCards = techniques.length ? techniques.map(function (id) {
      var t = techniqueMap[id] || {name:"Mapped ATT&CK technique", tactics:[]};
      return '<button type="button" class="dei-inspector-technique ' + (id === focus ? "active" : "") + '" data-technique="' + escapeHtml(id) + '"><span>' + escapeHtml(t.currentId || id) + '</span><strong>' + escapeHtml(t.name) + '</strong>' + (t.parent ? '<small>Sub-technique of ' + escapeHtml(t.parent) + '</small>' : '') + '</button>';
    }).join("") : '<p class="dei-empty">No ATT&amp;CK technique is currently mapped to this detection.</p>';
    var liveId = meta && meta.currentId ? meta.currentId : focus;
    var attackLink = liveId ? "https://attack.mitre.org/techniques/" + liveId.replace(".", "/") + "/" : "https://attack.mitre.org/matrices/enterprise/";
    var buildable = ["production_ready","field_unverified","field_gap"].indexOf(item.readiness) !== -1;
    var nextHref = buildable ? "detection_workflow?detection=" + encodeURIComponent(item.detection_id) : "command_center#dei-telemetry";
    var nextLabel = buildable ? "Build this detection" : "Resolve telemetry gaps";
    var nextDetail = buildable ? "Generate SPL, scheduling guidance, and validation evidence." : "Run a new scan after onboarding the required telemetry.";
    var observedSourcetypes = observedSourcetypesForDetection(item);
    var improvementGuidance = [];
    if (!techniques.length) { improvementGuidance.push("Add a reviewed ATT&CK technique mapping before peer review."); }
    if (item.readiness === "field_gap") { improvementGuidance.push("Resolve the reported field gaps or add reviewed field aliases before treating this detection as production ready."); }
    if (item.readiness === "field_unverified") { improvementGuidance.push("Run representative field validation against the observed logs and document the verified fields."); }
    if (item.readiness === "partial") { improvementGuidance.push("Add the missing telemetry source or narrow the SPL to the log sources that are currently observable."); }
    if (!observedSourcetypes.length) { improvementGuidance.push("Confirm the required log source is onboarded and producing current events before building."); }
    if (meta && meta.detection) { improvementGuidance.push(meta.detection); }
    if (!improvementGuidance.length) { improvementGuidance.push("Preserve the current mapping, then validate thresholds, entities, and false-positive behavior against representative logs."); }
    var improvementCards = improvementGuidance.map(function (guidance) {
      return '<li>' + escapeHtml(guidance) + '</li>';
    }).join("");
    var offlineReference = meta ? [
      '<section class="dei-offline-reference">',
      '<div class="dei-offline-reference-head"><div><span class="dei-protection-label">Offline ATT&amp;CK reference</span><h3>', escapeHtml((meta.currentId || focus) + " · " + meta.name), '</h3></div><span class="dei-offline-badge">Bundled</span></div>',
      meta.superseded ? '<p class="dei-framework-notice">' + escapeHtml(meta.superseded) + '</p>' : '',
      '<div class="dei-reference-grid">',
      '<div><span>Tactic(s)</span><strong>', escapeHtml((meta.tactics || []).map(tacticName).join(" · ")), '</strong></div>',
      '<div><span>Platforms</span><strong>', escapeHtml(meta.platforms || "See live ATT&CK record"), '</strong></div>',
      meta.strategy ? '<div><span>Detection strategy</span><strong>' + escapeHtml(meta.strategy) + '</strong></div>' : '',
      meta.version ? '<div><span>ATT&CK version</span><strong>' + escapeHtml(meta.version) + '</strong></div>' : '',
      '</div>',
      '<div class="dei-reference-narrative"><span>Behavior</span><p>', escapeHtml(meta.summary || "Bundled behavior summary not available."), '</p></div>',
      '<div class="dei-reference-narrative"><span>Detection guidance</span><p>', escapeHtml(meta.detection || "Use the detection rationale and required telemetry shown by DEI."), '</p></div>',
      '<div class="dei-reference-narrative"><span>Mitigation themes</span><p>', escapeHtml(meta.mitigation || "Apply least privilege, strong identity controls, segmentation, and monitoring appropriate to this behavior."), '</p></div>',
      '<p class="dei-snapshot-note">', escapeHtml(ATTACK_SNAPSHOT + (meta.modified ? " · MITRE last-modified metadata: " + meta.modified : "")), '. The live MITRE record is authoritative and may contain newer revisions.</p>',
      '</section>'
    ].join("") : '<section class="dei-offline-reference"><p class="dei-empty">No bundled ATT&amp;CK reference exists for this mapping yet.</p></section>';

    $("#mitre-inspector-body").html(
      '<div class="dei-inspector-columns">' +
      '<div class="dei-inspector-primary">' +
      '<section class="dei-inspector-section"><span class="dei-protection-label">Detection state</span><div class="dei-inspector-badges"><span class="dei-readiness ' + escapeHtml(item.readiness) + '">' + escapeHtml(String(item.readiness || "unknown").replace(/_/g," ")) + '</span><span class="dei-severity ' + escapeHtml(item.severity) + '">' + escapeHtml(item.severity) + '</span><span class="dei-field-state neutral">' + escapeHtml(String(item.field_validation || "not evaluated").replace(/_/g," ")) + '</span></div></section>' +
      '<section class="dei-inspector-section"><span class="dei-protection-label">Why it matters</span><p>' + escapeHtml(item.why || "") + '</p></section>' +
      '<section class="dei-inspector-section dei-mitre-improvements"><span class="dei-protection-label">Recommended detection improvements</span><p>Based on the selected mapping, readiness state, and observed log sources:</p><ul>' + improvementCards + '</ul><small>Observed sourcetypes: ' + escapeHtml(observedSourcetypes.join(" · ") || "none verified") + '</small></section>' +
      '<section class="dei-inspector-section"><span class="dei-protection-label">Mapped techniques</span><div class="dei-inspector-techniques">' + techniqueCards + '</div></section>' +
      '<section class="dei-inspector-section"><span class="dei-protection-label">What this protects</span><div class="dei-inspector-outcomes">' + (tacticCards || '<p class="dei-empty">No tactic protection outcome available.</p>') + '</div></section>' +
      '</div>' +
      '<div class="dei-inspector-reference">' + offlineReference +
      '<a class="dei-attack-live-button" target="_blank" rel="noopener noreferrer" href="' + attackLink + '"><span>Open live MITRE ATT&amp;CK</span><b>↗</b></a>' +
      '<p class="dei-live-link-note">Internet access is optional. Use this button for additional live framework detail when the search head can reach attack.mitre.org.</p>' +
      '<a class="dei-mitre-next-action" href="' + nextHref + '"><span><strong>' + nextLabel + '</strong><br>' + nextDetail + '</span><b>→</b></a>' +
      '</div></div>'
    );
  }

  function sourceMappings() {
    return report && report.source_mappings ? report.source_mappings : [];
  }

  function canonicalSourcesForObserved(observedSource) {
    var selectedMapping = sourceMappings().filter(function (mapping) {
      return String(mapping.observed_source || "").toLowerCase() ===
        String(observedSource || "").toLowerCase();
    })[0];
    if (!selectedMapping) { return []; }
    return [selectedMapping.canonical_source].concat(
      selectedMapping.additional_canonical_sources || []
    ).map(function (source) { return String(source || "").toLowerCase(); });
  }

  function observedSourcetypesForDetection(item) {
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

  function populateSourcetypeFilter() {
    var current = $("#mitre-sourcetype-filter").val() || "all";
    var values = {};
    sourceMappings().forEach(function (mapping) {
      var observed = String(mapping.observed_source || "").trim();
      if (observed) { values[observed.toLowerCase()] = observed; }
    });
    var options = Object.keys(values).sort().map(function (key) {
      var value = values[key];
      return '<option value="' + escapeHtml(value) + '">' + escapeHtml(value) + '</option>';
    }).join("");
    $("#mitre-sourcetype-filter").html('<option value="all">All sourcetypes</option>' + options);
    if (current === "all" || values[String(current).toLowerCase()]) {
      $("#mitre-sourcetype-filter").val(current);
    }
  }

  function renderDetectionList() {
    var query = String($("#mitre-filter").val() || "").toLowerCase();
    var readiness = $("#mitre-readiness-filter").val() || "all";
    var sourcetype = $("#mitre-sourcetype-filter").val() || "all";
    var selectedCanonical = sourcetype === "all" ? [] : canonicalSourcesForObserved(sourcetype);
    var items = report && report.recommendations ? report.recommendations.filter(function (item) {
      var matchesText = !query || (item.name + " " + item.capability + " " + (item.mitre_techniques || []).join(" ")).toLowerCase().indexOf(query) !== -1;
      var matchesReadiness = readiness === "all" || item.readiness === readiness;
      var observedCanonical = (item.observed_sources || []).map(function (source) {
        return String(source || "").toLowerCase();
      });
      var matchesSourcetype = sourcetype === "all" || selectedCanonical.some(function (source) {
        return observedCanonical.indexOf(source) !== -1;
      });
      return matchesText && matchesReadiness && matchesSourcetype;
    }) : [];

    if (selected && !items.some(function (item) { return item.detection_id === selected.detection_id; })) {
      selected = items.length ? items[0] : null;
      renderMatrix();
      renderInspector(selected);
    }

    $("#mitre-detection-count").text(items.length);
    $("#mitre-detection-list").html(items.length ? items.map(function (item) {
      var observedSourcetypes = observedSourcetypesForDetection(item);
      return '<button type="button" class="dei-advisor-item ' + (selected && selected.detection_id === item.detection_id ? "selected" : "") + '" data-detection="' + escapeHtml(item.detection_id) + '"><div><span class="dei-severity ' + escapeHtml(item.severity) + '">' + escapeHtml(item.severity) + '</span><span class="dei-readiness ' + escapeHtml(item.readiness) + '">' + escapeHtml(String(item.readiness).replace(/_/g," ")) + '</span></div><strong>' + escapeHtml(item.name) + '</strong><small class="dei-advisor-sources">Sourcetype: ' + escapeHtml(observedSourcetypes.join(" · ") || "No observed source") + '</small><small>' + escapeHtml((item.mitre_techniques || []).map(function (id) { return techniqueMap[id] && techniqueMap[id].currentId ? techniqueMap[id].currentId : id; }).join(" · ") || "No ATT&CK mapping") + '</small></button>';
    }).join("") : '<p class="dei-empty">No detections match the current filters.</p>');
  }

  $("#mitre-filter, #mitre-readiness-filter, #mitre-sourcetype-filter").on("input change", renderDetectionList);
  $("#mitre-detection-list").on("click", ".dei-advisor-item", function () {
    var id = $(this).data("detection");
    selected = (report.recommendations || []).filter(function (item) { return item.detection_id === id; })[0];
    renderDetectionList(); renderMatrix(); renderInspector(selected);
    $(document).trigger("dei:advisor-detection-selected",[id]);
  });
  $("#mitre-matrix, #mitre-inspector-body").on("click", "[data-technique]", function () {
    renderInspector(selected, $(this).data("technique"));
  });

  loadReport();
  populateSourcetypeFilter();
  renderPortfolioCoverage();
  renderDetectionList();
  if (report && report.recommendations && report.recommendations.length) { selected = report.recommendations[0]; }
  renderDetectionList(); renderMatrix(); renderInspector(selected);
});

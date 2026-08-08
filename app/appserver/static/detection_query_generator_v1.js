require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var ARTIFACT_KEY = "dei.detectionDraftArtifacts";
  var ES_KEY = "dei.latestEnterpriseSecurityEnabled";
  var REPORT_KEY = "dei.latestRecommendationReport";
  var SELECTED_DETECTION_KEY = "dei.selectedDetectionDraft";
  var selected = null;

  function safeJson(value, fallback) {
    try { return JSON.parse(value || "null") || fallback; } catch (error) { return fallback; }
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value).replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function quote(value) {
    return '"' + String(value || "").replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  }

  function observedSourcetypes(item, report) {
    var canonical = (item.observed_sources || []).map(function (source) {
      return String(source || "").toLowerCase();
    });
    return (report.source_mappings || []).filter(function (mapping) {
      return [mapping.canonical_source].concat(mapping.additional_canonical_sources || [])
        .some(function (source) { return canonical.indexOf(String(source || "").toLowerCase()) !== -1; });
    }).map(function (mapping) { return mapping.observed_source; });
  }

  function sourceClause(sources) {
    return sources.map(function (source) { return "sourcetype=" + quote(source); }).join(" OR ");
  }

  function normalizedPrelude(item) {
    var id = item.detection_id;
    if (/password-spray|mfa-failure|ssh-bruteforce/.test(id)) {
      return "| eval user=coalesce(user, TargetUserName, user_name, src_user, 'actor.alternateId'), src_ip=coalesce(src_ip, IpAddress, source_ip, client_ip), action=lower(coalesce(action, status, result, 'outcome.result'))";
    }
    if (/powershell/.test(id)) {
      return "| eval user=coalesce(user, UserName), process=coalesce(process_name, Image, file_name), command_line=coalesce(command_line, CommandLine, process_command_line, ScriptBlockText)";
    }
    if (/dns/.test(id)) {
      return "| eval query=coalesce(query, query_name, domain), src_ip=coalesce(src_ip, client_ip), answer=coalesce(answer, response, dest_ip)";
    }
    if (/firewall/.test(id)) {
      return "| eval src_ip=coalesce(src_ip, source_ip), dest_ip=coalesce(dest_ip, destination_ip), dest_port=coalesce(dest_port, destination_port), action=lower(coalesce(action, result))";
    }
    if (/web-anomalous/.test(id)) {
      return "| eval method=upper(coalesce(method, http_method)), uri=coalesce(uri, uri_path, url, request_uri), src_ip=coalesce(src_ip, clientip, client_ip)";
    }
    if (/iam|cloudtrail|s3/.test(id)) {
      return "| eval action=coalesce(eventName, event_name), user=coalesce('userIdentity.arn','userIdentity.userName','userIdentity.sessionContext.sessionIssuer.userName',user_arn,user), src_ip=coalesce(sourceIPAddress,src_ip), object=coalesce('requestParameters.bucketName',bucket_name,bucket)";
    }
    if (/guardduty|securityhub/.test(id)) {
      return "| eval finding_severity=upper(coalesce('Severity.Label',severity)), account=coalesce(accountId,account_id), resource=coalesce('resource.resourceType',resourceType,resource_type,ProductArn,product_arn)";
    }
    if (/admin-change|privilege-grant|model-admin|config-change|sensitive-api/.test(id)) {
      return "| eval action=coalesce(action,eventName,event_name,operationName,operation_name,Operation,operation,methodName,'protoPayload.methodName',events.name,verb,command), user=coalesce(user,caller,Caller,actor,'actor.email','protoPayload.authenticationInfo.principalEmail','actor.alternateId'), object=coalesce(target,target_user,'target.alternateId',resource,resourceId,resource_id,resourceName,'objectRef.resource',host,device)";
    }
    return "";
  }

  function analyticLogic(item) {
    var id = item.detection_id;
    if (id === "windows-password-spray") {
      return "| where EventCode=4625 OR event_id=4625\n| bin _time span=5m\n| stats count dc(user) AS targeted_accounts values(user) AS users by _time src_ip\n| where count>=10 AND targeted_accounts>=5";
    }
    if (id === "windows-kerberoasting") {
      return "| where EventCode=4769 OR event_id=4769\n| eval encryption=coalesce(TicketEncryptionType,ticket_encryption_type)\n| where encryption IN (\"0x17\",\"23\")\n| stats count dc(ServiceName) AS services values(ServiceName) AS service_names by user src_ip\n| where count>=5";
    }
    if (/powershell/.test(id)) {
      return "| where match(lower(command_line), \"(-enc\\\\s|encodedcommand|frombase64string|invoke-expression|downloadstring|hidden)\")\n| table _time host user process command_line";
    }
    if (/mfa-failure|ssh-bruteforce/.test(id)) {
      return "| where match(action, \"fail|deny|reject|invalid\")\n| bin _time span=5m\n| stats count dc(user) AS targeted_accounts values(user) AS users by _time src_ip\n| where count>=10";
    }
    if (id === "endpoint-remote-logon") {
      return "| eval user=coalesce(user,UserName), src_ip=coalesce(src_ip,RemoteAddress,SourceIP), logon_type=coalesce(logon_type,event_type,EventType)\n| where logon_type IN (\"3\",\"10\",3,10)\n| stats count values(host) AS destinations by user src_ip\n| where count>=3";
    }
    if (id === "dns-suspicious-resolution") {
      return "| eval query_length=len(query), label_count=mvcount(split(query,\".\"))\n| stats count dc(answer) AS answer_count avg(query_length) AS avg_query_length by src_ip query\n| where count>=20 OR avg_query_length>=55 OR answer_count>=10";
    }
    if (id === "firewall-risky-inbound") {
      return "| where action IN (\"allowed\",\"accept\",\"permit\") AND dest_port IN (22,23,3389,445,5985,5986,1433,3306,5432)\n| stats count dc(dest_ip) AS destinations values(dest_port) AS ports by src_ip\n| where count>=5";
    }
    if (id === "web-anomalous-post-volume") {
      return "| where method=\"POST\"\n| bin _time span=10m\n| stats count sum(bytes_out) AS bytes_out dc(uri) AS uri_count by _time src_ip\n| where count>=100 OR bytes_out>=50000000";
    }
    if (id === "aws-cloudtrail-disabled") {
      return "| where action IN (\"StopLogging\",\"DeleteTrail\",\"UpdateTrail\",\"PutEventSelectors\")\n| table _time user src_ip action object";
    }
    if (id === "aws-iam-policy-escalation") {
      return "| where action IN (\"AttachUserPolicy\",\"AttachRolePolicy\",\"PutUserPolicy\",\"PutRolePolicy\",\"CreatePolicyVersion\",\"SetDefaultPolicyVersion\",\"UpdateAssumeRolePolicy\",\"AddUserToGroup\")\n| table _time user src_ip action object";
    }
    if (id === "aws-s3-public-access") {
      return "| where action IN (\"PutBucketAcl\",\"PutBucketPolicy\",\"DeletePublicAccessBlock\",\"PutBucketPublicAccessBlock\")\n| table _time user src_ip action object";
    }
    if (/guardduty/.test(id)) {
      return "| where tonumber(severity)>=7\n| table _time account resource severity type title";
    }
    if (/securityhub/.test(id)) {
      return "| where finding_severity IN (\"CRITICAL\",\"HIGH\")\n| table _time resource finding_severity Workflow.Status Title";
    }
    if (id === "ai-sensitive-data-exposure") {
      return "| eval user=coalesce(user,src_user), content=coalesce(prompt,message,request_body), classification=coalesce(classification,category,policy,rule_name), action=lower(coalesce(action,verdict,result))\n| where isnotnull(content) AND isnotnull(classification) AND NOT action IN (\"blocked\",\"deny\",\"denied\")\n| stats count values(classification) AS classifications by user dest";
    }
    if (id === "ai-shadow-usage") {
      return "| eval user=coalesce(user,src_user), destination=lower(coalesce(url,dest,host))\n| where match(destination,\"openai|anthropic|claude|gemini|copilot|perplexity\")\n| stats count values(destination) AS ai_services by user";
    }
    if (id === "threat-intel-observable-match") {
      return "| eval observable=coalesce(indicator,value,ioc), observable_type=coalesce(type,indicator_type,ioc_type)\n| where isnotnull(observable)\n| stats latest(_time) AS last_seen values(source) AS intelligence_sources by observable observable_type";
    }
    if (id === "es-risk-score-spike") {
      return "| eval score=coalesce(calculated_risk_score,risk_score)\n| bin _time span=30m\n| stats sum(score) AS risk_score values(search_name) AS contributing_detections by _time risk_object risk_object_type\n| where risk_score>=100";
    }
    if (id === "salesforce-session-anomaly") {
      return "| eval src_ip=coalesce(CLIENT_IP,client_ip,src_ip), user_agent=coalesce(USER_AGENT,user_agent)\n| stats dc(src_ip) AS source_count dc(user_agent) AS agent_count values(src_ip) AS sources by SESSION_KEY LOGIN_KEY\n| where source_count>=3 OR agent_count>=3";
    }
    if (id === "m365-message-trace-anomaly") {
      return "| eval sender=coalesce(SenderAddress,sender), recipient=coalesce(RecipientAddress,recipient), status=coalesce(Status,status)\n| bin _time span=15m\n| stats count dc(recipient) AS recipients values(status) AS statuses by _time sender\n| where count>=100 OR recipients>=50";
    }
    if (/admin-change|privilege-grant|model-admin|config-change|sensitive-api|sudo-shell/.test(id)) {
      return "| where isnotnull(action)\n| stats count values(action) AS actions values(object) AS objects by user src_ip\n| where count>=1";
    }
    return "| stats count earliest(_time) AS first_seen latest(_time) AS last_seen values(host) AS hosts by sourcetype\n| where count>=1";
  }

  function schedule(item) {
    if (item.severity === "critical") { return {cron:"*/5 * * * *", earliest:"-10m@m", latest:"-2m@m"}; }
    if (item.severity === "high") { return {cron:"*/10 * * * *", earliest:"-15m@m", latest:"-2m@m"}; }
    if (/anomal|rare|spike/.test(item.detection_id)) { return {cron:"15 * * * *", earliest:"-70m@m", latest:"-10m@m"}; }
    return {cron:"*/15 * * * *", earliest:"-20m@m", latest:"-2m@m"};
  }

  function buildArtifact(item) {
    var report = safeJson(window.localStorage.getItem(REPORT_KEY), {});
    var sources = observedSourcetypes(item, report);
    var timing = schedule(item);
    var spl = "search (" + sourceClause(sources) + ") earliest=" + timing.earliest + " latest=" + timing.latest +
      "\n" + normalizedPrelude(item) + "\n" + analyticLogic(item);
    var esEnabled = window.localStorage.getItem(ES_KEY) === "true";
    var riskScore = item.severity === "critical" ? 80 : item.severity === "high" ? 60 : item.severity === "medium" ? 40 : 20;
    return {
      schema_version:"1.0.0", id:"dei-" + item.detection_id, name:item.name, status:"draft",
      description:item.why, severity:item.severity, capability:item.capability,
      sourcetypes:sources, mitre_attack:item.mitre_techniques || [], spl:spl,
      schedule:timing, generated_at:new Date().toISOString(), enterprise_security: esEnabled ? {
        app:"SplunkEnterpriseSecuritySuite", search_type:"Correlation", security_domain:
          item.pack_id === "network" ? "network" : item.pack_id === "identity" ? "identity" : item.pack_id === "endpoint" || item.pack_id === "windows" ? "endpoint" : "threat",
        alert_type:"always", alert_comparator:"greater than", alert_threshold:"0",
        notable_enabled:true, notable_title:item.name, notable_description:item.why,
        notable_severity:item.severity, mitre_attack:item.mitre_techniques || [],
        risk_based_alerting:{enabled:true, risk_score:riskScore,
          risk_object_field:/identity|windows|m365|google_workspace/.test(item.pack_id) ? "user" : "src_ip",
          risk_object_type:/identity|windows|m365|google_workspace/.test(item.pack_id) ? "user" : "system",
          message:item.name + " detected for $risk_object$"},
        drilldown_search:spl, disabled:true
      } : null
    };
  }

  function renderArtifact(artifact) {
    var es = artifact.enterprise_security;
    $("#generator-empty").hide();
    $("#generator-output").show();
    $("#generator-title").text(artifact.name);
    $("#generator-badges").html('<span>' + escapeHtml(artifact.status) + '</span><span>' +
      escapeHtml(artifact.severity) + '</span><span>' + escapeHtml(artifact.mitre_attack.join(" · ") || "No MITRE mapping") + '</span>');
    $("#generator-schedule").text(artifact.schedule.cron);
    $("#generator-window").text(artifact.schedule.earliest + " → " + artifact.schedule.latest);
    $("#generator-spl").text(artifact.spl);
    $("#generator-es-state").text(es ? "Enterprise Security configuration ready" : "Platform SPL · ES enhancement unavailable");
    $("#generator-es-output").html(es ? [
      "<dl>",
      "<dt>Security domain</dt><dd>", escapeHtml(es.security_domain), "</dd>",
      "<dt>Notable / Finding</dt><dd>Enabled · ", escapeHtml(es.notable_severity), "</dd>",
      "<dt>Risk-based alerting</dt><dd>", escapeHtml(es.risk_based_alerting.risk_score), " points against ",
      escapeHtml(es.risk_based_alerting.risk_object_field), "</dd>",
      "<dt>Deployment state</dt><dd>Disabled draft · analyst approval required</dd>",
      "</dl>"
    ].join("") : '<p>Enable Enterprise Security during environment analysis to generate correlation-search, finding/notable, and RBA parameters.</p>');
    selected = artifact;
  }

  function saveArtifact(artifact) {
    var artifacts = safeJson(window.localStorage.getItem(ARTIFACT_KEY), []);
    artifacts = artifacts.filter(function (entry) { return entry.id !== artifact.id; });
    artifacts.push(artifact);
    window.localStorage.setItem(ARTIFACT_KEY, JSON.stringify(artifacts));
    $(document).trigger("dei:detection-artifacts-changed", [artifacts]);
  }

  function copyText(value, button) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(function () {
        var original = button.text(); button.text("Copied");
        window.setTimeout(function () { button.text(original); }, 1200);
      });
    }
  }

  function readyRecommendations() {
    var report = safeJson(window.localStorage.getItem(REPORT_KEY), {});
    return (report.recommendations || []).filter(function (item) {
      return item.readiness === "production_ready";
    });
  }

  function requestedDetectionId() {
    var match = String(window.location.search || "").match(/[?&]detection=([^&]+)/);
    if (match) {
      try { return decodeURIComponent(match[1].replace(/\+/g, " ")); } catch (error) { return match[1]; }
    }
    return String(window.localStorage.getItem(SELECTED_DETECTION_KEY) || "");
  }

  function populateDetectionSelector() {
    var items = readyRecommendations();
    var requested = requestedDetectionId();
    $("#builder-ready-count").text(items.length + " ready");
    $("#builder-detection-select").html('<option value="">Select a telemetry-ready detection</option>' +
      items.map(function (item) {
        return '<option value="' + escapeHtml(item.detection_id) + '">' +
          escapeHtml(item.name + " · " + item.severity + " · " + (item.mitre_techniques || []).join(", ")) +
          "</option>";
      }).join(""));
    if (requested && items.some(function (item) { return item.detection_id === requested; })) {
      $("#builder-detection-select").val(requested);
      $("#builder-generate").prop("disabled", false);
      generateSelectedDetection();
    } else {
      $("#builder-generate").prop("disabled", true);
    }
  }

  function generateSelectedDetection() {
    var id = String($("#builder-detection-select").val() || "");
    var item = readyRecommendations().filter(function (candidate) {
      return candidate.detection_id === id;
    })[0];
    if (!item) { return; }
    try { window.localStorage.setItem(SELECTED_DETECTION_KEY, id); } catch (error) {
      // Generation remains available when browser storage is unavailable.
    }
    var artifact = buildArtifact(item);
    saveArtifact(artifact);
    renderArtifact(artifact);
  }

  $("#builder-detection-select").on("change", function () {
    $("#builder-generate").prop("disabled", !$(this).val());
  });
  $("#builder-generate").on("click", generateSelectedDetection);
  $("#lifecycle-workspace-menu").on("change", function () {
    var destination = String($(this).val() || "");
    if (destination && destination !== "detection_builder") { window.location.href = destination; }
  });

  $("#copy-generated-spl").on("click", function () { if (selected) { copyText(selected.spl, $(this)); } });
  $("#copy-generated-json").on("click", function () { if (selected) { copyText(JSON.stringify(selected, null, 2), $(this)); } });
  $("#download-generated-json").on("click", function () {
    if (!selected) { return; }
    var blob = new Blob([JSON.stringify(selected, null, 2)], {type:"application/json"});
    var link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = selected.id + ".json";
    link.click();
    window.setTimeout(function () { URL.revokeObjectURL(link.href); }, 0);
  });

  populateDetectionSelector();
});

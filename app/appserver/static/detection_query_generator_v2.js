require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var ARTIFACT_KEY = "dei.detectionDraftArtifacts";
  var ES_KEY = "dei.latestEnterpriseSecurityEnabled";
  var REPORT_KEY = "dei.latestRecommendationReport";
  var SELECTED_DETECTION_KEY = "dei.selectedDetectionDraft";
  var VALIDATION_RESULT_LIMIT = 25;
  var VALIDATION_TIMEOUT_MS = 60000;
  var ATTACK_SNAPSHOT = "MITRE ATT&CK Enterprise bundled reference reviewed 2026-08-07";
  var MITRE_TACTIC_NAMES = {"TA0043":"Reconnaissance","TA0042":"Resource Development","TA0001":"Initial Access","TA0002":"Execution","TA0003":"Persistence","TA0004":"Privilege Escalation","TA0005":"Defense Evasion","TA0112":"Defense Evasion","TA0006":"Credential Access","TA0007":"Discovery","TA0008":"Lateral Movement","TA0009":"Collection","TA0011":"Command and Control","TA0010":"Exfiltration","TA0040":"Impact"};
  var MITRE_REFERENCE = {"T1021":{"name":"Remote Services","tactics":["TA0008"],"platforms":"ESXi, IaaS, Linux, Windows, macOS","summary":"Remote access services such as RDP, SSH, SMB, WinRM, VNC, or cloud remote services are used to move between systems or services.","detection":"Correlate remote logons with unusual source hosts, accounts, time windows, service use, privileged activity, and subsequent process execution.","mitigation":"Restrict remote administration paths, segment management networks, require MFA where supported, and limit privileged remote-service access.","version":"1.6","modified":"24 October 2025"},"T1041":{"name":"Exfiltration Over C2 Channel","tactics":["TA0010"],"platforms":"Linux, Network Devices, Windows, macOS","summary":"Data is stolen using an existing command-and-control channel instead of establishing a separate exfiltration path.","detection":"Measure unusual outbound transfer volume, encoded or staged data, beacon channels that shift to sustained transfer, and sensitive-host egress to C2 infrastructure.","mitigation":"Restrict egress, inspect known C2 patterns, segment sensitive systems, and reduce access to data that compromised processes can read."},"T1059.001":{"name":"PowerShell","parent":"T1059","tactics":["TA0002"],"platforms":"Windows","summary":"PowerShell commands, scripts, or the underlying automation interfaces are abused to execute code, perform discovery, or retrieve payloads.","detection":"Inspect script-block content, encoded or obfuscated commands, unusual parent/child process relationships, remote invocation, and network activity associated with PowerShell execution.","mitigation":"Constrain administrative scripting, apply application control, enable detailed PowerShell logging, and limit privileged use.","modified":"12 May 2026"},"T1071.004":{"name":"DNS","parent":"T1071","tactics":["TA0011"],"platforms":"ESXi, Linux, Network Devices, Windows, macOS","summary":"DNS is abused for command-and-control traffic by embedding commands or data within otherwise common DNS queries and responses.","detection":"Detect high-volume or encoded subdomains, unusual query length or entropy, rare resolvers, beaconing patterns, and non-standard processes issuing DNS queries.","mitigation":"Force approved resolvers, filter untrusted domains, use DNS monitoring/NIDS, and restrict direct external DNS where practical.","strategy":"DET0400","version":"1.4","modified":"12 May 2026"},"T1078":{"name":"Valid Accounts","tactics":["TA0001","TA0003","TA0004","TA0005"],"platforms":"Containers, ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS","summary":"Legitimate credentials are abused to gain access, persist, elevate privileges, or blend into normal activity.","detection":"Identify anomalous login geography, time, device, protocol, privilege use, service-account behavior, and activity inconsistent with the account baseline.","mitigation":"Use MFA, conditional access, credential rotation, privileged-account controls, and rapid retirement of inactive accounts.","strategy":"DET0560","version":"3.0","modified":"12 May 2026"},"T1078.004":{"name":"Cloud Accounts","parent":"T1078","tactics":["TA0001","TA0003","TA0004","TA0005"],"platforms":"IaaS, Identity Provider, Office Suite, SaaS","summary":"Compromised or misused cloud identities are used to access services and maintain trusted-looking access.","detection":"Look for impossible travel, legacy authentication, abnormal API scope, unusual privileged activity, and cloud-service usage that departs from the user baseline.","mitigation":"Require MFA, conditional access, modern authentication, routine privilege review, JIT access, and unique rotated credentials.","strategy":"DET0546","modified":"12 May 2026"},"T1098":{"name":"Account Manipulation","tactics":["TA0003","TA0004"],"platforms":"Containers, ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS","summary":"Accounts, credentials, groups, roles, or permissions are changed to preserve access or obtain stronger privileges.","detection":"Correlate account and role changes with unusual timing, initiating principals, processes, privilege transitions, or API activity.","mitigation":"Apply least privilege, MFA, privileged-account management, user-account governance, segmentation, and tight control over account modification rights.","strategy":"DET0096","version":"2.8","modified":"12 May 2026"},"T1110":{"name":"Brute Force","tactics":["TA0006"],"platforms":"Containers, ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS","summary":"Systematic credential guessing or cracking used to obtain valid account access.","detection":"Look for repeated or distributed authentication failures, unusual account targeting, and credential-use patterns that deviate from baseline.","mitigation":"Use MFA, strong password policy, account-use controls, and lockout/conditional-access protections.","version":"2.8","modified":"12 May 2026"},"T1110.003":{"name":"Password Spraying","parent":"T1110","tactics":["TA0006"],"platforms":"Containers, ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS","summary":"A small set of commonly used passwords is tried across many accounts to obtain valid credentials while reducing per-account lockout risk.","detection":"Correlate authentication failures across many identities from common infrastructure or repeated password patterns within a bounded time window.","mitigation":"Use MFA, conditional access, account-use policy, strong passwords, and carefully tuned lockout controls.","strategy":"DET0487","version":"1.8","modified":"24 October 2025"},"T1190":{"name":"Exploit Public-Facing Application","tactics":["TA0001"],"platforms":"Containers, IaaS, Linux, Network Devices, Windows, macOS","summary":"Internet-facing applications or services are exploited through software weaknesses or unsafe exposed functionality to gain access.","detection":"Correlate suspicious requests and application errors with post-exploitation process creation, outbound connections, or new persistence behavior.","mitigation":"Patch exposed software rapidly, scan continuously, segment public services, minimize service-account privilege, and use protective gateway controls.","strategy":"DET0080","modified":"12 May 2026"},"T1530":{"name":"Data from Cloud Storage","tactics":["TA0009"],"platforms":"IaaS, Office Suite, SaaS","summary":"Cloud object or document storage is accessed to collect sensitive organizational data.","detection":"Monitor unusual object reads, bulk downloads, atypical API access, new principals, abnormal locations, and access to sensitive storage outside established patterns.","mitigation":"Apply least privilege, private-by-default storage controls, strong identity protection, access reviews, and monitoring for public or overly broad permissions.","version":"2.2","modified":"12 May 2026"},"T1548.003":{"name":"Sudo and Sudo Caching","parent":"T1548","tactics":["TA0004"],"platforms":"Linux, macOS","summary":"Sudo configuration, cached authorization, or elevated command execution is abused to gain higher privileges.","detection":"Monitor unusual sudo invocation, unexpected users gaining elevation, changes to sudoers policy, and privileged commands inconsistent with normal administration.","mitigation":"Restrict sudoers policy, minimize broad NOPASSWD rules, require strong authentication, and audit privileged command use.","modified":"12 May 2026"},"T1558.003":{"name":"Kerberoasting","parent":"T1558","tactics":["TA0006"],"platforms":"Windows","summary":"Service tickets are requested for SPNs so service-account material can be attacked offline and potentially expose reusable credentials.","detection":"Monitor anomalous Kerberos TGS requests, especially RC4/etype 0x17 use, unusual ticket volume, and service accounts requested outside normal baselines.","mitigation":"Prefer AES Kerberos encryption, use long managed service-account credentials, rotate secrets, and minimize service-account privilege.","strategy":"DET0157","version":"1.3","modified":"24 October 2025"},"T1562.008":{"name":"Disable or Modify Cloud Log","currentId":"T1685.002","parent":"T1685","tactics":["TA0112"],"platforms":"IaaS, Identity Provider, Office Suite, SaaS","summary":"Cloud logging or audit integrations are disabled or altered to reduce defensive visibility before or during malicious activity.","detection":"Alert on API or administrative events that stop, delete, downgrade, bypass, or materially change cloud audit and logging services.","mitigation":"Limit permissions to change logging, continuously validate required audit settings, and protect central log destinations from administrative tampering.","strategy":"DET0289","version":"1.0","modified":"12 May 2026","superseded":"Catalog mapping T1562.008 now resolves to current ATT&CK T1685.002."},"T1566":{"name":"Phishing","tactics":["TA0001"],"platforms":"Identity Provider, Linux, Office Suite, SaaS, Windows, macOS","summary":"Electronically delivered social engineering is used to induce a victim to open content, follow a link, call an adversary, or otherwise enable access.","detection":"Correlate suspicious inbound mail, links, attachments, sender anomalies, and subsequent endpoint or network behavior after message delivery.","mitigation":"Use secure mail controls, sender authentication, user training, attachment/link analysis, and protective isolation for untrusted content.","strategy":"DET0070","version":"2.7","modified":"12 May 2026"},"T1567":{"name":"Exfiltration Over Web Service","tactics":["TA0010"],"platforms":"ESXi, Linux, Office Suite, SaaS, Windows, macOS","summary":"Legitimate external web services are used as a channel to move data out of the organization and blend with expected encrypted traffic.","detection":"Look for unusual upload volume, new web-service destinations, atypical user agents, suspicious processes initiating transfers, and deviations from normal egress behavior.","mitigation":"Control approved web services, inspect egress where appropriate, apply DLP, and restrict unsanctioned external storage or webhook destinations.","version":"1.5","modified":"12 May 2026","subtechniques":[{"id":"T1567.001","name":"Exfiltration to Code Repository"},{"id":"T1567.002","name":"Exfiltration to Cloud Storage"},{"id":"T1567.003","name":"Exfiltration to Text Storage Sites"},{"id":"T1567.004","name":"Exfiltration Over Webhook"}]},"T1610":{"name":"Deploy Container","tactics":["TA0002"],"platforms":"Containers","summary":"A new container or workload is deployed to execute malicious code, bypass controls, or establish access within containerized infrastructure.","detection":"Detect unapproved images, privileged containers, risky host mounts/namespaces, unusual principals, and suspicious create-to-start-to-network or process chains.","mitigation":"Apply least privilege and RBAC, restrict privileged runtime settings, enforce approved images, segment workloads, and monitor control-plane changes.","strategy":"DET0249","version":"2.0","modified":"12 May 2026"}};
  var selected = null;
  var pendingValidationFix = null;
  var generatedBaseline = null;
  var Store = null;

  function searchExportEndpoint() {
    return Splunk.util.make_url("splunkd", "__raw", "services", "search", "jobs", "export");
  }

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

  function parseExportRows(text) {
    var rows = [];
    String(text || "").split(/\r?\n/).forEach(function (line) {
      var parsed;
      if (!line.trim()) { return; }
      try { parsed = JSON.parse(line); } catch (error) { return; }
      if (parsed && parsed.result) { rows.push(parsed.result); }
    });
    return rows;
  }

  function storedArtifacts() {
    return safeJson(window.localStorage.getItem(ARTIFACT_KEY), []);
  }

  function storedArtifact(id) {
    return storedArtifacts().filter(function (entry) { return entry.id === id; })[0] || null;
  }

  var ANALYTIC_FAMILIES={
    "windows-password-spray":"authentication_threshold","windows-kerberoasting":"kerberos_service_ticket",
    "windows-powershell-encoded":"powershell","endpoint-suspicious-powershell":"powershell",
    "aws-iam-policy-escalation":"aws_change","aws-cloudtrail-disabled":"aws_change","aws-s3-public-access":"aws_change",
    "ai-shadow-usage":"ai_usage","ai-sensitive-data-exposure":"ai_sensitive","ai-model-admin-change":"admin_change",
    "identity-mfa-failure-spike":"authentication_threshold","identity-privilege-grant":"admin_change",
    "endpoint-remote-logon":"remote_logon","linux-ssh-bruteforce":"authentication_threshold","linux-sudo-shell":"privileged_command",
    "dns-suspicious-resolution":"dns_anomaly","firewall-risky-inbound":"firewall_threshold",
    "network-device-config-change":"admin_change","threat-intel-observable-match":"threat_intelligence",
    "es-risk-score-spike":"risk_aggregation","web-anomalous-post-volume":"web_volume",
    "aws-guardduty-high-severity":"guardduty","aws-securityhub-critical-finding":"securityhub",
    "m365-admin-change-failure":"admin_change","m365-message-trace-anomaly":"message_volume",
    "azure-control-plane-change":"admin_change","gcp-admin-activity-change":"admin_change",
    "google-workspace-admin-change":"admin_change","kubernetes-sensitive-api-operation":"admin_change",
    "github-organization-admin-change":"admin_change","salesforce-session-anomaly":"session_anomaly"
  };
  function analyticFamily(id){return ANALYTIC_FAMILIES[id]||"unsupported";}

  function normalizedPrelude(item) {
    var id=item.detection_id;
    if (/password-spray|mfa-failure|ssh-bruteforce/.test(id)) {
      return "| eval user=coalesce(user,TargetUserName,user_name,src_user,'actor.alternateId'), src_ip=coalesce(src_ip,IpAddress,source_ip,client_ip), action=lower(coalesce(action,status,result,'outcome.result'))";
    }
    if (id==="windows-kerberoasting") {
      return "| eval user=coalesce(user,TargetUserName,UserName), src_ip=coalesce(src_ip,IpAddress,ClientAddress), service_name=coalesce(ServiceName,service_name), encryption=lower(tostring(coalesce(TicketEncryptionType,ticket_encryption_type)))";
    }
    if (/powershell/.test(id)) {
      return "| eval user=coalesce(user,UserName), process=coalesce(process_name,Image,file_name), command_line=coalesce(command_line,CommandLine,process_command_line,ScriptBlockText)";
    }
    if (/dns/.test(id)) {
      return "| eval query=coalesce(query,query_name,domain), src_ip=coalesce(src_ip,client_ip), answer=coalesce(answer,response,dest_ip)";
    }
    if (/firewall/.test(id)) {
      return "| eval src_ip=coalesce(src_ip,source_ip), dest_ip=coalesce(dest_ip,destination_ip), dest_port=tonumber(coalesce(dest_port,destination_port)), action=lower(coalesce(action,result))";
    }
    if (/web-anomalous/.test(id)) {
      return "| eval method=upper(coalesce(method,http_method)), uri=coalesce(uri,uri_path,url,request_uri), src_ip=coalesce(src_ip,clientip,client_ip), bytes_out=tonumber(coalesce(bytes_out,bytes_sent,response_bytes,sc_bytes))";
    }
    if (/iam|cloudtrail|s3/.test(id)) {
      return "| eval action=coalesce(eventName,event_name), user=coalesce('userIdentity.arn','userIdentity.userName','userIdentity.sessionContext.sessionIssuer.userName',user_arn,user), src_ip=coalesce(sourceIPAddress,src_ip), object=coalesce('requestParameters.bucketName',bucket_name,bucket)";
    }
    if (/guardduty/.test(id)) {
      return "| eval numeric_severity=tonumber(coalesce(severity,Severity)), account=coalesce(accountId,account_id), resource=coalesce('resource.resourceType',resourceType,resource_type), finding_type=coalesce(type,Type), finding_title=coalesce(title,Title)";
    }
    if (/securityhub/.test(id)) {
      return "| eval finding_severity=upper(coalesce('Severity.Label',severity)), workflow_status=upper(coalesce('Workflow.Status',workflow_status)), account=coalesce(AwsAccountId,accountId,account_id), resource=coalesce('Resources{}.Type','resource.resourceType',resourceType,resource_type,ProductArn,product_arn), finding_title=coalesce(Title,title)";
    }
    if (/admin-change|privilege-grant|model-admin|config-change|sensitive-api|sudo-shell|control-plane-change|admin-activity-change/.test(id)) {
      return "| eval action=coalesce(action,eventName,event_name,operationName,operation_name,Operation,operation,methodName,'protoPayload.methodName',events.name,verb,command), user=coalesce(user,caller,Caller,actor,'actor.email','protoPayload.authenticationInfo.principalEmail','actor.alternateId'), object=coalesce(target,target_user,'target.alternateId',resource,resourceId,resource_id,resourceName,'objectRef.resource',host,device), src_ip=coalesce(src_ip,sourceIPAddress,callerIp,'protoPayload.requestMetadata.callerIp',client_ip), command=coalesce(command,CommandLine,process,process_name)";
    }
    return "";
  }

  function analyticLogic(item) {
    var id=item.detection_id;
    if (id==="windows-password-spray") {
      return "| where EventCode=4625 OR event_id=4625\n| fillnull value=\"unknown\" user src_ip\n| bin _time span=5m\n| stats count dc(user) AS targeted_accounts values(user) AS users by _time src_ip\n| where count>=10 AND targeted_accounts>=5";
    }
    if (id==="windows-kerberoasting") {
      return "| where EventCode=4769 OR event_id=4769\n| where encryption IN (\"0x17\",\"23\")\n| fillnull value=\"unknown\" user src_ip service_name\n| stats count dc(service_name) AS services values(service_name) AS service_names earliest(_time) AS first_seen latest(_time) AS last_seen by user src_ip\n| where count>=5";
    }
    if (/powershell/.test(id)) {
      return "| where match(lower(command_line),\"(-enc\\s|encodedcommand|frombase64string|invoke-expression|downloadstring|hidden)\")\n| table _time host user process command_line";
    }
    if (/mfa-failure|ssh-bruteforce/.test(id)) {
      return "| where match(action,\"fail|deny|reject|invalid\")\n| fillnull value=\"unknown\" user src_ip\n| bin _time span=5m\n| stats count dc(user) AS targeted_accounts values(user) AS users by _time src_ip\n| where count>=10";
    }
    if (id==="endpoint-remote-logon") {
      return "| eval user=coalesce(user,UserName), src_ip=coalesce(src_ip,RemoteAddress,SourceIP), logon_type=coalesce(logon_type,event_type,EventType)\n| where logon_type IN (\"3\",\"10\",3,10)\n| fillnull value=\"unknown\" user src_ip host\n| stats count values(host) AS destinations earliest(_time) AS first_seen latest(_time) AS last_seen by user src_ip\n| where count>=3";
    }
    if (id==="dns-suspicious-resolution") {
      return "| eval query_length=len(query), label_count=mvcount(split(query,\".\"))\n| fillnull value=\"unknown\" src_ip query\n| stats count dc(answer) AS answer_count avg(query_length) AS avg_query_length by src_ip query\n| where count>=20 OR avg_query_length>=55 OR answer_count>=10";
    }
    if (id==="firewall-risky-inbound") {
      return "| where action IN (\"allowed\",\"accept\",\"permit\") AND dest_port IN (22,23,3389,445,5985,5986,1433,3306,5432)\n| fillnull value=\"unknown\" src_ip\n| stats count dc(dest_ip) AS destinations values(dest_port) AS ports by src_ip\n| where count>=5";
    }
    if (id==="web-anomalous-post-volume") {
      return "| where method=\"POST\"\n| fillnull value=\"unknown\" src_ip\n| bin _time span=10m\n| stats count sum(bytes_out) AS bytes_out dc(uri) AS uri_count by _time src_ip\n| where count>=100 OR bytes_out>=50000000";
    }
    if (id==="aws-cloudtrail-disabled") {
      return "| where action IN (\"StopLogging\",\"DeleteTrail\",\"UpdateTrail\",\"PutEventSelectors\")\n| table _time user src_ip action object";
    }
    if (id==="aws-iam-policy-escalation") {
      return "| where action IN (\"AttachUserPolicy\",\"AttachRolePolicy\",\"PutUserPolicy\",\"PutRolePolicy\",\"CreatePolicyVersion\",\"SetDefaultPolicyVersion\",\"UpdateAssumeRolePolicy\",\"AddUserToGroup\")\n| table _time user src_ip action object";
    }
    if (id==="aws-s3-public-access") {
      return "| where action IN (\"PutBucketAcl\",\"PutBucketPolicy\",\"DeletePublicAccessBlock\",\"PutBucketPublicAccessBlock\")\n| table _time user src_ip action object";
    }
    if (/guardduty/.test(id)) {
      return "| where numeric_severity>=7\n| table _time account resource numeric_severity finding_type finding_title";
    }
    if (/securityhub/.test(id)) {
      return "| where finding_severity IN (\"CRITICAL\",\"HIGH\")\n| table _time account resource finding_severity workflow_status finding_title";
    }
    if (id==="ai-sensitive-data-exposure") {
      return "| eval user=coalesce(user,src_user), content=coalesce(prompt,message,request_body), classification=coalesce(classification,category,policy,rule_name), action=lower(coalesce(action,verdict,result)), destination=coalesce(dest,url,host,service,application)\n| where isnotnull(content) AND isnotnull(classification) AND NOT (action IN (\"blocked\",\"deny\",\"denied\"))\n| fillnull value=\"unknown\" user destination\n| stats count values(classification) AS classifications earliest(_time) AS first_seen latest(_time) AS last_seen by user destination";
    }
    if (id==="ai-shadow-usage") {
      return "| eval user=coalesce(user,src_user), destination=lower(coalesce(url,dest,host))\n| where match(destination,\"openai|anthropic|claude|gemini|copilot|perplexity\")\n| fillnull value=\"unknown\" user\n| stats count values(destination) AS ai_services earliest(_time) AS first_seen latest(_time) AS last_seen by user";
    }
    if (id==="threat-intel-observable-match") {
      return "| eval observable=coalesce(indicator,value,ioc), observable_type=coalesce(type,indicator_type,ioc_type)\n| where isnotnull(observable)\n| fillnull value=\"unknown\" observable_type\n| stats latest(_time) AS last_seen values(source) AS intelligence_sources by observable observable_type";
    }
    if (id==="es-risk-score-spike") {
      return "| eval score=tonumber(coalesce(calculated_risk_score,risk_score))\n| fillnull value=\"unknown\" risk_object risk_object_type\n| bin _time span=30m\n| stats sum(score) AS risk_score values(search_name) AS contributing_detections by _time risk_object risk_object_type\n| where risk_score>=100";
    }
    if (id==="salesforce-session-anomaly") {
      return "| eval src_ip=coalesce(CLIENT_IP,client_ip,src_ip), user_agent=coalesce(USER_AGENT,user_agent)\n| fillnull value=\"unknown\" SESSION_KEY LOGIN_KEY\n| stats dc(src_ip) AS source_count dc(user_agent) AS agent_count values(src_ip) AS sources by SESSION_KEY LOGIN_KEY\n| where source_count>=3 OR agent_count>=3";
    }
    if (id==="m365-message-trace-anomaly") {
      return "| eval sender=coalesce(SenderAddress,sender), recipient=coalesce(RecipientAddress,recipient), status=coalesce(Status,status)\n| fillnull value=\"unknown\" sender\n| bin _time span=15m\n| stats count dc(recipient) AS recipients values(status) AS statuses by _time sender\n| where count>=100 OR recipients>=50";
    }
    if (/admin-change|privilege-grant|model-admin|config-change|sensitive-api|sudo-shell|control-plane-change|admin-activity-change/.test(id)) {
      return "| where isnotnull(action)\n| fillnull value=\"unknown\" user src_ip object\n| stats count values(action) AS actions values(object) AS objects values(command) AS commands earliest(_time) AS first_seen latest(_time) AS last_seen by user src_ip\n| where count>=1";
    }
      return "| eval dei_generation_blocker=\"No explicit analytic template exists for this detection ID\"\n| where 1=0";
  }

  function schedule(item) {
    if (item.severity === "critical") { return {cron:"*/5 * * * *", earliest:"-10m@m", latest:"-2m@m"}; }
    if (item.severity === "high") { return {cron:"*/10 * * * *", earliest:"-15m@m", latest:"-2m@m"}; }
    if (/anomal|rare|spike/.test(item.detection_id)) { return {cron:"15 * * * *", earliest:"-70m@m", latest:"-10m@m"}; }
    return {cron:"*/15 * * * *", earliest:"-20m@m", latest:"-2m@m"};
  }

  function uniqueValues(values) {
    var seen = {};
    return values.filter(function (value) {
      var key = String(value || "");
      if (!key || seen[key]) { return false; }
      seen[key] = true;
      return true;
    });
  }

  function multivalueLiteral(values, fallback) {
    var cleaned = uniqueValues(values || []);
    if (!cleaned.length) { return quote(fallback || "Unknown"); }
    if (cleaned.length === 1) { return quote(cleaned[0]); }
    return "mvappend(" + cleaned.map(quote).join(", ") + ")";
  }

  function techniqueUrl(id) {
    var parts = String(id || "").split(".");
    return "https://attack.mitre.org/techniques/" + parts[0] + (parts[1] ? "/" + parts[1] : "") + "/";
  }

  function tacticUrl(id) {
    return "https://attack.mitre.org/tactics/" + String(id || "") + "/";
  }

  function platformMitreMetadata(item) {
    var techniques = item.mitre_techniques || [];
    var references = techniques.map(function (id) {
      return $.extend({id:id, name:"Unknown ATT&CK technique", tactics:[], platforms:"",
        summary:"No bundled ATT&CK description is available.", detection:"Review the current MITRE ATT&CK technique guidance."},
        MITRE_REFERENCE[id] || {});
    });
    var summaries = references.map(function (entry) { return entry.id + ": " + entry.summary; });
    return "| eval mitre_attack_ttp=" + multivalueLiteral(references.map(function (entry) { return entry.name; }), "Unmapped") +
      ", mitre_attack_id=" + multivalueLiteral(techniques, "Unmapped") +
      ", mitre_attack_description=" + multivalueLiteral(summaries, "No ATT&CK description is available");
  }

  function stripPlatformMitreMetadata(spl) {
    var analyticSpl=String(spl || "").replace(/\\n(?=\|)/g,"\n");
    var markers=[
      /(?:\r?\n)?\|\s*eval\s+(?:dei_detection_id|mitre_attack_ttp)\s*=/i,
      /(?:\r?\n)?\|\s*(?:rShell|search)"\s*,\s*(?:"\|\|"\)|mitre_attack_id\s*=)/i,
      /n\|\s*(?:rShell|search)"\s*,\s*(?:"\|\|"\)|mitre_attack_id\s*=)/i
    ];
    var boundary=-1;
    markers.forEach(function (pattern) {
      var match=pattern.exec(analyticSpl);
      if(match && (boundary<0 || match.index<boundary)) boundary=match.index;
    });
    if(boundary>=0) analyticSpl=analyticSpl.slice(0,boundary);
    return analyticSpl.trim();
  }

  function attachPlatformMitreMetadata(spl, item) {
    var analyticSpl=stripPlatformMitreMetadata(spl);
    return analyticSpl+"\n"+platformMitreMetadata(item);
  }

  function generatedSplIntegrity(spl) {
    var value=String(spl || ""),errors=[],allowed={
      mitre_attack_ttp:true,mitre_attack_id:true,mitre_attack_description:true
    };
    Object.keys(allowed).forEach(function (field) {
      var count=(value.match(new RegExp("\\b"+field+"\\s*=","g")) || []).length;
      if(count!==1) errors.push(field+" must appear exactly once");
    });
    (value.match(/\bmitre_attack_[a-z_]+\b/gi) || []).forEach(function (field) {
      if(!allowed[field.toLowerCase()]) errors.push("unsupported MITRE output field "+field);
    });
    if(/\\n(?=\|)/.test(value)) errors.push("literal newline escape remains");
    if(/mitre_attack_(?:ttp|id|description)\s*=\s*split\s*\(/i.test(value)) errors.push("legacy MITRE split output remains");
    if(/n?\|\s*rShell"/i.test(value)) errors.push("legacy rShell fragment remains");
    if(!/\n\|\s*eval\s+mitre_attack_ttp\s*=/.test(value)) errors.push("MITRE output is not the final pipeline stage");
    var syntax=pipelineSyntax(value);
    if(!syntax.balancedQuotes) errors.push("generated SPL contains an unmatched quote");
    if(syntax.emptyPipes.length) errors.push("generated SPL contains an empty pipeline stage");
    return {valid:errors.length===0,errors:errors};
  }

  function artifactRecommendation(artifact) {
    return {
      detection_id:String(artifact.id || artifact.detection_id || "").replace(/^dei-/, ""),
      name:artifact.name,
      mitre_techniques:artifact.mitre_attack || []
    };
  }

  function enforcePlatformMitreMetadata(artifact, item) {
    var enriched = attachPlatformMitreMetadata(artifact.spl, item || artifactRecommendation(artifact));
    var changed = enriched !== artifact.spl;
    artifact.spl = enriched;
    if (artifact.enterprise_security) { artifact.enterprise_security.drilldown_search = enriched; }
    return changed;
  }

  function readinessLabel(value) {
    var labels = {
      production_ready:"Telemetry ready",
      field_unverified:"Field verification required",
      field_gap:"Confirmed field gap"
    };
    return labels[value] || String(value || "unknown").replace(/_/g, " ");
  }

  function unresolvedFields(item) {
    var unresolved = [];
    Object.keys(item.missing_fields || {}).forEach(function (source) {
      (item.missing_fields[source] || []).forEach(function (fields) {
        unresolved.push(source + ": " + fields);
      });
    });
    (item.unverified_field_sources || []).forEach(function (source) {
      unresolved.push(source + ": field inventory not verified");
    });
    return unresolved;
  }

  function engineeringWarnings(item) {
    var warnings = [];
    if (item.readiness === "field_unverified") {
      warnings.push("Field requirements have not been verified against a representative sample. Review field aliases before validation.");
    }
    if (item.readiness === "field_gap") {
      warnings.push("The environment has confirmed field gaps. Resolve or replace the listed fields before production use.");
    }
    return warnings.concat(unresolvedFields(item));
  }

  function buildArtifact(item) {
    var report = safeJson(window.sessionStorage.getItem(REPORT_KEY), {});
    var sources = observedSourcetypes(item, report);
    var timing = schedule(item);
    var spl = attachPlatformMitreMetadata("search (" + sourceClause(sources) + ") earliest=" + timing.earliest + " latest=" + timing.latest +
      "\n" + normalizedPrelude(item) + "\n" + analyticLogic(item), item);
    var integrity=generatedSplIntegrity(spl);
    if(!integrity.valid) throw new Error("Generated SPL integrity check failed: "+integrity.errors.join("; "));
    var esEnabled = window.sessionStorage.getItem(ES_KEY) === "true";
    var riskScore = item.severity === "critical" ? 80 : item.severity === "high" ? 60 : item.severity === "medium" ? 40 : 20;
    var artifact={
      schema_version:"1.0.0", id:"dei-" + item.detection_id, name:item.name, status:"draft", analytic_family:analyticFamily(item.detection_id),
      description:item.why, severity:item.severity, capability:item.capability,
      source_readiness:item.readiness, unresolved_fields:unresolvedFields(item), engineering_warnings:engineeringWarnings(item),
      sourcetypes:sources, mitre_attack:item.mitre_techniques || [], spl:spl,
      schedule:timing, generated_at:new Date().toISOString(), updated_at:new Date().toISOString(),
      validation:null, enterprise_security: esEnabled ? {
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
    artifact.standards=window.DEIDetectionStandards ? window.DEIDetectionStandards.evaluate(artifact) : null;
    return artifact;
  }

  function renderStandards(artifact) {
    var report=window.DEIDetectionStandards ? window.DEIDetectionStandards.evaluate(artifact) : null;
    if(!report){return;}
    artifact.standards=report;
    $("#builder-quality-score").text(report.score+"%");
    $("#builder-quality-state").attr("data-state",report.status).text(report.status==="passed"?"Production quality passed":report.status==="blocked"?"Blocked — resolve required checks":"Review quality warnings");
    $("#builder-quality-dimensions").html(Object.keys(report.scores).map(function(key){return "<div><span>"+escapeHtml(key.replace(/_/g," "))+"</span><strong>"+report.scores[key]+"%</strong></div>";}).join(""));
    $("#builder-quality-issues").html(report.issues.length?report.issues.map(function(item){return "<article data-severity=\""+item.severity+"\"><div><strong>"+escapeHtml(item.title)+"</strong><p>"+escapeHtml(item.detail)+"</p><small>"+escapeHtml(item.remediation)+"</small></div><button type=\"button\" data-quality-focus=\"generator-spl\">Review SPL</button></article>";}).join(""):"<p class=\"dei-quality-clear\">All required SPL engineering checks passed.</p>");
  }

  function renderArtifact(artifact) {
    var es = artifact.enterprise_security;
    renderStandards(artifact);
    $("#generator-empty").hide();
    $("#generator-output").show();
    $("#generator-title").text(artifact.name);
    $("#generator-badges").html('<span>' + escapeHtml(artifact.status) + '</span><span>' +
      escapeHtml(artifact.severity) + '</span><span>' + escapeHtml(readinessLabel(artifact.source_readiness)) + '</span><span>' + escapeHtml(artifact.mitre_attack.join(" · ") || "No MITRE mapping") + '</span>');
    $("#builder-cron").val(artifact.schedule.cron);
    $("#builder-earliest").val(artifact.schedule.earliest);
    $("#builder-latest").val(artifact.schedule.latest);
    $("#generator-spl").val(artifact.spl);
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
    renderValidation(artifact.validation);
    if ((artifact.engineering_warnings || []).length) {
      setFeedback("Engineering draft generated with prerequisites: " + artifact.engineering_warnings.join(" · "), "error");
    } else {
      setFeedback(artifact.updated_at ? "Saved draft loaded. Review or validate it against current telemetry." : "Generated draft is ready for review.", "ready");
    }
  }

  function lifecycleRecord(artifact) {
    var record = $.extend(true, {}, artifact);
    record._key = String(artifact.id || "").replace(/^dei-/, "");
    record.detection_id = record._key;
    record.state = artifact.status === "testing" ? "testing" : (artifact.state || artifact.status || "draft");
    record.status = record.state;
    record.version = Number(record.version || 1);
    record.history = Array.isArray(record.history) ? record.history : [];
    return record;
  }

  function saveArtifact(artifact) {
    var artifacts = storedArtifacts();
    var eventName = artifact.status === "testing" ? "validation_completed" :
      (artifact.state === "tuning" ? "tuning_draft_saved" : "draft_saved");
    artifacts = artifacts.filter(function (entry) { return entry.id !== artifact.id; });
    artifacts.push(artifact);
    window.localStorage.setItem(ARTIFACT_KEY, JSON.stringify(artifacts));
    $(document).trigger("dei:detection-artifacts-changed", [artifacts]);
    if (Store) {
      var record = Store.appendHistory(lifecycleRecord(artifact), eventName,
        artifact.status === "testing" ? "Bounded historical validation evidence persisted." : "Detection definition and SPL saved.");
      artifact.history = record.history;
      Store.write(record);
    }
  }

  function setFeedback(message, state) {
    $("#builder-feedback").removeClass("ready working success error").addClass(state || "ready").text(message);
  }

  function currentArtifact() {
    if (!selected) { return null; }
    var artifact = $.extend(true, {}, selected);
    artifact.spl = attachPlatformMitreMetadata(String($("#generator-spl").val() || "").trim(), artifactRecommendation(artifact));
    artifact.schedule = {
      cron:String($("#builder-cron").val() || "").trim(),
      earliest:String($("#builder-earliest").val() || "").trim(),
      latest:String($("#builder-latest").val() || "").trim()
    };
    if (artifact.spl !== selected.spl || artifact.schedule.cron !== selected.schedule.cron ||
        artifact.schedule.earliest !== selected.schedule.earliest || artifact.schedule.latest !== selected.schedule.latest) {
      artifact.validation = null;
      artifact.status = selected.state === "tuning" ? "tuning" : "draft";
      artifact.state = artifact.status;
    }
    artifact.updated_at = new Date().toISOString();
    return artifact;
  }

  function validateDraftInputs(artifact) {
    if (!artifact.spl) { return "Detection SPL is required."; }
    if (!/^(search\s|\|)/i.test(artifact.spl)) { return "Detection SPL must begin with search or a generating command (|)."; }
    if (artifact.schedule.cron.split(/\s+/).length !== 5) { return "Cron schedule must contain five fields."; }
    if (!artifact.schedule.earliest || !artifact.schedule.latest) { return "Earliest and latest validation times are required."; }
    if (!/^-\d+[smhdw](?:@[smhdw])?$/i.test(artifact.schedule.earliest)) {
      return "Earliest time must be a bounded relative value such as -15m@m or -24h@h.";
    }
    if (!/^(?:now|-\d+[smhdw](?:@[smhdw])?)$/i.test(artifact.schedule.latest)) {
      return "Latest time must be now or a bounded relative value such as -2m@m.";
    }
    return "";
  }

  function saveCurrentDraft() {
    var artifact = currentArtifact();
    var error = artifact ? validateDraftInputs(artifact) : "Generate a detection draft first.";
    if (error) { setFeedback(error, "error"); return null; }
    selected = artifact;
    $("#generator-spl").val(artifact.spl);
    saveArtifact(artifact);
    setFeedback("Draft saved at " + new Date(artifact.updated_at).toLocaleString() + ".", "success");
    return artifact;
  }

  function commandBoundaryPattern(command) {
    var escaped=String(command || "").replace(/[.*+?^${}()|[\]\\]/g,"\\$&");
    return new RegExp("(^|\\|)(\\s*)"+escaped+"\\b","i");
  }

  function replaceCommandAtBoundary(spl, command, replacement) {
    return String(spl || "").replace(commandBoundaryPattern(command),function (match,boundary,spacing) {
      return boundary+spacing+replacement;
    });
  }

  function pipelineSyntax(spl) {
    var value=String(spl || ""),quoteCharacter="",escaped=false,emptyPipes=[],previousPipe=-1;
    for (var index=0;index<value.length;index+=1) {
      var character=value.charAt(index);
      if (escaped) { escaped=false; continue; }
      if (character==="\\" && quoteCharacter) { escaped=true; continue; }
      if (quoteCharacter) {
        if (character===quoteCharacter) { quoteCharacter=""; }
        continue;
      }
      if (character==='"' || character==="'") { quoteCharacter=character; continue; }
      if (character==="|") {
        if (previousPipe>=0 && !value.slice(previousPipe+1,index).trim()) {
          emptyPipes.push({first:previousPipe,second:index});
        }
        previousPipe=index;
      } else if (!/\s/.test(character)) {
        previousPipe=-1;
      }
    }
    return {balancedQuotes:!quoteCharacter,emptyPipes:emptyPipes};
  }

  function collapseEmptyPipelines(spl) {
    var value=String(spl || ""),syntax=pipelineSyntax(value);
    syntax.emptyPipes.slice().reverse().forEach(function (pair) {
      value=value.slice(0,pair.first+1)+" "+value.slice(pair.second+1).replace(/^\s*/,"");
    });
    return value;
  }

  function canAddSearchPrefix(spl) {
    var value=String(spl || "").trim();
    var first=String(value.split("|")[0] || "").trim();
    var generating=/^(?:search|tstats|inputlookup|metadata|metasearch|datamodel|makeresults|loadjob|savedsearch|eventcount|rest|from)\b/i;
    var filterExpression=/^(?:\(|[A-Za-z_][A-Za-z0-9_.:-]*\s*(?:=|!=|<=|>=|<|>))/;
    return !!value && value.charAt(0)!=="|" && !generating.test(first) && filterExpression.test(first);
  }

  function validationResolution(error, spl) {
    var message=String(error || "Splunk rejected or could not execute the search.");
    var lower=message.toLowerCase();
    var unknown=message.match(/Unknown search command\s+['\"]?([A-Za-z][A-Za-z0-9_-]*)['\"]?/i);
    var command=unknown ? unknown[1] : "";
    var syntax=pipelineSyntax(spl);
    var missingBeforePipe=/missing a search command before\s+['\"]?\|/i.test(message);
    var result={category:"Search review",summary:"Review the Splunk error, inspect the generated SPL, apply a safe correction when available, and validate again.",steps:[
      "Read the complete Splunk error shown below.",
      "Open the SPL editor and inspect the command or field named by Splunk.",
      "Save the corrected draft, then run validation again."
    ],fix:null,fixLabel:""};
    if (command.toLowerCase() === "rshell" && commandBoundaryPattern("rshell").test(String(spl || ""))) {
      result.category="Missing command or macro";
      result.summary="Splunk does not provide a built-in rshell command. DEI found rshell in an SPL command position and can safely correct this exact typo to search.";
      result.steps=["Replace only the command-position token rshell with search.",
        "Review the corrected SPL; field values and quoted text are not modified.",
        "Run validation again against the same bounded time window."];
      result.fix="rshell_to_search"; result.fixLabel="Replace rshell with search";
      result.correctedSpl=replaceCommandAtBoundary(spl, "rshell", "search");
      result.autoApply=true;
      result.appliedSummary="DEI replaced the invalid command-position token rshell with search. No quoted text or field values were changed.";
    } else if (missingBeforePipe && syntax.emptyPipes.length) {
      result.category="SPL syntax";
      result.summary="Splunk found an empty pipeline stage. DEI can safely collapse the adjacent pipe delimiters without changing commands or field expressions.";
      result.steps=["Remove only the empty pipeline delimiter.","Review the corrected command boundary highlighted by the Splunk error position.","Run validation again against the same bounded window."];
      result.fix="empty_pipeline"; result.fixLabel="Remove empty pipeline stage";
      result.correctedSpl=collapseEmptyPipelines(spl); result.autoApply=true;
      result.appliedSummary="DEI removed an empty pipeline stage. Commands, quoted strings, field expressions, and MITRE metadata values were preserved.";
    } else if (/timeout|timed out|time range|exceeded the 60 second/.test(lower)) {
      result.category="Search scope";
      result.summary="The validation search exceeded its safety boundary. Use a narrower window before changing detection logic.";
      result.steps=["Apply the bounded 15-minute validation window.","Review high-cardinality stats or transaction commands.","Run validation again and expand the window only after the search completes."];
      result.fix="narrow_window"; result.fixLabel="Apply 15-minute window";
    } else if ((/must begin with search|missing a search command|first command/.test(lower)) &&
        !/unknown search command|unknown command|macro/.test(lower) && canAddSearchPrefix(spl)) {
      result.category="SPL syntax";
      result.summary="Splunk could not identify a valid generating command. DEI can add the required search prefix when the query begins with a filter expression.";
      result.steps=["Apply the search-prefix correction.","Review the beginning of the SPL for unmatched quotes or parentheses.","Run validation again."];
      result.fix="search_prefix"; result.fixLabel="Add search prefix";
      result.correctedSpl="search "+String(spl || "").trim(); result.autoApply=true;
      result.appliedSummary="DEI added search before the opening field-filter expression. The remaining pipeline was not changed.";
    } else if (missingBeforePipe) {
      result.category="SPL syntax";
      result.summary="The SPL already has a generating search, so adding another search prefix would be incorrect. Splunk found a malformed pipe boundary or an unmatched quote near the reported position.";
      result.steps=["Inspect the exact error position and the command immediately before it.",
        syntax.balancedQuotes ? "Check for a missing command between pipe delimiters." : "Close the unmatched quoted string before the next pipe delimiter.",
        "Correct the SPL in the editor, then run validation again."];
    } else if (/unknown search command|unknown command|cannot find.*macro|macro .*not found/.test(lower)) {
      result.category="Missing command or macro";
      result.summary="The SPL references a command or macro that is unavailable in this Splunk environment. DEI will not guess a replacement because that could change detection meaning.";
      result.steps=["Identify the command or macro named in the error.","Confirm the required app, TA, or macro is installed and shared with this app.","Replace the unavailable command with supported SPL, then validate again."];
    } else if (/permission|not authorized|authorization|insufficient privilege|access denied/.test(lower)) {
      result.category="Splunk permissions";
      result.summary="The current analyst role cannot execute part of this validation search.";
      result.steps=["Identify the denied index, command, knowledge object, or capability.","Ask a Splunk administrator to grant the minimum required DEI role access.","Run validation again after access is confirmed."];
    } else if (/field.*(?:not found|does not exist|unknown)|unknown field|invalid field/.test(lower)) {
      result.category="Field mapping";
      result.summary="The generated SPL references a field that is not available in the selected sourcetype.";
      result.steps=["Return to the active environment scan and confirm representative extracted fields.","Replace the missing field with the observed equivalent in Detection SPL.","Update any related stats, by, eval, or where clauses, then validate again."];
    } else if (/parse|syntax|unbalanced|mismatched|unexpected|invalid argument/.test(lower)) {
      result.category="SPL syntax";
      result.summary="Splunk rejected the SPL syntax. This requires analyst review because automatically rewriting the expression could change detection intent.";
      result.steps=["Inspect the command and position named in the error.","Check quotes, parentheses, commas, pipes, and command arguments.","Correct the SPL in the editor and run validation again."];
    }
    return result;
  }

  function renderValidationResolution(validation) {
    var panel=$("#builder-validation-resolution");
    if (!validation || validation.status!=="failed") {
      pendingValidationFix=null; panel.prop("hidden",true); return;
    }
    var resolution=validation.resolution || validationResolution(validation.error,String($("#generator-spl").val() || ""));
    pendingValidationFix=resolution.applied ? null : resolution.fix;
    $("#builder-validation-resolution-category").text(resolution.category+(resolution.applied ? " · corrected automatically" : ""));
    $("#builder-validation-resolution-summary").text(resolution.applied ? resolution.appliedSummary : resolution.summary);
    $("#builder-validation-error").text(validation.error || "No detailed Splunk error was returned.");
    $("#builder-validation-resolution-steps").html(resolution.steps.map(function (step) {
      return "<li>"+escapeHtml(step)+"</li>";
    }).join(""));
    $("#builder-apply-validation-fix").prop("hidden",!resolution.fix || resolution.applied).text(resolution.fixLabel || "Apply recommended fix");
    panel.prop("hidden",false);
  }

  function renderValidation(validation) {
    var state = $("#builder-validation-state");
    if (!validation) {
      state.removeClass("running passed failed").addClass("idle").text("Not run");
      $("#builder-validation-metrics, #builder-validation-results").hide();
      renderValidationResolution(null);
      return;
    }
    state.removeClass("idle running passed failed").addClass(validation.status)
      .text(validation.status === "passed" ? "Search completed" : "Validation failed");
    $("#validation-status").text(validation.status);
    $("#validation-result-count").text(validation.result_count);
    $("#validation-runtime").text(validation.runtime_ms + " ms");
    $("#validation-time").text(new Date(validation.validated_at).toLocaleString());
    $("#builder-validation-metrics").show();
    renderValidationRows(validation.sample_results || []);
    renderValidationResolution(validation);
  }

  function resultColumns(rows) {
    var preferred = ["_time", "mitre_attack_ttp", "mitre_attack_id",
      "mitre_attack_description", "user", "src_ip", "dest_ip", "host", "action", "count"];
    var found = {};
    rows.forEach(function (row) { Object.keys(row || {}).forEach(function (key) { found[key] = true; }); });
    return preferred.filter(function (key) { return found[key]; }).concat(
      Object.keys(found).filter(function (key) { return preferred.indexOf(key) === -1 && key !== "_raw"; }).sort()
    ).slice(0, 12);
  }

  function renderValidationRows(rows) {
    var columns = resultColumns(rows);
    if (!rows.length || !columns.length) { $("#builder-validation-results").hide(); return; }
    $("#validation-result-head").html("<tr>" + columns.map(function (column) {
      return "<th>" + escapeHtml(column) + "</th>";
    }).join("") + "</tr>");
    $("#validation-result-body").html(rows.map(function (row) {
      return "<tr>" + columns.map(function (column) {
        var value = Array.isArray(row[column]) ? row[column].join(", ") : row[column];
        value = String(value == null ? "" : value);
        return '<td title="' + escapeHtml(value) + '">' + escapeHtml(value.slice(0, 180)) + "</td>";
      }).join("") + "</tr>";
    }).join(""));
    $("#builder-validation-results").show();
  }

  function validationError(xhr, status) {
    var response = safeJson(xhr && xhr.responseText, {});
    var messages=(response.messages || []).map(function (message) { return message && message.text; }).filter(Boolean);
    if (messages.length) { return messages.join(" · "); }
    return status === "timeout" ? "Validation exceeded the 60 second safety timeout." :
      "Splunk rejected or could not execute the search.";
  }

  function applyValidationCorrection(artifact, resolution) {
    if (!resolution || !resolution.fix) { return false; }
    if (resolution.correctedSpl) {
      artifact.spl=resolution.correctedSpl;
      $("#generator-spl").val(resolution.correctedSpl);
      if (artifact.enterprise_security) { artifact.enterprise_security.drilldown_search=resolution.correctedSpl; }
    } else if (resolution.fix==="narrow_window") {
      artifact.schedule={cron:"*/5 * * * *",earliest:"-15m@m",latest:"-2m@m"};
      $("#builder-cron").val(artifact.schedule.cron);
      $("#builder-earliest").val(artifact.schedule.earliest);
      $("#builder-latest").val(artifact.schedule.latest);
    } else { return false; }
    return true;
  }

  function runValidation() {
    var artifact = saveCurrentDraft();
    if (artifact && window.DEIDetectionStandards) {
      artifact.standards=window.DEIDetectionStandards.evaluate(artifact);
      renderStandards(artifact);
      if (artifact.standards.status==="blocked") { setFeedback("Quality gate blocked validation. Resolve the required SPL checks shown above.", "error"); return; }
    }
    var started;
    if (!artifact) { return; }
    $("#builder-run-validation").prop("disabled", true).text("Running…");
    $("#builder-validation-state").removeClass("idle passed failed").addClass("running").text("Running bounded search…");
    setFeedback("Submitting the draft to Splunk for bounded historical validation.", "working");
    started = Date.now();
    $.ajax({
      url:searchExportEndpoint(), method:"POST", dataType:"text", timeout:VALIDATION_TIMEOUT_MS,
      headers:{"X-Splunk-Form-Key":Splunk.util.getConfigValue("FORM_KEY")},
      data:{search:artifact.spl + "\n| head " + VALIDATION_RESULT_LIMIT, output_mode:"json", preview:"0",
        earliest_time:artifact.schedule.earliest, latest_time:artifact.schedule.latest}
    }).done(function (text) {
      var rows = parseExportRows(text);
      artifact.validation = {status:"passed", validated_at:new Date().toISOString(), runtime_ms:Date.now() - started,
        result_count:rows.length, result_limit:VALIDATION_RESULT_LIMIT, sample_results:rows};
      artifact.status = "testing";
      artifact.state = "testing";
      artifact.updated_at = artifact.validation.validated_at;
      selected = artifact;
      saveArtifact(artifact);
      renderArtifact(artifact);
      setFeedback("Validation completed. " + rows.length + " result row" + (rows.length === 1 ? "" : "s") + " returned (cap " + VALIDATION_RESULT_LIMIT + ").", "success");
    }).fail(function (xhr, status) {
      var error=validationError(xhr,status);
      var resolution=validationResolution(error,artifact.spl);
      artifact.validation = {status:"failed", validated_at:new Date().toISOString(), runtime_ms:Date.now() - started,
        result_count:0, result_limit:VALIDATION_RESULT_LIMIT, sample_results:[], error:error,
        resolution:resolution};
      if (resolution.autoApply && applyValidationCorrection(artifact,resolution)) {
        artifact.validation_history=Array.isArray(artifact.validation_history) ? artifact.validation_history : [];
        artifact.validation_history.push($.extend(true,{},artifact.validation));
        resolution.applied=true;
      }
      artifact.updated_at = artifact.validation.validated_at;
      selected = artifact;
      saveArtifact(artifact);
      renderArtifact(artifact);
      setFeedback(resolution.applied ? resolution.appliedSummary+" Review the update and run validation again." : artifact.validation.error, resolution.applied ? "working" : "error");
    }).always(function () {
      $("#builder-run-validation").prop("disabled", false).text("Run validation");
    });
  }

  function copyText(value, button) {
    var original=button.text();
    function success() {
      button.text("Copied");
      setFeedback("Copied to clipboard.", "success");
      window.setTimeout(function () { button.text(original); },1200);
    }
    function fallback() {
      var helper=$("<textarea>").val(value).attr("aria-hidden","true").css({position:"fixed",left:"-9999px"});
      $("body").append(helper); helper[0].select();
      try {
        if (document.execCommand("copy")) { success(); } else { throw new Error("copy unavailable"); }
      } catch (error) {
        setFeedback("Clipboard access is unavailable. Select the generated value and copy it manually.", "error");
      }
      helper.remove();
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(success).catch(fallback);
    } else {
      fallback();
    }
  }

  function buildableRecommendations() {
    var report = safeJson(window.sessionStorage.getItem(REPORT_KEY), {});
    var allowed = {production_ready:true, field_unverified:true, field_gap:true};
    return (report.recommendations || []).filter(function (item) {
      return allowed[item.readiness] === true;
    });
  }

  function requestedDetectionId() {
    var match = String(window.location.search || "").match(/[?&]detection=([^&]+)/);
    if (match) {
      try { return decodeURIComponent(match[1].replace(/\+/g, " ")); } catch (error) { return match[1]; }
    }
    return "";
  }

  function resetDraftWorkspace(message) {
    selected = null;
    generatedBaseline = null;
    pendingValidationFix = null;
    $("#detection-generator,#generator-output").hide();
    $("#generator-empty").show().text(message || "Choose Generate detection draft to start a clean workspace.");
    $("#generator-title").text("Detection draft");
    $("#generator-badges,#builder-quality-dimensions,#generator-es-output").empty();
    $("#generator-spl,#builder-cron,#builder-earliest,#builder-latest").val("");
    $("#builder-quality-score").text("0%");
    $("#builder-quality-state").attr("data-state", "blocked").text("Generate a draft");
    $("#builder-quality-issues").html("<p>Generate a draft to evaluate its engineering quality.</p>");
    $("#generator-es-state").text("Select a telemetry-ready detection");
    renderValidation(null);
  }

  function selectorGroup(items, readiness, label) {
    var matches = items.filter(function (item) { return item.readiness === readiness; });
    if (!matches.length) { return ""; }
    return '<optgroup label="' + escapeHtml(label + " (" + matches.length + ")") + '">' +
      matches.map(function (item) {
        return '<option value="' + escapeHtml(item.detection_id) + '">' +
          escapeHtml(item.name + " · " + item.severity + " · " + (item.mitre_techniques || []).join(", ")) +
          "</option>";
      }).join("") + "</optgroup>";
  }

  function populateDetectionSelector() {
    var report = safeJson(window.sessionStorage.getItem(REPORT_KEY), null);
    var items = buildableRecommendations();
    var requested = requestedDetectionId();
    $("#builder-ready-count").text(items.length + " buildable");
    $("#builder-detection-select").html('<option value="">Select a detection to build</option>' +
      selectorGroup(items, "production_ready", "Telemetry ready") +
      selectorGroup(items, "field_unverified", "Field verification required") +
      selectorGroup(items, "field_gap", "Confirmed field gaps"));
    if (!report || !report.recommendations) {
      $("#generator-empty").html('No environment analysis is loaded. Return to <a href="command_center#dei-telemetry">Environment Discovery</a> and run an intelligence scan.');
      $("#builder-generate").prop("disabled", false);
      return;
    }
    if (!items.length) {
      $("#generator-empty").text("No buildable recommendations are available. Unsupported and missing-telemetry detections remain blocked.");
      $("#builder-generate").prop("disabled", false);
      return;
    }
    if (requested && items.some(function (item) { return item.detection_id === requested; })) {
      $("#builder-detection-select").val(requested);
      $("#builder-generate").prop("disabled", false);
      resetDraftWorkspace("Selection ready. Choose Generate detection draft to start.");
    } else {
      resetDraftWorkspace("Select a detection, then choose Generate detection draft to start.");
      $("#builder-generate").prop("disabled", false);
    }
  }

  function generateSelectedDetection() {
    var id = String($("#builder-detection-select").val() || "");
    var item = buildableRecommendations().filter(function (candidate) {
      return candidate.detection_id === id;
    })[0];
    if (!item) {
      $("#generator-empty").text("Select a detection first, then choose Generate detection draft.");
      setFeedback("Select a qualified recommendation before generating SPL.", "ready");
      $("#builder-detection-select").focus();
      return;
    }
    try { window.localStorage.setItem(SELECTED_DETECTION_KEY, id); } catch (error) {
      // Generation remains available when browser storage is unavailable.
    }
    var existingArtifact = storedArtifact("dei-" + item.detection_id);
    var artifact;
    try { artifact=buildArtifact(item); }
    catch (error) {
      setFeedback(error && error.message ? error.message : "DEI blocked an invalid generated query.","error");
      $("#generator-output").hide();
      return;
    }
    generatedBaseline = $.extend(true, {}, artifact);
    if (existingArtifact) {
      artifact.version=Number(existingArtifact.version || 1);
      artifact.history=Array.isArray(existingArtifact.history) ? existingArtifact.history : [];
      artifact.validation_history=Array.isArray(existingArtifact.validation_history) ? existingArtifact.validation_history : [];
    }
    artifact.source_readiness = item.readiness;
    artifact.unresolved_fields = unresolvedFields(item);
    artifact.engineering_warnings = engineeringWarnings(item);
    if (!artifact.sourcetypes || !artifact.sourcetypes.length) {
      setFeedback("No observed sourcetype mapping is available for this recommendation. Refresh Environment Intelligence before generating SPL.", "error");
      return;
    }
    $("#detection-generator").show();
    saveArtifact(artifact);
    renderArtifact(artifact);
    setFeedback(existingArtifact ? "A fresh detection draft replaced the prior saved SPL. Historical lifecycle and validation evidence was preserved." : "Generated a fresh detection draft from the current telemetry recommendation.", "success");
  }

  $("#builder-detection-select").on("change", function () {
    var hasSelection = !!$(this).val();
    $("#builder-generate").prop("disabled", false);
    resetDraftWorkspace(hasSelection ? "Selection ready. Choose Generate detection draft to start." : "Select a detection, then choose Generate detection draft to start.");
    if (hasSelection && $("#workflow-detection-select").length && $("#workflow-detection-select").val() !== $(this).val()) {
      $("#workflow-detection-select").val($(this).val()).trigger("change");
    }
  });
  $("#builder-generate").on("click", generateSelectedDetection);
  $("#builder-save-draft").on("click", saveCurrentDraft);
  $("#builder-run-validation").on("click", runValidation);
  $("#builder-reset-draft").on("click", function () {
    if (!generatedBaseline) { return; }
    selected = $.extend(true, {}, generatedBaseline);
    saveArtifact(selected);
    renderArtifact(selected);
    setFeedback("Draft reset to the current generated values.", "success");
  });
  $("#builder-clear-spl").on("click", function () {
    $("#generator-spl").val("").focus();
    renderValidation(null);
    setFeedback("Detection SPL cleared. Generate again to restore the recommended query.", "success");
  });
  $("#generator-spl, #builder-cron, #builder-earliest, #builder-latest").on("input", function () {
    if (selected) { setFeedback("Unsaved changes. Save the draft or run validation to persist them.", "ready"); }
  });
  $("#lifecycle-workspace-menu").on("change", function () {
    var destination = String($(this).val() || "");
    if (destination && destination !== "detection_builder") { window.location.href = destination; }
  });

  $("#builder-edit-validation-query").on("click", function () {
    $("#generator-spl")[0].scrollIntoView({behavior:"smooth",block:"center"});
    window.setTimeout(function () { $("#generator-spl").focus(); },300);
    setFeedback("Edit the SPL using the resolution steps, save the draft, and run validation again.", "ready");
  });
  $("#builder-retry-validation").on("click", runValidation);
  $("#builder-apply-validation-fix").on("click", function () {
    var previous=selected && selected.validation ? $.extend(true,{},selected.validation) : null;
    if (!selected || !pendingValidationFix) {
      setFeedback("No safe automatic correction is available. Follow the displayed guidance and edit the SPL manually.", "error");
      return;
    }
    var failedResolution=selected.validation && selected.validation.resolution;
    if (!failedResolution || !applyValidationCorrection(selected,failedResolution)) {
      setFeedback("The recommended correction is no longer applicable. Review the current SPL manually.","error");
      return;
    }
    var artifact=currentArtifact();
    if (!artifact) { return; }
    artifact.validation_history=Array.isArray(artifact.validation_history) ? artifact.validation_history : [];
    if (previous) { artifact.validation_history.push(previous); }
    artifact.validation=null;
    artifact.status=artifact.state==="tuning" ? "tuning" : "draft";
    artifact.state=artifact.status;
    selected=artifact;
    saveArtifact(artifact);
    renderArtifact(artifact);
    setFeedback("Recommended correction applied. Review the updated SPL and time range, then run validation again.", "success");
    $("#builder-run-validation").focus();
  });

  $("#copy-generated-spl").on("click", function () {
    var artifact = currentArtifact(); if (artifact) { copyText(artifact.spl, $(this)); }
  });
  $("#copy-generated-json").on("click", function () {
    var artifact = currentArtifact(); if (artifact) { copyText(JSON.stringify(artifact, null, 2), $(this)); }
  });
  $("#download-generated-json").on("click", function () {
    var artifact = currentArtifact();
    if (!artifact) { return; }
    var blob = new Blob([JSON.stringify(artifact, null, 2)], {type:"application/json"});
    var link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = artifact.id + ".json";
    link.click();
    window.setTimeout(function () { URL.revokeObjectURL(link.href); }, 0);
  });

  function initializeBuilder(attempt) {
    Store = window.DEILifecycleStore;
    if (!Store && attempt < 40) {
      window.setTimeout(function () { initializeBuilder(attempt + 1); }, 50);
      return;
    }
    if (!Store) {
      $("#generator-empty").text("Shared lifecycle store is unavailable. Reload the app or contact a Splunk administrator.");
      return;
    }
    Store.load().done(function (sharedRecords) {
      var local = storedArtifacts();
      var merged = {};
      local.concat(sharedRecords || []).forEach(function (artifact) {
        if (artifact && artifact.id) { merged[artifact.id] = artifact; }
      });
      window.localStorage.setItem(ARTIFACT_KEY, JSON.stringify(Object.keys(merged).map(function (key) { return merged[key]; })));
      populateDetectionSelector();
      $("#generator-es-state").attr("title", "Persistence: " + Store.mode());
    });
  }

  initializeBuilder(0);
});

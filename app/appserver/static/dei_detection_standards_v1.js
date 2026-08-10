(function (root) {
  "use strict";

  var VERSION="1.0.0";
  function issue(id,severity,title,detail,remediation,automatic) {
    return {id:id,severity:severity,title:title,detail:detail,remediation:remediation,automatic:!!automatic};
  }
  function has(text,pattern) { return pattern.test(String(text||"")); }
  function evaluate(artifact) {
    artifact=artifact||{}; var spl=String(artifact.spl||"").trim(); var schedule=artifact.schedule||{};
    var issues=[], scores={correctness:100,performance:100,telemetry:100,scheduling:100,analyst_context:100,mitre:100,es_readiness:100};
    function add(bucket,value) { issues.push(value); scores[bucket]=Math.max(0,scores[bucket]-(value.severity==="error"?30:value.severity==="warning"?15:6)); }
    if(!spl) add("correctness",issue("spl.empty","error","Detection SPL is empty","No executable search was generated.","Return to the qualified recommendation and generate the draft again."));
    if(spl && !/^(search\s+|\|\s*(tstats|from|inputlookup)\b)/i.test(spl)) add("correctness",issue("spl.generating-command","error","Missing supported generating command","The query does not begin with search, tstats, from, or an approved lookup.","Add an explicit generating command before pipeline commands.",true));
    if(has(spl,/\bindex\s*=\s*\*/i)) add("performance",issue("scope.index-star","error","Unbounded index scope","index=* can create expensive searches and ambiguous evidence.","Replace it with the indexes confirmed by telemetry discovery."));
    if(!has(spl,/\b(index|sourcetype)\s*=|\|\s*tstats\b/i)) add("telemetry",issue("scope.telemetry","error","No explicit telemetry scope","The query does not identify an index, sourcetype, or accelerated data model.","Use the discovered sourcetypes or an approved data model."));
    if(has(spl,/\|\s*transaction\b/i)) add("performance",issue("command.transaction","warning","Expensive transaction command","transaction can consume substantial memory on scheduled detections.","Prefer stats, streamstats, or eventstats with explicit grouping and time bounds."));
    if(has(spl,/\|\s*join\b/i)) add("performance",issue("command.join","warning","Join requires review","join can truncate subsearch results and increase runtime.","Prefer stats-based correlation, lookup, or append-based logic where semantics allow."));
    if(has(spl,/\|\s*sort\s+(?!0\b)/i)) add("performance",issue("command.sort-limit","warning","Sort may truncate results","The default sort result limit can hide detection evidence.","Remove sort or use sort 0 only after aggregation when all rows are required."));
    if(has(spl,/dei_generation_blocker/i)) add("correctness",issue("template.unsupported","error","No explicit analytic template","This detection would otherwise use generic non-detection SPL.","Add and test a detection-specific analytic family before validation."));
    if(has(spl,/\|\s*stats\b[^\n]*\bby\b/i) && !has(spl,/\|\s*fillnull\b/i)) add("analyst_context",issue("stats.null-group","warning","Grouping fields may discard events","Transforming commands omit events whose by-fields are null.","Normalize or fill required grouping entities before stats."));
    if(has(spl,/\b(?:Workflow|Severity|Resources)\.[A-Za-z]/) && !has(spl,/'(?:Workflow|Severity|Resources)\.[^']+'/)) add("correctness",issue("field.dotted","warning","Dotted field requires normalization review","Complex source-native fields should be quoted when used in eval expressions and normalized before output.","Quote the source field and expose a stable normalized field."));
    if(!has(spl,/\|\s*(where|search)\b[^\n]*(>=|<=|>|<|IN\s*\()/i)) add("correctness",issue("logic.threshold","warning","Detection condition is not explicit","The query does not expose a clear threshold or behavior predicate after telemetry selection.","Add a reviewed behavioral condition or threshold supported by baseline evidence."));
    if(has(spl,/\|\s*table\b/i) && !has(spl,/\b(_time|first_seen|last_seen)\b/i)) add("analyst_context",issue("context.time","warning","Result time context is missing","Analysts need event time or first/last-seen fields for investigation.","Return _time or calculated first_seen and last_seen fields."));
    if(!schedule.cron) add("scheduling",issue("schedule.cron","error","Cron schedule is missing","The detection cannot run consistently without a schedule.","Generate or enter an explicit cron expression."));
    if(!schedule.earliest||!schedule.latest) add("scheduling",issue("schedule.window","error","Search window is incomplete","A scheduled detection needs explicit earliest and latest boundaries.","Set a bounded window that accounts for the run interval and ingestion delay."));
    if(schedule.latest==="now") add("scheduling",issue("schedule.delay","warning","No ingestion-delay allowance","Searching through now can miss events that have not become searchable.","Measure ingestion latency and use an appropriate latest-time delay."));
    var mitre=artifact.mitre_attack||[];
    if(!mitre.length && !has(spl,/mitre_attack_id/i)) add("mitre",issue("mitre.missing","error","MITRE mapping is missing","The detection has no ATT&CK technique context.","Select a mapped recommendation or add a reviewed technique mapping."));
    ["mitre_attack_ttp","mitre_attack_id","mitre_attack_description"].forEach(function(field){
      if(!has(spl,new RegExp("\\b"+field+"\\b","i"))) add("mitre",issue("output."+field,"warning","Missing "+field+" output","Analysts will not receive this context in standard Splunk results.","Add the field to the final detection output."));
    });
    if(!has(spl,/\b(user|src_ip|dest_ip|host|process_name|file_name)\b/i)) add("analyst_context",issue("context.entity","warning","No investigation entity identified","The result does not expose a primary user, system, network, process, or file entity.","Return at least one stable investigation entity."));
    if(artifact.enterprise_security) {
      var es=artifact.enterprise_security;
      if(!es.security_domain) add("es_readiness",issue("es.domain","error","ES security domain is missing","Enterprise Security requires classification for investigation workflows.","Select the domain matching the detection telemetry."));
      if(!es.risk_based_alerting||!es.risk_based_alerting.risk_object_field) add("es_readiness",issue("es.risk-object","error","ES risk object is incomplete","RBA cannot attribute risk without an entity field and type.","Select a returned entity and configure its risk object type."));
    }
    var errors=issues.filter(function(x){return x.severity==="error";}).length;
    var warnings=issues.filter(function(x){return x.severity==="warning";}).length;
    var total=Math.round(Object.keys(scores).reduce(function(sum,key){return sum+scores[key];},0)/Object.keys(scores).length);
    return {version:VERSION,status:errors?"blocked":warnings?"review":"passed",score:total,scores:scores,errors:errors,warnings:warnings,issues:issues,evaluated_at:new Date().toISOString()};
  }
  root.DEIDetectionStandards={version:VERSION,evaluate:evaluate};
}(window));

require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var tactics = [
    ["TA0043", "Reconnaissance"], ["TA0042", "Resource Development"], ["TA0001", "Initial Access"],
    ["TA0002", "Execution"], ["TA0003", "Persistence"], ["TA0004", "Privilege Escalation"],
    ["TA0005", "Stealth"], ["TA0112", "Defense Impairment"], ["TA0006", "Credential Access"],
    ["TA0007", "Discovery"], ["TA0008", "Lateral Movement"], ["TA0009", "Collection"],
    ["TA0011", "Command and Control"], ["TA0010", "Exfiltration"], ["TA0040", "Impact"]
  ];
  var techniqueMap = {
    "T1110": {name:"Brute Force", tactics:["TA0006"]}, "T1110.003": {name:"Password Spraying", tactics:["TA0006"]},
    "T1558.003": {name:"Kerberoasting", tactics:["TA0006"]}, "T1059.001": {name:"PowerShell", tactics:["TA0002"]},
    "T1098": {name:"Account Manipulation", tactics:["TA0003","TA0004"]},
    "T1078": {name:"Valid Accounts", tactics:["TA0001","TA0003","TA0004","TA0005"]},
    "T1078.004": {name:"Cloud Accounts", tactics:["TA0001","TA0003","TA0004","TA0005"]},
    "T1562.008": {name:"Disable or Modify Cloud Logs", tactics:["TA0112"]}, "T1530": {name:"Data from Cloud Storage", tactics:["TA0009"]},
    "T1567": {name:"Exfiltration Over Web Service", tactics:["TA0010"]}, "T1021": {name:"Remote Services", tactics:["TA0008"]},
    "T1548.003": {name:"Sudo and Sudo Caching", tactics:["TA0004"]}, "T1071.004": {name:"DNS", tactics:["TA0011"]},
    "T1190": {name:"Exploit Public-Facing Application", tactics:["TA0001"]}, "T1041": {name:"Exfiltration Over C2 Channel", tactics:["TA0010"]},
    "T1566": {name:"Phishing", tactics:["TA0001"]}, "T1610": {name:"Deploy Container", tactics:["TA0002"]}
  };
  var tacticPurpose = {
    TA0001:"Exposes attempts to establish unauthorized entry into the environment.", TA0002:"Surfaces malicious or unauthorized code execution before it progresses.",
    TA0003:"Detects changes and behaviors intended to preserve an adversary foothold.", TA0004:"Identifies attempts to gain stronger permissions or administrative control.",
    TA0005:"Exposes activity intended to blend in, conceal access, or evade normal scrutiny.", TA0112:"Detects attempts to weaken logging, monitoring, or other defensive mechanisms.",
    TA0006:"Protects identities and credentials from theft, guessing, or credential abuse.", TA0007:"Reveals attempts to learn about systems, accounts, services, and environment structure.",
    TA0008:"Detects movement from one system, account, or service to another.", TA0009:"Provides visibility into adversary collection of data before theft or misuse.",
    TA0011:"Detects communication paths used to control compromised systems.", TA0010:"Identifies attempts to move protected information outside trusted boundaries.",
    TA0040:"Surfaces activity intended to disrupt, manipulate, or destroy business systems and data."
  };
  function escapeHtml(value) { return String(value == null ? "" : value).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"); }
  function renderEmptySwimlane() { $("#mitre-swimlane").html(tactics.map(function(t){return '<article class="dei-mitre-tactic" data-tactic="'+t[0]+'"><span>'+t[0]+'</span><strong>'+t[1]+'</strong><small>No mapped detection</small></article>';}).join("")); }
  function mappedTactics(techniques) { var found={}; (techniques||[]).forEach(function(id){var e=techniqueMap[id]; if(e){e.tactics.forEach(function(t){found[t]=true;});}}); return found; }
  function renderSelection(item) {
    var techniques=item.mitre_techniques||[], active=mappedTactics(techniques);
    $("#mitre-selection").text(item.name);
    $("#mitre-swimlane").html(tactics.map(function(t){var covered=!!active[t[0]]; var names=techniques.filter(function(id){return techniqueMap[id]&&techniqueMap[id].tactics.indexOf(t[0])!==-1;}).map(function(id){return id+" · "+techniqueMap[id].name;}); return '<article class="dei-mitre-tactic '+(covered?'covered':'')+'"><span>'+t[0]+'</span><strong>'+t[1]+'</strong><small>'+escapeHtml(names.length?names.join(" / "):"No mapped detection")+'</small></article>';}).join(""));
    $("#protection-title").text(item.name); $("#protection-summary").text(item.why||"Detection coverage for the selected ATT&CK behavior.");
    $("#protection-techniques").html(techniques.length?techniques.map(function(id){var m=techniqueMap[id]; return '<span class="dei-technique">'+escapeHtml(id+(m?' · '+m.name:''))+'</span>';}).join(""):'<span class="dei-technique muted">No ATT&CK technique mapped</span>');
    var outcomes=Object.keys(active).map(function(id){var t=tactics.filter(function(x){return x[0]===id;})[0]; return '<div class="dei-protection-outcome"><strong>'+escapeHtml(t?t[1]:id)+'</strong><p>'+escapeHtml(tacticPurpose[id]||"Provides detection visibility at this ATT&CK stage.")+'</p></div>';}).join("");
    $("#protection-outcomes").html(outcomes||'<p class="dei-empty">This detection does not yet have an ATT&CK technique mapping.</p>');
    document.getElementById("dei-mitre-section").scrollIntoView({behavior:"smooth",block:"start"});
  }
  function attachDetectionSelectors() { $("#recommendations").off("click.deiMitre").on("click.deiMitre",".dei-recommendation",function(){var index=$(this).index(), report=window.DEIRecommendationReport; if(report&&report.recommendations&&report.recommendations[index]){$(".dei-recommendation").removeClass("selected");$(this).addClass("selected");renderSelection(report.recommendations[index]);}}); }
  $(document).ajaxSuccess(function(event,xhr,settings){
    if (!settings || String(settings.url||"").indexOf("/dei/v1/recommendations") === -1) { return; }
    var response=xhr.responseJSON||{}; if(typeof response.payload==="string"){try{response=JSON.parse(response.payload);}catch(error){return;}}
    window.DEIRecommendationReport=response; attachDetectionSelectors();
  });
  renderEmptySwimlane(); attachDetectionSelectors(); window.DEIRenderMitreSelection=renderSelection;
});

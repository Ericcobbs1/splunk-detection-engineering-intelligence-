require(["jquery","splunkjs/mvc/simplexml/ready!"],function($){"use strict";
  var lastSpl="";
  function resizeSpl(){
    var field=document.getElementById("generator-spl");
    if(!field){return;}
    var value=field.value||"";
    field.style.height="auto";
    field.style.height=Math.max(240,field.scrollHeight+4)+"px";
    field.setAttribute("aria-label","Detection SPL editor; automatically sized to the generated search and manually resizable");
    lastSpl=value;
  }
  function recommendedName(){
    var title=String($("#generator-title").text()||$("#lifecycle-action-title").text()||"Recommended Detection").trim();
    title=title.replace(/^Select a detection$/i,"Recommended Detection").replace(/^Current required action$/i,"Recommended Detection");
    return "DEI - "+title.replace(/^DEI\s*-\s*/i,"");
  }
  function enhanceDeploymentId(){
    var field=$("#lifecycle-external-id");
    if(!field.length){return;}
    var example=recommendedName();
    field.attr("placeholder",example).attr("aria-describedby","lifecycle-external-id-help");
    if(!$("#lifecycle-external-id-help").length){
      field.after('<small id="lifecycle-external-id-help">Enter the exact deployed Splunk object name. Example: <code>'+escapeHtml(example)+'</code>. Platform saved searches are under Settings → Searches, Reports, and Alerts; ES correlation searches are under Configure → Content → Content Management.</small>');
    }
  }
  function enhanceMonitoring(){
    if(!$("#lifecycle-health").length||$("#dei-monitoring-field-guide").length){return;}
    var guide='<aside id="dei-monitoring-field-guide" class="dei-context-guide"><strong>How to record monitoring evidence</strong><dl>'+
      '<div><dt>Health</dt><dd>Overall condition based on the evidence entered for this review period.</dd></div>'+
      '<div><dt>Result volume</dt><dd>Results returned by the detection during the review period.</dd></div>'+
      '<div><dt>Runtime ms</dt><dd>Representative execution time from Job Inspector or search history.</dd></div>'+
      '<div><dt>True positives</dt><dd>Results confirmed as legitimate security findings.</dd></div>'+
      '<div><dt>False positives</dt><dd>Benign or incorrect matches confirmed by analyst review.</dd></div>'+
      '<div><dt>Rationale</dt><dd>Document health context; a specific objective is required for Tuning or retirement.</dd></div></dl></aside>';
    $("#lifecycle-health").closest(".dei-action-fields-row").before(guide);
  }
  function escapeHtml(value){return String(value||"").replace(/[&<>"']/g,function(ch){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch];});}
  $(document).on("input","#generator-spl",resizeSpl);
  $(document).on("dei:workflow-detection-selected dei:lifecycle-records-updated dei:lifecycle-action-complete",function(){window.setTimeout(function(){resizeSpl();enhanceDeploymentId();enhanceMonitoring();},50);});
  var observer=new MutationObserver(function(){resizeSpl();enhanceDeploymentId();enhanceMonitoring();});
  observer.observe(document.body,{childList:true,subtree:true,characterData:true});
  window.setInterval(function(){var field=document.getElementById("generator-spl");if(field&&field.value!==lastSpl){resizeSpl();}enhanceDeploymentId();enhanceMonitoring();},800);
  resizeSpl();enhanceDeploymentId();enhanceMonitoring();
});
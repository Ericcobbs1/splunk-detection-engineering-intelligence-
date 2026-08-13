require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";
  var KEY="dei.colorScheme";
  function stored(){ try { return window.localStorage.getItem(KEY); } catch(error){ return null; } }
  function save(value){ try { window.localStorage.setItem(KEY,value); } catch(error){} }
  function normalized(value){ return value==="light" ? "light" : "dark"; }
  function apply(value,announce){
    var scheme=normalized(value);
    document.documentElement.setAttribute("data-dei-theme",scheme);
    $(".dei-shell").attr("data-dei-theme",scheme);
    $("#dei-theme-toggle").attr("aria-pressed",scheme==="light"?"true":"false")
      .attr("aria-label",scheme==="light"?"Switch to dark mode":"Switch to light mode")
      .html('<span aria-hidden="true">'+(scheme==="light"?"☀":"◐")+'</span><b>'+(scheme==="light"?"Light":"Dark")+'</b>');
    save(scheme);
    if(announce){ $(document).trigger("dei:theme-changed",[scheme]); }
  }
  function ensureToggle(){
    if($("#dei-theme-toggle").length) return;
    var control='<button id="dei-theme-toggle" class="dei-theme-toggle" type="button" aria-pressed="false"><span aria-hidden="true">◐</span><b>Dark</b></button>';
    var toolbar=$(".dei-workspace-controls").first();
    if(toolbar.length){ toolbar.append(control); }
    else {
      var bar=$(".dei-product-bar").first();
      if(bar.length) bar.append('<div class="dei-theme-standalone" aria-label="Appearance">'+control+'</div>');
      else $(".dei-shell").first().prepend('<div class="dei-theme-standalone" aria-label="Appearance">'+control+'</div>');
    }
    apply(stored()||"dark",false);
  }
  apply(stored()||"dark",false);
  ensureToggle();
  new MutationObserver(ensureToggle).observe(document.body,{childList:true,subtree:true});
  $(document).on("click","#dei-theme-toggle",function(){ apply(document.documentElement.getAttribute("data-dei-theme")==="light"?"dark":"light",true); });
});

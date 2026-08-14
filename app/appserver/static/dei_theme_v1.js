require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  function enforceDarkTheme() {
    document.documentElement.setAttribute("data-dei-theme", "dark");
    $(".dei-shell").attr("data-dei-theme", "dark");
    $("#dei-theme-toggle,.dei-theme-standalone").remove();
    try { window.localStorage.removeItem("dei.colorScheme"); } catch (error) {}
  }

  enforceDarkTheme();
  new MutationObserver(enforceDarkTheme).observe(document.body, {childList: true, subtree: true});
});

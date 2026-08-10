require(["splunkjs/mvc/simplexml/ready!"], function () {
  "use strict";
  var destination = "detection_workflow" + String(window.location.search || "") + String(window.location.hash || "");
  var link = document.getElementById("detection-builder-redirect-link");
  if (link) { link.setAttribute("href", destination); }
  window.location.replace(destination);
});

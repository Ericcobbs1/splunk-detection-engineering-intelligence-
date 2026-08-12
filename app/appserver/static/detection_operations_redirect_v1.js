require(["splunkjs/mvc/simplexml/ready!"], function () {
  "use strict";
  var destination = "detection_catalog" + String(window.location.search || "") + String(window.location.hash || "");
  window.location.replace(destination);
});

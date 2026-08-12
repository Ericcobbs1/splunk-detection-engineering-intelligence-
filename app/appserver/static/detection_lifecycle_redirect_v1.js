require(["splunkjs/mvc/simplexml/ready!"], function () {
  "use strict";
  var destination = "detection_catalog" + String(window.location.search || "") + "#lifecycle-map";
  window.location.replace(destination);
});

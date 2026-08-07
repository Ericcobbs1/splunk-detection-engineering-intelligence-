require(["jquery", "splunkjs/mvc/simplexml/ready!"], function ($) {
  "use strict";

  var STORAGE_KEY = "dei.latestRecommendationReport";
  var STORAGE_TIME_KEY = "dei.latestRecommendationTime";

  $(document).ajaxSuccess(function (_event, _xhr, settings, data) {
    var url = String(settings && settings.url || "");
    if (url.indexOf("/dei/v1/recommendations") === -1) { return; }
    var payload = data;
    if (payload && typeof payload.payload === "string") {
      try { payload = JSON.parse(payload.payload); } catch (error) { return; }
    }
    if (!payload || !payload.recommendations) { return; }
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
      window.localStorage.setItem(STORAGE_TIME_KEY, String(Date.now()));
    } catch (error) {
      // Storage failures must never interfere with the primary analysis workflow.
    }
  });
});

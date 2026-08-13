(function (root, factory) {
  "use strict";
  root.DEILifecycleStore = factory(root.jQuery, root.Splunk);
}(window, function ($, Splunk) {
  "use strict";

  var COLLECTION = "dei_lifecycle_records";
  var FALLBACK_KEY = "dei.detectionDraftArtifacts";
  var mode = "loading";

  function persistenceWarning(operation, detail) {
    mode = "browser fallback";
    $(document).trigger("dei:persistence-warning", [{
      collection:COLLECTION, operation:operation, mode:mode,
      message:"Splunk KV Store is unavailable. Changes are saved only in this browser and are not shared or governed.",
      detail:detail || ""
    }]);
  }

  function safeJson(value, fallback) {
    try { return JSON.parse(value || "null") || fallback; } catch (error) { return fallback; }
  }

  function username() {
    try { return Splunk.util.getConfigValue("USERNAME") || "unknown"; } catch (error) { return "unknown"; }
  }

  function endpoint(key) {
    var parts = ["splunkd", "__raw", "servicesNS", "-",
      "splunk_detection_engineering_intelligence", "dei", "v1", "storage"];
    return Splunk.util.make_url.apply(Splunk.util, parts);
  }

  function request(payload) {
    return $.ajax({url:endpoint(), method:"POST", data:JSON.stringify(payload), dataType:"json",
      timeout:30000, headers:headers()}).then(function(response) {
        return response&&typeof response.payload==="string"?JSON.parse(response.payload):response;
      });
  }

  function headers() {
    var value = "";
    try { value = Splunk.util.getConfigValue("FORM_KEY") || ""; } catch (error) { value = ""; }
    return {"X-Splunk-Form-Key":value, "Content-Type":"application/json"};
  }

  function fallbackRecords() {
    var records = safeJson(root.localStorage.getItem(FALLBACK_KEY), []);
    return Array.isArray(records) ? records : [];
  }

  function saveFallback(record) {
    var records = fallbackRecords().filter(function (item) {
      return String(item._key || item.id) !== String(record._key || record.id);
    });
    records.push(record);
    root.localStorage.setItem(FALLBACK_KEY, JSON.stringify(records));
    persistenceWarning("write");
    record._persistence = {durable:false, mode:mode};
    return record;
  }

  function load() {
    var deferred = $.Deferred();
    request({resource:"lifecycle", operation:"read"})
      .done(function (response) {
        mode = "Splunk KV Store";
        deferred.resolve(response&&Array.isArray(response.records) ? response.records : []);
      })
      .fail(function (xhr) {
        persistenceWarning("load", xhr&&xhr.status||"");
        deferred.resolve(fallbackRecords());
      });
    return deferred.promise();
  }

  function write(record) {
    var deferred = $.Deferred();
    var key = String(record._key || record.id || "").replace(/^dei-/, "");
    var payload = $.extend(true, {}, record, {_key:key, updated_at:new Date().toISOString(), updated_by:username()});
    if (!payload.created_at) { payload.created_at = payload.updated_at; }
    request({resource:"lifecycle", operation:"upsert", record:payload})
      .done(function () { mode = "Splunk KV Store"; payload._persistence={durable:true,mode:mode}; deferred.resolve(payload); })
      .fail(function () { deferred.resolve(saveFallback(payload)); });
    return deferred.promise();
  }

  function appendHistory(record, event, detail) {
    var copy = $.extend(true, {}, record);
    copy.history = Array.isArray(copy.history) ? copy.history : [];
    copy.history.push({event:event, at:new Date().toISOString(), actor:username(), detail:detail || ""});
    return copy;
  }

  function remove(key) {
    var deferred = $.Deferred();
    request({resource:"lifecycle", operation:"delete", key:key})
      .done(function () { deferred.resolve(); })
      .fail(function (xhr) {
        var records = fallbackRecords().filter(function (item) {
          return String(item._key || item.id) !== String(key);
        });
        root.localStorage.setItem(FALLBACK_KEY, JSON.stringify(records));
        persistenceWarning("remove", xhr&&xhr.status||"");
        deferred.resolve();
      });
    return deferred.promise();
  }

  return {
    collection:COLLECTION,
    load:load,
    write:write,
    remove:remove,
    appendHistory:appendHistory,
    username:username,
    mode:function () { return mode; }
  };
}));

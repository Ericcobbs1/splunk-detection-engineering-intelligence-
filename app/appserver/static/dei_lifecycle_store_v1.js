(function (root, factory) {
  "use strict";
  root.DEILifecycleStore = factory(root.jQuery, root.Splunk);
}(window, function ($, Splunk) {
  "use strict";

  var COLLECTION = "dei_lifecycle_records";
  var FALLBACK_KEY = "dei.detectionDraftArtifacts";
  var mode = "loading";
  var recoveryPending = false;

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
        var value=response; var depth=0;
        while(value&&typeof value==="object"&&value.payload!==undefined&&depth<3) {
          value=typeof value.payload==="string"?safeJson(value.payload,{}):value.payload; depth+=1;
        }
        return value;
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
    record = sanitize(record);
    var records = fallbackRecords().filter(function (item) {
      return String(item._key || item.id) !== String(record._key || record.id);
    });
    records.push(record);
    root.localStorage.setItem(FALLBACK_KEY, JSON.stringify(records));
    persistenceWarning("write");
    record._persistence = {durable:false, mode:mode};
    return record;
  }

  function sanitize(value) {
    if (Array.isArray(value)) { return value.map(sanitize); }
    if (!value || typeof value !== "object") { return value; }
    return Object.keys(value).reduce(function (copy, key) {
      if (["sample_results", "raw_results", "_raw"].indexOf(key) === -1) { copy[key] = sanitize(value[key]); }
      return copy;
    }, {});
  }

  function responseMessage(xhr) {
    var body=xhr&&xhr.responseJSON;
    if (body&&typeof body.payload==="string") { body=safeJson(body.payload,{}); }
    if (body&&body.payload&&typeof body.payload==="object") { body=body.payload; }
    return String(body&&body.error||body&&body.message||"").trim();
  }

  function load() {
    var deferred = $.Deferred();
    request({resource:"lifecycle", operation:"read"})
      .done(function (response) {
        mode = "Splunk KV Store";
        var durable=response&&Array.isArray(response.records) ? response.records :
          (response&&response.data&&Array.isArray(response.data.records)?response.data.records:[]);
        var fallback=fallbackRecords();
        recoveryPending=fallback.some(function(local){var key=String(local._key||local.id||"");return key&&!durable.some(function(shared){return String(shared._key||shared.id||"")===key&&String(shared.updated_at||"")===String(local.updated_at||"");});});
        if(recoveryPending)$(document).trigger("dei:persistence-recovery-required",[{count:fallback.length,message:"Browser recovery records differ from shared KV Store. Review them before overwriting governed data."}]);
        deferred.resolve(durable);
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
    request({resource:"lifecycle", operation:"upsert", expected_revision:record._revision, record:payload})
      .done(function (response) { mode = "Splunk KV Store"; recoveryPending=false; payload=$.extend(true,{},payload,response&&response.record||{}); payload._persistence={durable:true,mode:mode}; deferred.resolve(payload); })
      .fail(function (xhr) {
        var status=xhr&&xhr.status||0; var detail=responseMessage(xhr);
        if (status>=400&&status<500) {
          deferred.reject({message:detail||"The governed lifecycle change was rejected. Reload the record and correct the highlighted requirement.",status:status});
          return;
        }
        var fallback=saveFallback(payload);
        deferred.reject({message:"Shared lifecycle persistence is unavailable. A sanitized, non-durable recovery copy was saved in this browser.",status:status,fallback:fallback});
      });
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
        deferred.reject({message:"Shared lifecycle deletion failed. The governed record was not confirmed deleted.",status:xhr&&xhr.status||0});
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
    mode:function () { return mode; },
    recoveryPending:function () { return recoveryPending; }
  };
}));

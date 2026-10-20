/* NetMon web front-end: Chart.js rendering, live WebSocket state and the
   alert SSE stream. No build step; plain DOM APIs only. */
(function () {
  "use strict";

  /* -- HTMX JSON extension -------------------------------------------------
     htmx submits hx-vals as form data by default, while every NetMon write
     endpoint expects a JSON body. This mirrors the official htmx json-enc
     extension (the templates enable it with hx-ext="json-enc"). */
  if (typeof htmx !== "undefined") {
    htmx.defineExtension("json-enc", {
      onEvent: function (name, evt) {
        if (name === "htmx:configRequest") {
          evt.detail.headers["Content-Type"] = "application/json";
        }
      },
      encodeParameters: function (xhr, parameters) {
        xhr.overrideMimeType("text/json");
        return JSON.stringify(parameters);
      }
    });
  }

  var SERIES_COLORS = ["#00B4D8", "#00D084", "#FFB800", "#FF4757", "#8B949E", "#7C4DFF", "#FF7AB2"];
  var MAX_ALERTS = 20;
  var MONO = '"JetBrains Mono", ui-monospace, monospace';

  var live = {
    socket: null,
    attempts: 0,
    alerts: null,
  };

  function qs(selector, root) { return (root || document).querySelector(selector); }
  function qsa(selector, root) { return Array.prototype.slice.call((root || document).querySelectorAll(selector)); }

  /* -- formatting --------------------------------------------------------- */

  var BYTE_UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];

  function formatBytes(value, precision) {
    if (value === null || value === undefined || isNaN(value)) { return "--"; }
    var amount = Math.abs(Number(value));
    var sign = Number(value) < 0 ? "-" : "";
    var digits = precision === undefined ? 1 : precision;
    var index = 0;
    while (amount >= 1024 && index < BYTE_UNITS.length - 1) { amount /= 1024; index += 1; }
    var text = index === 0 ? String(Math.round(amount)) : amount.toFixed(digits);
    return sign + text + " " + BYTE_UNITS[index];
  }

  function formatValue(value, format) {
    if (value === null || value === undefined || isNaN(value)) { return "--"; }
    if (format === "rate") { return formatBytes(value) + "/s"; }
    if (format === "bytes") { return formatBytes(value); }
    if (format === "percent") { return Number(value).toFixed(0) + "%"; }
    if (Math.abs(value) >= 1000) { return Number(value).toFixed(0); }
    if (Math.abs(value) >= 10) { return Number(value).toFixed(1); }
    return Number(value).toFixed(2);
  }

  function shortTime(iso) {
    if (typeof iso !== "string" || iso.length < 16) { return String(iso || ""); }
    return iso.slice(11, 16);
  }

  /* -- toast -------------------------------------------------------------- */

  function toast(message) {
    var node = qs("#toast");
    if (!node) { return; }
    node.textContent = message;
    node.hidden = false;
    window.clearTimeout(node._hideTimer);
    node._hideTimer = window.setTimeout(function () { node.hidden = true; }, 6000);
  }

  /* -- charts ------------------------------------------------------------- */

  function metricsUrl(canvas) {
    if (canvas.dataset.url) { return canvas.dataset.url; }
    var params = new URLSearchParams();
    if (canvas.dataset.range) { params.set("range", canvas.dataset.range); }
    if (canvas.dataset.interval) { params.set("interval", canvas.dataset.interval); }
    String(canvas.dataset.fields || "").split(",").forEach(function (field) {
      if (field.trim()) { params.append("field", field.trim()); }
    });
    String(canvas.dataset.tags || "").split(",").forEach(function (tag) {
      if (tag.trim()) { params.append("tag", tag.trim()); }
    });
    return "/api/metrics/" + encodeURIComponent(canvas.dataset.measurement || "health_score") + "?" + params.toString();
  }

  function chartOptions(format) {
    return {
      responsive: true,
      animation: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: {
          labels: { color: "#C9D1D9", boxWidth: 14, boxHeight: 3, font: { family: MONO, size: 11 } },
        },
        tooltip: {
          callbacks: {
            label: function (context) {
              return context.dataset.label + ": " + formatValue(context.parsed.y, format);
            },
          },
        },
      },
      scales: {
        x: {
          grid: { color: "rgba(139,148,158,0.12)" },
          ticks: { color: "#8B949E", maxTicksLimit: 6, maxRotation: 0, font: { family: MONO, size: 10 } },
        },
        y: {
          grid: { color: "rgba(139,148,158,0.12)" },
          ticks: {
            color: "#8B949E",
            font: { family: MONO, size: 10 },
            callback: function (value) { return formatValue(value, format); },
          },
        },
      },
    };
  }

  function applySeries(canvas, chart, payload) {
    var series = payload.series || [];
    var labels = [];
    for (var index = 0; index < series.length; index += 1) {
      if ((series[index].points || []).length > labels.length) {
        labels = series[index].points.map(function (point) { return shortTime(point.time); });
      }
    }
    chart.data.labels = labels;
    chart.data.datasets = series.map(function (item, position) {
      var lookup = {};
      (item.points || []).forEach(function (point) { lookup[shortTime(point.time)] = point.value; });
      var color = SERIES_COLORS[position % SERIES_COLORS.length];
      return {
        label: item.label || item.field,
        data: labels.map(function (label) { return lookup[label]; }),
        borderColor: color,
        backgroundColor: color,
        borderWidth: 1.5,
        pointRadius: 0,
        tension: 0.25,
        spanGaps: true,
      };
    });
    chart.update("none");

    var wrap = canvas.closest(".chart-wrap");
    var empty = wrap ? qs(".chart-empty", wrap) : null;
    if (empty) { empty.hidden = labels.length > 0; }
  }

  function createChart(canvas) {
    if (typeof Chart === "undefined") {
      var wrap = canvas.closest(".chart-wrap");
      var empty = wrap ? qs(".chart-empty", wrap) : null;
      if (empty) { empty.hidden = false; empty.textContent = "chart library unavailable (CDN offline)"; }
      return;
    }
    var format = canvas.dataset.format || "number";
    var chart = new Chart(canvas.getContext("2d"), {
      type: "line",
      data: { labels: [], datasets: [] },
      options: chartOptions(format),
    });

    function refresh() {
      if (!canvas.isConnected) {
        chart.destroy();
        window.clearInterval(timer);
        return;
      }
      fetch(metricsUrl(canvas), { headers: { Accept: "application/json" } })
        .then(function (response) {
          if (!response.ok) { throw new Error("HTTP " + response.status); }
          return response.json();
        })
        .then(function (payload) { applySeries(canvas, chart, payload); })
        .catch(function () { /* keep the last good rendering */ });
    }

    var timer = window.setInterval(refresh, Math.max(3000, parseInt(canvas.dataset.refresh || "15000", 10)));
    refresh();
  }

  function initCharts(root) {
    qsa("canvas[data-chart]", root).forEach(function (canvas) {
      if (canvas.dataset.chartInit === "1") { return; }
      canvas.dataset.chartInit = "1";
      createChart(canvas);
    });
  }

  /* -- live state (WebSocket) --------------------------------------------- */

  function setLiveStatus(state, label) {
    var status = qs("#live-status");
    if (status) { status.dataset.state = state; status.title = "live socket: " + label; }
    var labelNode = qs("#live-label");
    if (labelNode) { labelNode.textContent = label; }
  }

  function resolvePath(state, path) {
    return path.split(".").reduce(function (node, part) {
      if (node === null || node === undefined) { return undefined; }
      return node[part];
    }, state);
  }

  function applyState(state) {
    qsa("[data-live]").forEach(function (node) {
      var value = resolvePath(state, node.dataset.live);
      if (value === null || value === undefined) { value = "--"; }
      if (typeof value === "number") { value = Math.round(value * 10) / 10; }
      node.textContent = String(value);
    });
    var status = qs("#live-status");
    if (status) { status.dataset.state = state.state || "unknown"; }
    setLiveStatus(state.state || "unknown", "live");
    document.dispatchEvent(new CustomEvent("netmon:state", { detail: state }));
  }

  function connectLive() {
    if (!("WebSocket" in window)) { setLiveStatus("unknown", "no websocket"); return; }
    if (live.socket && (live.socket.readyState === 0 || live.socket.readyState === 1)) { return; }
    var protocol = window.location.protocol === "https:" ? "wss" : "ws";
    var socket;
    try {
      socket = new WebSocket(protocol + "://" + window.location.host + "/ws/live");
    } catch (error) {
      scheduleReconnect();
      return;
    }
    live.socket = socket;

    socket.onopen = function () {
      live.attempts = 0;
      setLiveStatus("unknown", "live");
    };
    socket.onmessage = function (event) {
      try { applyState(JSON.parse(event.data)); } catch (error) { /* ignore malformed frame */ }
    };
    socket.onclose = function () {
      live.socket = null;
      setLiveStatus("unknown", "reconnecting");
      scheduleReconnect();
    };
    socket.onerror = function () { /* onclose schedules the retry */ };
  }

  function scheduleReconnect() {
    var delay = Math.min(30000, 1000 * Math.pow(2, live.attempts));
    live.attempts += 1;
    window.setTimeout(connectLive, delay + Math.random() * 500);
  }

  /* -- alert stream (SSE) -------------------------------------------------- */

  function alertRow(alert) {
    var severity = alert.severity || "info";
    var row = document.createElement("li");
    row.className = "alert severity-" + severity;
    var glyph = document.createElement("span");
    glyph.className = "glyph state-" + severity;
    glyph.textContent = severity === "critical" ? "\u25cf" : severity === "warning" ? "\u25d0" : "\u25cb";
    var body = document.createElement("div");
    body.className = "alert-body";
    var message = document.createElement("p");
    message.className = "alert-message";
    message.textContent = alert.message || alert.rule_name || "alert";
    var meta = document.createElement("p");
    meta.className = "muted small mono";
    meta.textContent = (alert.rule_name || "alert") + " / " + (alert.metric || "issue") + " / just now";
    body.appendChild(message);
    body.appendChild(meta);
    row.appendChild(glyph);
    row.appendChild(body);
    return row;
  }

  function pushAlert(alert) {
    var list = qs("#alert-stream");
    if (list) {
      qsa(".muted", list).forEach(function (node) {
        if (node.parentElement === list) { node.remove(); }
      });
      list.insertBefore(alertRow(alert), list.firstChild);
      while (list.children.length > MAX_ALERTS) { list.removeChild(list.lastChild); }
    }
    if (alert.severity === "critical") {
      toast("ALERT: " + (alert.message || alert.rule_name || "critical event"));
    }
  }

  function connectAlerts() {
    if (!("EventSource" in window) || live.alerts) { return; }
    var source = new EventSource("/sse/alerts");
    source.onmessage = function (event) {
      try { pushAlert(JSON.parse(event.data)); } catch (error) { /* ignore malformed payload */ }
    };
    source.onerror = function () { /* EventSource reconnects on its own */ };
    live.alerts = source;
  }

  /* -- HTMX integration ---------------------------------------------------- */

  function wireHtmx() {
    if (typeof htmx === "undefined") { return; }
    if (Array.isArray(htmx.config.responseHandling)) {
      htmx.config.responseHandling = [
        { code: "204", swap: false },
        { code: "[23]..", swap: true },
        { code: "503", swap: true, error: true },
        { code: "[45]..", swap: false, error: true },
        { code: "...", swap: false },
      ];
    }

    var pendingActions = 0;

    function isActionRequest(detail) {
      var config = detail && detail.requestConfig ? detail.requestConfig : {};
      return String(config.verb || "get").toLowerCase() !== "get";
    }

    function pollAncestor(element) {
      if (!element || !element.closest) { return null; }
      return element.closest('[hx-trigger*="every"]');
    }

    /*
     * A poll swap can remove the button that started an ack/delete/test
     * request, which drops the response toast and the HX-Trigger refresh.
     * Abort the surrounding poll as soon as a mutating request starts and
     * pause its timer until every in-flight action has finished.
     */
    document.addEventListener("htmx:beforeRequest", function (event) {
      var detail = event.detail || {};
      if (!isActionRequest(detail)) { return; }
      pendingActions += 1;
      document.body.classList.add("netmon-action-pending");
      var poll = pollAncestor(detail.elt);
      if (poll) { htmx.trigger(poll, "htmx:abort"); }
    });

    document.addEventListener("htmx:afterRequest", function (event) {
      if (!isActionRequest(event.detail || {})) { return; }
      pendingActions = Math.max(0, pendingActions - 1);
      if (pendingActions === 0) {
        document.body.classList.remove("netmon-action-pending");
      }
    });
    document.addEventListener("htmx:afterSwap", function (event) {
      initCharts(event.target || document);
    });
    document.addEventListener("htmx:responseError", function (event) {
      var xhr = event.detail && event.detail.xhr;
      var status = xhr ? xhr.status : "?";
      var detail = "";
      try {
        var body = JSON.parse(xhr.responseText);
        if (typeof body.detail === "string") {
          detail = body.detail;
        } else if (Array.isArray(body.detail)) {
          // FastAPI validation errors: [{loc: [...], msg: "..."}, ...]
          detail = body.detail.map(function (item) {
            var loc = Array.isArray(item.loc) ? item.loc.join(".") : "";
            return (loc ? loc + ": " : "") + (item.msg || "");
          }).join("; ");
        }
      } catch (error) { detail = ""; }
      toast("Request failed (" + status + ") " + detail);
    });
    document.addEventListener("htmx:afterRequest", function (event) {
      var detail = event.detail || {};
      var xhr = detail.xhr;
      if (!xhr || !xhr.status || xhr.status < 200 || xhr.status >= 300) { return; }
      var path = "";
      try { path = new URL(xhr.responseURL || "", window.location.origin).pathname; } catch (error) { path = ""; }
      var verb = (detail.requestConfig && detail.requestConfig.verb) || "";
      var elt = detail.elt;

      if (path.indexOf("/api/config/") === 0) {
        var key = decodeURIComponent(path.slice("/api/config/".length));
        var row = elt && elt.closest ? elt.closest("tr") : null;
        var status = row ? qs(".setting-status", row) : null;
        if (status) { status.textContent = "saved"; }
        toast("Saved " + key);
      } else if (path.indexOf("/api/alert-channels/") === 0) {
        var payload = {};
        try { payload = JSON.parse(xhr.responseText); } catch (error) { payload = {}; }
        if (payload.ok) {
          toast("Test alert sent to " + (payload.channel || "channel"));
        } else {
          toast("Test alert failed for " + (payload.channel || "channel") + ": " + (payload.error || "unknown error"));
        }
      } else if (path.indexOf("/api/alert-rules") === 0) {
        if (verb === "delete") {
          toast("Alert rule deleted");
        } else {
          toast("Alert rule saved");
          if (verb === "post" && elt && elt.tagName === "FORM" && !elt.querySelector("[readonly]")) {
            elt.reset();
          }
        }
      } else if (path.indexOf("/api/alerts/") === 0) {
        toast("Alert acknowledged");
      }
    });
    document.addEventListener("htmx:sendError", function () {
      toast("Network error: the request could not be sent");
    });
  }

  /* -- bootstrap ----------------------------------------------------------- */

  function start() {
    initCharts(document);
    wireHtmx();
    connectLive();
    connectAlerts();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();

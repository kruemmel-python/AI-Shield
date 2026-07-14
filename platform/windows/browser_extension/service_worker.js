const nativeHost = "de.ai_shield.browser";

function safeUrl(raw) {
  if (!URL.canParse(raw)) {
    return {scheme: "invalid", host: "", port: "", path_length: 0, query_present: false};
  }
  const parsed = new URL(raw);
  return {
    scheme: parsed.protocol.replace(":", ""),
    host: parsed.hostname.toLowerCase(),
    port: parsed.port,
    path_length: parsed.pathname.length,
    query_present: parsed.search.length > 0
  };
}

function send(kind, details) {
  const message = {
    schema: "AIShieldBrowserEvent/1",
    event_id: crypto.randomUUID(),
    generated_ms: Date.now(),
    kind,
    tab_id: Number.isInteger(details.tabId) ? details.tabId : -1,
    frame_id: Number.isInteger(details.frameId) ? details.frameId : -1,
    transition: details.transitionType || "",
    url: safeUrl(details.url || details.finalUrl || "")
  };
  chrome.runtime.sendNativeMessage(nativeHost, message, response => {
    const error = chrome.runtime.lastError;
    chrome.storage.local.set({
      native_status: error ? "error" : (response && response.accepted ? "connected" : "rejected"),
      native_error: error ? error.message : "",
      native_checked_ms: Date.now()
    });
  });
}

function heartbeat() {
  send("sensor-ready", {tabId: -1, frameId: -1, transitionType: "", url: ""});
}

chrome.runtime.onInstalled.addListener(heartbeat);
chrome.runtime.onStartup.addListener(heartbeat);
heartbeat();

chrome.webNavigation.onCommitted.addListener(details => {
  if (details.frameId === 0) send("navigation", details);
});
chrome.downloads.onCreated.addListener(item => send("download-created", {
  tabId: -1, frameId: -1, transitionType: "", url: item.finalUrl || item.url
}));
chrome.downloads.onChanged.addListener(delta => {
  if (delta.state && delta.state.current === "complete") {
    chrome.downloads.search({id: delta.id}, items => {
      const item = items.length === 1 ? items[0] : {};
      send("download-complete", {
        tabId: -1, frameId: -1, transitionType: "", url: item.finalUrl || item.url || ""
      });
    });
  }
});

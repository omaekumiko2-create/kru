let socket;
let reconnectTimer;
let heartbeatTimer;
let connectTask;
let forceReconnectAfterCurrent = false;
const focusedFrameByTab = new Map();
const JOB_TIMEOUT_MS = 35_000;

chrome.runtime.onMessage.addListener((message, sender) => {
  if (message?.type === "kru-focus" && sender.tab?.id != null) {
    focusedFrameByTab.set(sender.tab.id, sender.frameId ?? 0);
    return;
  }
  if (message?.type === "bridge-config-updated") {
    requestConnect({ force: true });
  }
});

chrome.tabs.onRemoved.addListener((tabId) => focusedFrameByTab.delete(tabId));
chrome.tabs.onActivated.addListener(() => announceActive());
chrome.windows.onFocusChanged.addListener((windowId) => {
  if (windowId !== chrome.windows.WINDOW_ID_NONE) announceActive();
});

async function setStatus(status, detail) {
  await chrome.storage.local.set({ bridgeStatus: status, bridgeDetail: detail });
}

function reconnectAfter(delay = 1500) {
  clearTimeout(reconnectTimer);
  reconnectTimer = setTimeout(requestConnect, delay);
}

function socketIsLive() {
  return socket &&
    (socket.readyState === WebSocket.CONNECTING || socket.readyState === WebSocket.OPEN);
}

function announceActive() {
  if (socket?.readyState !== WebSocket.OPEN) {
    requestConnect();
    return;
  }
  try {
    socket.send(JSON.stringify({ type: "activate" }));
  } catch {
    handleDisconnect(socket);
  }
}

async function announceIfFocused() {
  try {
    const window = await chrome.windows.getLastFocused();
    if (window?.focused) announceActive();
  } catch {
    // The next tab/window activation will update the active extension.
  }
}

function requestConnect({ force = false } = {}) {
  if (!force && socketIsLive()) return connectTask || Promise.resolve();
  if (connectTask) {
    if (force) forceReconnectAfterCurrent = true;
    return connectTask;
  }
  connectTask = (async () => {
    let forceCurrent = force;
    do {
      forceReconnectAfterCurrent = false;
      await connectOnce(forceCurrent);
      forceCurrent = forceReconnectAfterCurrent;
    } while (forceCurrent);
  })().finally(() => {
    connectTask = null;
  });
  return connectTask;
}

function disposeSocket(ws, close = false) {
  if (socket !== ws) return false;
  socket = null;
  clearInterval(heartbeatTimer);
  heartbeatTimer = null;
  ws.onopen = null;
  ws.onmessage = null;
  ws.onerror = null;
  ws.onclose = null;
  if (close && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) {
    ws.close();
  }
  return true;
}

async function handleDisconnect(ws) {
  if (!disposeSocket(ws, true)) return;
  const { bridgePort = 39272 } = await chrome.storage.local.get("bridgePort");
  await setStatus("disconnected", `127.0.0.1:${bridgePort}`);
  reconnectAfter();
}

function startHeartbeat(ws) {
  clearInterval(heartbeatTimer);
  heartbeatTimer = setInterval(() => {
    if (socket === ws && ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(JSON.stringify({ type: "ping" }));
      } catch {
        handleDisconnect(ws);
      }
    } else {
      handleDisconnect(ws);
    }
  }, 20000);
}

async function claimPairing(port) {
  try {
    const response = await fetch(`http://127.0.0.1:${port}/claim`, { method: "POST" });
    if (!response.ok) return false;
    const payload = await response.json();
    if (!payload?.token || !payload?.port) return false;
    await chrome.storage.local.set({ bridgePort: payload.port, bridgeToken: payload.token });
    return true;
  } catch {
    return false;
  }
}

async function connectOnce(force = false) {
  clearTimeout(reconnectTimer);
  if (!force && socketIsLive()) return;
  if (socket) {
    disposeSocket(socket, true);
  }
  const { bridgePort = 39272, bridgeToken = "" } = await chrome.storage.local.get([
    "bridgePort",
    "bridgeToken",
  ]);
  if (!bridgeToken) {
    await setStatus("waiting", `127.0.0.1:${bridgePort}`);
    if (await claimPairing(bridgePort)) {
      reconnectAfter(50);
      return;
    }
    reconnectAfter();
    return;
  }
  await setStatus("connecting", `127.0.0.1:${bridgePort}`);
  const ws = new WebSocket(`ws://127.0.0.1:${bridgePort}/extension`);
  socket = ws;
  ws.onopen = () => ws.send(JSON.stringify({ type: "auth", token: bridgeToken }));
  ws.onmessage = async (event) => {
    let message;
    try {
      message = JSON.parse(event.data);
    } catch {
      return;
    }
    if (message.type === "ready") {
      await setStatus("connected", `127.0.0.1:${bridgePort}`);
      startHeartbeat(ws);
      await announceIfFocused();
      return;
    }
    if (message.type === "pong") return;
    if (message.type === "auth-error") {
      await chrome.storage.local.remove("bridgeToken");
      await setStatus("waiting", `127.0.0.1:${bridgePort}`);
      disposeSocket(ws, true);
      reconnectAfter();
      return;
    }
    if (message.type === "job") {
      const expiresAt = jobExpiresAt(message.job);
      const result = Number.isFinite(expiresAt) && Date.now() >= expiresAt
        ? { ok: false, message: "填写任务已过期" }
        : await fillFocused(message.job?.value, expiresAt, Boolean(message.job?.submit));
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: "complete",
          jobId: message.job?.id,
          ok: result.ok,
          message: result.message,
        }));
      }
    }
  };
  ws.onerror = () => handleDisconnect(ws);
  ws.onclose = () => handleDisconnect(ws);
}

function jobExpiresAt(job, now = Date.now()) {
  const raw = job?.expiresAt ?? job?.expires_at;
  const latest = now + JOB_TIMEOUT_MS;
  if (raw === undefined || raw === null) return latest;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? Math.min(parsed, latest) : latest;
}

async function fillFocused(value, expiresAt, submit = false) {
  if (typeof value !== "string") return { ok: false, message: "填写内容无效" };
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return { ok: false, message: "没有活动标签页" };
  const frameId = focusedFrameByTab.get(tab.id) ?? 0;
  try {
    const [execution] = await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [frameId] },
      func: writeToFocusedControl,
      args: [value, expiresAt, submit],
    });
    return execution?.result || { ok: false, message: "页面没有返回填写结果" };
  } catch {
    return { ok: false, message: "无法写入当前焦点控件；请确认页面和扩展权限" };
  }
}

function writeToFocusedControl(value, expiresAt, submit = false) {
  if (Number.isFinite(expiresAt) && Date.now() >= expiresAt) {
    return { ok: false, message: "填写任务已过期" };
  }
  const findActiveElement = (root) => {
    const element = root.activeElement;
    const shadowRoot = element?.shadowRoot;
    return shadowRoot?.activeElement ? findActiveElement(shadowRoot) : element;
  };
  const element = findActiveElement(document);
  if (!element || element === document.body || element === document.documentElement) {
    return { ok: false, message: "当前页面没有聚焦的可输入控件" };
  }
  const tag = element.tagName?.toLowerCase();
  const editable = element.isContentEditable;
  if (tag !== "input" && tag !== "textarea" && !editable) {
    return { ok: false, message: "当前焦点不是可输入控件" };
  }
  try {
    element.focus();
    if (editable) {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(element);
      selection.removeAllRanges();
      selection.addRange(range);
      document.execCommand("insertText", false, value);
    } else {
      const prototype = tag === "textarea" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(prototype, "value")?.set;
      if (!setter) return { ok: false, message: "当前控件不支持安全写入" };
      setter.call(element, value);
    }
    element.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText" }));
    element.dispatchEvent(new Event("change", { bubbles: true }));
    if (submit) {
      const form = element.form || element.closest?.("form");
      if (!form || typeof form.requestSubmit !== "function") {
        return { ok: false, message: "已写入当前焦点控件，但找不到可提交的表单" };
      }
      setTimeout(() => form.requestSubmit(), 0);
      return { ok: true, message: "已写入并提交当前表单" };
    }
    return { ok: true, message: "已写入当前焦点控件" };
  } catch {
    return { ok: false, message: "页面拒绝写入当前控件" };
  }
}

requestConnect();

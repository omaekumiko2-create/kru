let socket;
let reconnectTimer;
const focusedFrameByTab = new Map();

chrome.runtime.onMessage.addListener((message, sender) => {
  if (message?.type === "kru-focus" && sender.tab?.id != null) {
    focusedFrameByTab.set(sender.tab.id, sender.frameId ?? 0);
    return;
  }
  if (message?.type === "bridge-config-updated") {
    connect();
  }
});

chrome.tabs.onRemoved.addListener((tabId) => focusedFrameByTab.delete(tabId));
chrome.tabs.onActivated.addListener(() => connect());

async function setStatus(status, detail) {
  await chrome.storage.local.set({ bridgeStatus: status, bridgeDetail: detail });
}

function reconnectAfter(delay = 1500) {
  clearTimeout(reconnectTimer);
  reconnectTimer = setTimeout(connect, delay);
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

async function connect() {
  clearTimeout(reconnectTimer);
  if (socket) {
    socket.onclose = null;
    socket.close();
    socket = null;
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
      return;
    }
    if (message.type === "auth-error") {
      await chrome.storage.local.remove("bridgeToken");
      await setStatus("waiting", `127.0.0.1:${bridgePort}`);
      ws.close();
      return;
    }
    if (message.type === "job") {
      const result = await fillFocused(message.job?.value);
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
  ws.onerror = () => {};
  ws.onclose = async () => {
    if (socket !== ws) return;
    socket = null;
    await setStatus("disconnected", `127.0.0.1:${bridgePort}`);
    reconnectAfter();
  };
}

async function fillFocused(value) {
  if (typeof value !== "string") return { ok: false, message: "填写内容无效" };
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return { ok: false, message: "没有活动标签页" };
  const frameId = focusedFrameByTab.get(tab.id) ?? 0;
  try {
    const [execution] = await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [frameId] },
      func: writeToFocusedControl,
      args: [value],
    });
    return execution?.result || { ok: false, message: "页面没有返回填写结果" };
  } catch {
    return { ok: false, message: "无法写入当前焦点控件；请确认页面和扩展权限" };
  }
}

function writeToFocusedControl(value) {
  const element = document.activeElement;
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
    return { ok: true, message: "已写入当前焦点控件" };
  } catch {
    return { ok: false, message: "页面拒绝写入当前控件" };
  }
}

connect();

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

const listeners = {};
const sockets = [];
let tabQueryCount = 0;

class FakeWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSED = 3;

  constructor(url) {
    this.url = url;
    this.readyState = FakeWebSocket.CONNECTING;
    this.sent = [];
    this.closed = false;
    sockets.push(this);
  }

  send(value) {
    this.sent.push(value);
  }

  close() {
    this.closed = true;
    this.readyState = FakeWebSocket.CLOSED;
  }
}

const chrome = {
  runtime: { onMessage: { addListener: (listener) => { listeners.message = listener; } } },
  tabs: {
    onRemoved: { addListener: () => {} },
    onActivated: { addListener: (listener) => { listeners.activated = listener; } },
    query: async () => {
      tabQueryCount += 1;
      return [];
    },
  },
  windows: {
    WINDOW_ID_NONE: -1,
    onFocusChanged: { addListener: (listener) => { listeners.windowFocused = listener; } },
    getLastFocused: async () => ({ focused: true }),
  },
  storage: {
    local: {
      get: async () => ({ bridgePort: 39272, bridgeToken: "test-token" }),
      set: async () => {},
      remove: async () => {},
    },
  },
  scripting: { executeScript: async () => [] },
};

const source = await readFile(new URL("./service-worker.js", import.meta.url), "utf8");
const sandbox = {
  chrome,
  WebSocket: FakeWebSocket,
  fetch: async () => ({ ok: false }),
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
  console,
};
vm.runInNewContext(source, sandbox);

assert.equal(sandbox.jobExpiresAt({ expiresAt: 123 }), 123, "current expiry field must be accepted");
assert.equal(sandbox.jobExpiresAt({ expires_at: 456 }), 456, "legacy expiry field must remain compatible");
assert.equal(sandbox.jobExpiresAt({}, 1000), 36_000, "missing expiry must get a bounded deadline");
assert.equal(sandbox.jobExpiresAt({ expiresAt: "invalid" }, 1000), 36_000, "invalid expiry must get a bounded deadline");
assert.equal(sandbox.jobExpiresAt({ expiresAt: 50_000 }, 1000), 36_000, "remote expiry must remain bounded");

listeners.activated();
listeners.activated();
await new Promise(setImmediate);
assert.equal(sockets.length, 1, "concurrent activation must create only one socket");

listeners.activated();
await new Promise(setImmediate);
assert.equal(sockets.length, 1, "CONNECTING socket must be reused");

sockets[0].readyState = FakeWebSocket.OPEN;
sockets[0].onopen();
listeners.activated();
await new Promise(setImmediate);
assert.equal(sockets.length, 1, "OPEN socket must be reused");
assert.equal(JSON.parse(sockets[0].sent.at(-1)).type, "activate", "tab activation must select the existing connection");
const activationCount = sockets[0].sent.length;
listeners.windowFocused(chrome.windows.WINDOW_ID_NONE);
assert.equal(sockets[0].sent.length, activationCount, "losing browser focus must not select the connection");
listeners.windowFocused(7);
assert.equal(JSON.parse(sockets[0].sent.at(-1)).type, "activate", "window focus must select the existing connection");

listeners.message({ type: "bridge-config-updated" }, {});
listeners.activated();
listeners.activated();
await new Promise(setImmediate);
assert.equal(sockets.length, 2, "configuration changes must force one reconnect");
assert.equal(sockets[0].closed, true, "forced reconnect must close the old socket");

sockets[1].readyState = FakeWebSocket.OPEN;
await sockets[1].onmessage({
  data: JSON.stringify({
    type: "job",
    job: { id: "expired-job", value: "must-not-be-written", expiresAt: 0 },
  }),
});
assert.equal(tabQueryCount, 0, "expired jobs must not inspect or write the active tab");
const expiredReply = JSON.parse(sockets[1].sent.at(-1));
assert.equal(expiredReply.type, "complete");
assert.equal(expiredReply.jobId, "expired-job");
assert.equal(expiredReply.ok, false);

class FakeInput {
  constructor() {
    this.tagName = "INPUT";
    this.isContentEditable = false;
    this.events = [];
  }

  focus() {
    this.focused = true;
  }

  set value(value) {
    this.written = value;
  }

  dispatchEvent(event) {
    this.events.push(event.type);
  }
}

class FakeEvent {
  constructor(type) {
    this.type = type;
  }
}

const input = new FakeInput();
const innerHost = { shadowRoot: { activeElement: input } };
const outerHost = { shadowRoot: { activeElement: innerHost } };
sandbox.document = {
  activeElement: outerHost,
  body: {},
  documentElement: {},
};
sandbox.HTMLInputElement = FakeInput;
sandbox.HTMLTextAreaElement = class {};
sandbox.InputEvent = FakeEvent;
sandbox.Event = FakeEvent;

const shadowResult = sandbox.writeToFocusedControl("shadow-secret");
assert.equal(shadowResult.ok, true, "open shadow roots must resolve to the focused input");
assert.equal(input.written, "shadow-secret");
assert.equal(input.focused, true);
assert.deepEqual(input.events, ["input", "change"]);

input.written = "unchanged";
input.events = [];
chrome.tabs.query = async () => {
  await new Promise((resolve) => setTimeout(resolve, 5));
  return [{ id: 42 }];
};
chrome.scripting.executeScript = async ({ func, args }) => [{ result: func(...args) }];
const delayedResult = await sandbox.fillFocused("late-secret", Date.now() + 1);
assert.equal(delayedResult.ok, false, "a job expiring during tab lookup must be rejected at injection time");
assert.equal(input.written, "unchanged", "an expired job must not write the focused control");
assert.deepEqual(input.events, [], "an expired job must not dispatch input events");

console.log("service-worker connection arbitration and shadow focus: ok");

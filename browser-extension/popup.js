const portInput = document.querySelector("#port");
const form = document.querySelector("#pair-form");
const statusText = document.querySelector("#status");
const detailText = document.querySelector("#detail");
const lamp = document.querySelector("#lamp");
const errorText = document.querySelector("#error");

async function refresh() {
  const stored = await chrome.storage.local.get(["bridgePort", "bridgeToken", "bridgeStatus", "bridgeDetail"]);
  portInput.value = stored.bridgePort || 39272;
  const status = stored.bridgeStatus || (stored.bridgeToken ? "disconnected" : "waiting");
  statusText.textContent = status.toUpperCase();
  detailText.textContent = stored.bridgeDetail || `127.0.0.1:${portInput.value}`;
  lamp.classList.toggle("on", status === "connected");
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorText.textContent = "";
  const port = Number(portInput.value);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    errorText.textContent = "请输入有效端口";
    return;
  }
  try {
    await chrome.storage.local.set({ bridgePort: port });
    await chrome.runtime.sendMessage({ type: "bridge-config-updated" });
    errorText.textContent = "请在 KRU 点击一键接入，扩展会自动配对";
    await refresh();
  } catch (error) {
    errorText.textContent = String(error?.message || error);
  }
});

chrome.storage.onChanged.addListener(refresh);
refresh();

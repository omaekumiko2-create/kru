function reportFocus() {
  chrome.runtime.sendMessage({ type: "kru-focus" }).catch(() => {});
}

document.addEventListener("focusin", reportFocus, true);
window.addEventListener("focus", reportFocus, true);

if (document.hasFocus()) reportFocus();

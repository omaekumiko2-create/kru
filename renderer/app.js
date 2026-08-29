const { invoke } = window.__TAURI__.core;
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const HAN_TEXT = /[\u3400-\u9fff]/;

const isMacOS = navigator.platform.startsWith('Mac') || navigator.userAgent.includes('Macintosh');
document.documentElement.classList.toggle('platform-macos', isMacOS);

if (isMacOS) {
  const titleDragRegion = document.querySelector('.title-drag-region');
  const isTitleControl = (target) => Boolean(target.closest?.('button, input, select, textarea, a, [role="button"]'));
  titleDragRegion.addEventListener('mousedown', (event) => {
    if (event.button === 0 && !isTitleControl(event.target)) event.preventDefault();
  });
  titleDragRegion.addEventListener('selectstart', (event) => event.preventDefault());
  titleDragRegion.addEventListener('dragstart', (event) => event.preventDefault());
}

// Keep the first paint deterministic. The persisted setting from the vault is
// applied by refresh(); browser storage can survive an app reinstall and must
// not override the English default while the native state is loading.
let language = 'en';

function localized(zh, en) {
  return language === 'en' ? en : zh;
}

const staticCopy = [
  ['.window-control[data-window-action="minimize"]', 'aria-label', '最小化', 'Minimize'],
  ['.window-control[data-window-action="close"]', 'aria-label', '关闭', 'Close'],
  ['.nav-item[data-page="connections"] > span', 'html', '项目<small>ITEMS</small>', 'ITEMS<small>VAULT</small>'],
  ['.nav-item[data-page="activity"] > span', 'html', '记录<small>LOG</small>', 'LOG<small>AUDIT</small>'],
  ['.nav-item[data-page="settings"] > span', 'html', '设置<small>SYSTEM</small>', 'SYSTEM<small>LOCAL</small>'],
  ['#page-connections .page-header h1', 'text', '秘密项目', 'VAULT ITEMS'],
  ['#page-connections .page-search-input', 'aria-label', '搜索秘密项目', 'Search vault items'],
  ['#add-connection-button', 'text', '＋ 添加', '+ ADD'],
  ['#drafts-button', 'text', '草稿', 'DRAFT'],
  ['#delete-draft-button', 'aria-label', '删除草稿', 'Delete draft'],
  ['#page-activity .page-search-input', 'aria-label', '搜索操作记录', 'Search activity'],
  ['#activity-filter-menu-button', 'aria-label', '记录筛选', 'Filter activity'],
  ['#activity-filter-menu', 'aria-label', '记录筛选', 'Activity filters'],
  ['#page-settings .page-search-input', 'aria-label', '搜索系统设置', 'Search settings'],
  ['#header-export-backup-button', 'text', '一键打包', 'EXPORT'],
  ['#header-import-backup-button', 'text', '一键导入包', 'IMPORT'],
  ['[data-module="SYSTEM / 01"] .settings-heading h2', 'text', '系统入口', 'SYSTEM ACCESS'],
  ['[data-module="SYSTEM / 01"] .settings-heading p', 'text', '控制 KRU 的桌面快捷方式与开机启动。', 'Control the KRU desktop shortcut and launch at login.'],
  ['#desktop-shortcut-option strong', 'text', '创建快捷方式到桌面', 'CREATE DESKTOP SHORTCUT'],
  ['#desktop-shortcut-option small', 'text', '在当前用户桌面创建 KRU 快捷方式', 'Create a KRU shortcut on the current user’s desktop.'],
  ['#launch-at-login-option strong', 'text', '开机自启动', 'LAUNCH AT LOGIN'],
  ['#launch-at-login-option small', 'text', '登录系统后自动启动 KRU，并保持单实例', 'Start KRU after sign-in while preserving single-instance behavior.'],
  ['[data-module="MCP / 02"] .settings-heading h2', 'text', 'Agent 接入', 'AGENT SETUP'],
  ['[data-module="MCP / 02"] .settings-heading p', 'text', '注册本地 stdio MCP；支持的 Agent 同时安装“认证任务优先使用 KRU”规则。', 'Register the local stdio MCP and install the KRU-first authentication rule where supported.'],
  ['[data-module="APP / 03"] .settings-heading h2', 'text', '窗口与锁定', 'WINDOW & LOCK'],
  ['[data-module="APP / 03"] .settings-heading p', 'text', '控制关闭按钮与本地 PIN 锁。', 'Control the close button and local PIN lock.'],
  ['label[for="close-behavior"] strong', 'text', '关闭按钮', 'CLOSE BUTTON'],
  ['label[for="close-behavior"] small', 'text', '最小化可保留托盘菜单', 'Minimizing keeps tray controls available.'],
  ['#close-behavior option[value="tray"]', 'text', '最小化到托盘', 'MINIMIZE TO TRAY'],
  ['#close-behavior option[value="exit"]', 'text', '退出 KRU', 'QUIT KRU'],
  ['.pin-option strong', 'text', 'PIN 锁', 'PIN LOCK'],
  ['.pin-option small', 'text', '关闭后移除当前 PIN；再次开启时设置新的 PIN', 'Turning this off removes the current PIN. Set a new PIN when enabling it again.'],
  ['.agent-restart-notice span', 'text', '完成后重启 Agent。', 'Restart the agent after setup.'],
  ['#agent-client-list .agent-scan-placeholder', 'text', '正在扫描本机 Agent', 'SCANNING LOCAL AGENTS'],
  ['.manual-mcp-config summary', 'text', '其他 Agent / 手动配置', 'OTHER AGENT / MANUAL SETUP'],
  ['.manual-config-steps > div:nth-child(1) span', 'text', '打开目标 Agent 的 MCP 配置', 'Open the target agent MCP configuration'],
  ['.manual-config-steps > div:nth-child(2) span', 'text', '按配置格式复制 JSON 或 TOML', 'Copy JSON or TOML to match its config format'],
  ['.manual-config-steps > div:nth-child(3) span', 'text', '粘贴保存并重新启动 Agent', 'Paste, save, and restart the agent'],
  ['[data-module="WEB / 04"] .settings-heading p', 'text', '通过已配对扩展填写当前浏览器控件。', 'Fill the focused browser field through the paired extension.'],
  ['label[for="browser-port"]', 'text', '本地端口', 'LOCAL PORT'],
  ['#save-browser-settings-button', 'text', '保存', 'SAVE'],
  ['.browser-connect-note span', 'text', '首次加载扩展目录，之后自动配对。', 'Load the extension once; pairing is automatic.'],
  ['#quick-pairing-button', 'text', '一键接入浏览器', 'CONNECT BROWSER'],
  ['#open-extension-button', 'text', '扩展目录', 'EXTENSION FOLDER'],
  ['#reset-pairing-button', 'text', '重置', 'RESET'],
  ['[data-module="SAFE / 05"] .settings-heading h2', 'text', '本地数据', 'LOCAL DATA'],
  ['[data-module="SAFE / 05"] .settings-heading p', 'text', '导出由 KRU 自动解密的加密包，避免秘密以原文直接暴露。', 'Export an encrypted package KRU unlocks automatically, preventing direct plaintext exposure.'],
  ['#open-data-button', 'text', '打开数据目录', 'OPEN DATA FOLDER'],
  ['#owner-lock-description', 'text', 'PIN 保护明文查看；模块值默认隐藏，仅在你开启后对 Agent 可见。', 'The PIN protects plaintext viewing. Module values stay hidden unless you make them visible to agents.'],
  ['#owner-pin', 'label', '六位数字 PIN', 'SIX-DIGIT PIN'],
  ['#owner-pin-confirm', 'label', '再次输入 PIN', 'CONFIRM PIN'],
  ['.lock-note span', 'text', '秘密仍由本机随机主密钥加密；PIN 只是本地查看锁。', 'Secrets remain encrypted by the local random master key. The PIN only locks plaintext viewing.'],
  ['#owner-pin-cancel', 'text', '取消', 'CANCEL'],
  ['[data-close-modal].icon-button', 'aria-label', '关闭编辑器', 'Close editor'],
  ['#connection-name', 'label', '名称', 'NAME'],
  ['#connection-description', 'label-html', '备注 / 用途 <em>可选</em>', 'NOTES / PURPOSE <em>OPTIONAL</em>'],
  ['.template-copy strong', 'text', '从一个组合开始', 'START WITH A PRESET'],
  ['.template-copy small', 'text', '模板只添加模块，不会限制之后的修改。', 'Templates only add modules; you can change anything afterward.'],
  ['.module-editor-heading > div > strong', 'text', '项目模块', 'ITEM MODULES'],
  ['.module-editor-heading > div > small', 'text', '拖动模块的非按钮区域调整顺序 · 开关控制 Agent 可见性', 'DRAG ANY NON-BUTTON AREA TO REORDER · SWITCH CONTROLS AGENT VISIBILITY'],
  ['#add-module-button', 'text', '＋ 添加模块', '+ ADD MODULE'],
  ['#module-menu [data-add-module="username"]', 'text', '账号', 'USERNAME'],
  ['#module-menu [data-add-module="password"]', 'text', '密码', 'PASSWORD'],
  ['#module-menu [data-add-module="apiCredential"]', 'text', 'API 凭据', 'API CREDENTIAL'],
  ['#module-menu [data-add-module="privateKey"]', 'text', '私钥', 'PRIVATE KEY'],
  ['#module-menu [data-add-module="passphrase"]', 'text', '私钥口令', 'KEY PASSPHRASE'],
  ['#module-menu [data-add-module="totp"]', 'text', 'TOTP', 'TOTP'],
  ['#module-menu [data-add-module="customSecret"]', 'text', '自定义字段', 'CUSTOM FIELD'],
  ['#module-menu [data-add-module="host"]', 'text', '主机 / IP', 'HOST / IP'],
  ['#module-menu [data-add-module="port"]', 'text', '端口', 'PORT'],
  ['#module-menu [data-add-module="url"]', 'text', '服务 URL', 'SERVICE URL'],
  ['[data-item-template="login"] > span', 'html', '登录<small>账号 + 密码</small>', 'LOGIN<small>USERNAME + PASSWORD</small>'],
  ['[data-item-template="ssh"] > span', 'html', 'SSH<small>主机 + 端口 + 账号 + 密码</small>', 'SSH<small>HOST + PORT + USER + PASSWORD</small>'],
  ['[data-item-template="api"] > span', 'html', 'API<small>API 凭据</small>', 'API<small>API CREDENTIAL</small>'],
  ['[data-item-template="blank"] > span', 'html', '空白<small>从零添加模块</small>', 'BLANK<small>START WITH NO MODULES</small>'],
  ['.check-row strong', 'text', '启用此项目', 'ENABLE ITEM'],
  ['.check-row small', 'text', '禁用后 Agent 无法使用', 'Agents cannot use a disabled item.'],
  ['.secret-hint', 'text', '当前项目的明文只在已解锁 GUI 中显示', 'Plaintext is visible only in the unlocked GUI.'],
  ['#connection-form .modal-footer [data-close-modal]', 'text', '关闭', 'CLOSE'],
  ['#save-connection-button', 'text', '保存', 'SAVE'],
];

function applyLanguage() {
  document.documentElement.lang = language === 'en' ? 'en' : 'zh-CN';
  $$('.language-switch button').forEach((button) => button.classList.toggle('active', button.dataset.language === language));
  for (const [selector, target, zh, en] of staticCopy) {
    const element = $(selector);
    if (!element) continue;
    const copy = localized(zh, en);
    if (target === 'text') element.textContent = copy;
    else if (target === 'html') element.innerHTML = copy;
    else if (target === 'aria-label' || target === 'placeholder') element.setAttribute(target, copy);
    else if (target === 'label' || target === 'label-html') {
      const label = element.closest('label')?.querySelector(':scope > span') || element.closest('.field')?.querySelector(':scope > span');
      if (label) target === 'label-html' ? label.innerHTML = copy : label.textContent = copy;
    }
  }
  if (isMacOS) {
    $('[data-module="SYSTEM / 01"] .settings-heading p').textContent = localized(
      '控制 KRU 的登录时启动。',
      'Control whether KRU launches at login.',
    );
  }
}

function publicMessage(value, fallback = localized('操作失败', 'Operation failed')) {
  const raw = String(value || '').replace(/^Error:\s*/, '');
  if (language !== 'en' || !HAN_TEXT.test(raw)) return raw || fallback;
  return fallback;
}

let settingsWriteQueue = Promise.resolve();

function updateSettings(patch) {
  const operation = settingsWriteQueue.then(() => invoke('update_settings', { patch }));
  settingsWriteQueue = operation.catch(() => {});
  return operation;
}

const api = {
  state: () => invoke('get_state'),
  ownerStatus: () => invoke('owner_status'),
  ownerSetPin: (pin) => invoke('owner_set_pin', { pin }),
  ownerDisablePin: () => invoke('owner_disable_pin'),
  ownerUnlock: (pin) => invoke('owner_unlock', { pin }),
  ownerLock: () => invoke('owner_lock'),
  ownerSecrets: (id) => invoke('owner_secret_view', { id }),
  drafts: () => invoke('owner_editor_drafts'),
  saveDraft: (draftId, input) => invoke('save_editor_draft', { draftId, input }),
  deleteDraft: (id) => invoke('delete_editor_draft', { id }),
  copyOwnerValue: (value) => invoke('copy_owner_value', { value }),
  save: (input) => invoke('save_connection', { input }),
  setEnabled: (id, enabled) => invoke('set_connection_enabled', { id, enabled }),
  remove: (id) => invoke('delete_connection', { id }),
  test: (id) => invoke('test_connection', { id }),
  settings: updateSettings,
  systemIntegration: () => invoke('system_integration_status'),
  setDesktopShortcut: (enabled) => invoke('set_desktop_shortcut', { enabled }),
  setLaunchAtLogin: (enabled) => invoke('set_launch_at_login', { enabled }),
  clear: () => invoke('clear_activities'),
  copyConfig: (format) => invoke('copy_mcp_config', { format }),
  agents: () => invoke('agent_mcp_status'),
  registerAgents: (clientIds) => invoke('agent_mcp_register', { clientIds }),
  repairAgent: (clientId) => invoke('agent_mcp_repair', { clientId }),
  removeAgent: (clientId) => invoke('agent_mcp_remove', { clientId }),
  chooseKey: () => invoke('choose_private_key'),
  quickPair: (port) => invoke('quick_pair_browser', { port }),
  resetPair: () => invoke('reset_browser_pairing'),
  extensionFolder: () => invoke('open_browser_extension_folder'),
  exportBackup: () => invoke('export_backup'),
  importBackup: () => invoke('import_backup'),
  dataFolder: () => invoke('open_data_folder'),
  window: (action) => invoke('window_action', { action }),
};

let state;
let systemIntegrationState = { desktopShortcut: false, launchAtLogin: false };
let activePage = 'connections';
let currentActivityFilter = 'all';
const pageSearch = { connections: '', activity: '', settings: '' };
let currentModules = [];
let editorDrafts = [];
let currentDraftId = '';
let removedSecretFields = new Set();
let editorExistingItem = null;
let editorSourceInput = null;
let editorOpenedFromDraft = false;
let editorInitialSnapshot = '';
let agentClients = [];
let agentRestartRequired = false;
const ACTIVITY_PAGE_SIZE = 50;
let activityVisibleCount = ACTIVITY_PAGE_SIZE;
let activityMatchCount = 0;
let activityLoadPending = false;
const expandedActivityErrors = new Set();
let ownerLockState = { pinConfigured: false, unlocked: false, expiresInSeconds: 0 };
let ownerPinSetupRequested = false;
const scrollThumbBindings = [];
let scrollSyncQueued = false;

function escapeHtml(value = '') {
  return String(value).replace(/[&<>"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[character]);
}

function cleanError(error) {
  return publicMessage(error?.message || error, localized('未知错误', 'Unknown error'));
}

function normalizeSearch(value = '') {
  return String(value).trim().toLocaleLowerCase('zh-CN');
}

function queueScrollThumbSync() {
  if (scrollSyncQueued) return;
  scrollSyncQueued = true;
  requestAnimationFrame(() => {
    scrollSyncQueued = false;
    for (const { surface, thumb } of scrollThumbBindings) {
      const maxScroll = Math.max(0, surface.scrollHeight - surface.clientHeight);
      const inset = 4;
      const thumbHeight = thumb.offsetHeight || 48;
      const travel = Math.max(0, surface.clientHeight - thumbHeight - inset * 2);
      const progress = maxScroll ? surface.scrollTop / maxScroll : 0;
      thumb.style.top = `${surface.offsetTop + inset}px`;
      thumb.style.transform = `translateY(${Math.round(progress * travel)}px)`;
      thumb.classList.toggle('visible', maxScroll > 1);
    }
  });
}

function initFixedScrollThumbs() {
  for (const thumb of $$('.fixed-scroll-thumb')) {
    const surface = $(thumb.dataset.scrollFor);
    if (!surface) continue;
    scrollThumbBindings.push({ surface, thumb });
    surface.addEventListener('scroll', queueScrollThumbSync, { passive: true });
    new ResizeObserver(queueScrollThumbSync).observe(surface);
    new MutationObserver(queueScrollThumbSync).observe(surface, { childList: true, subtree: true, attributes: true, attributeFilter: ['class'] });
  }
  window.addEventListener('resize', queueScrollThumbSync);
  queueScrollThumbSync();
}

function toast(message, type = '') {
  const item = document.createElement('div');
  item.className = `toast ${type}`;
  item.textContent = message;
  $('#toast-region').append(item);
  setTimeout(() => item.remove(), 3200);
}

function clearOwnerPlaintext() {
  closeEditor();
  currentModules.forEach((module) => { module.secretValue = ''; });
  $$('[data-secret-value]').forEach((input) => { input.value = ''; });
}

function pinInputs(id) {
  return $$(`[data-pin-group="${id}"] .pin-cell-input`);
}

function readPin(id) {
  return pinInputs(id).map((input) => input.value).join('');
}

function clearPin(id) {
  pinInputs(id).forEach((input) => { input.value = ''; });
}

function focusPin(id) {
  const inputs = pinInputs(id);
  (inputs.find((input) => !input.value) || inputs[inputs.length - 1])?.focus();
}

function renderOwnerLock() {
  const configured = ownerLockState.pinConfigured;
  const unlocked = ownerLockState.unlocked;
  const setupRequested = ownerPinSetupRequested && !configured;
  const locked = configured && !unlocked;
  const layerVisible = setupRequested || locked;
  $('#owner-lock-layer').classList.toggle('hidden', !layerVisible);
  $('#owner-lock-button').classList.toggle('hidden', !configured || !unlocked);
  $('#owner-pin-confirm-field').classList.toggle('hidden', configured);
  $('#owner-pin-cancel').classList.toggle('hidden', !setupRequested);
  pinInputs('owner-pin-confirm').forEach((input) => { input.required = !configured; });
  $('#owner-lock-mode').textContent = configured ? 'OWNER VERIFY' : 'SET LOCAL PIN';
  $('#owner-lock-title').textContent = configured
    ? localized('输入六位 PIN', 'ENTER SIX-DIGIT PIN')
    : localized('设置六位 PIN', 'SET SIX-DIGIT PIN');
  $('#owner-lock-code').textContent = configured ? 'LOCK' : 'INIT';
  $('#owner-unlock-action').textContent = configured ? 'UNLOCK' : 'SET PIN';
  if (locked) {
    clearOwnerPlaintext();
    editorDrafts = [];
    renderDrafts();
  }
  clearPin('owner-pin');
  clearPin('owner-pin-confirm');
  if (layerVisible) setTimeout(() => focusPin('owner-pin'), 0);
}

async function refreshOwnerLock(showError = true) {
  try {
    ownerLockState = await api.ownerStatus();
    renderOwnerLock();
  } catch (error) {
    if (showError) toast(cleanError(error), 'error');
  }
}

async function lockOwner() {
  try { ownerLockState = await api.ownerLock(); } catch (_) { ownerLockState.unlocked = false; }
  renderOwnerLock();
}

async function refresh(showError = true) {
  try {
    state = await api.state();
    try {
      systemIntegrationState = await api.systemIntegration();
    } catch (_) {
      systemIntegrationState = { desktopShortcut: false, launchAtLogin: false };
    }
    language = state.settings.language === 'en' ? 'en' : 'zh';
    applyLanguage();
    render();
  } catch (error) {
    if (showError) toast(cleanError(error), 'error');
  }
}

function render() {
  renderMetrics();
  renderConnections();
  renderDrafts();
  renderActivity();
  renderSettings();
}

const segmentNames = ['a', 'b', 'c', 'd', 'e', 'f', 'g'];

function sevenSegmentNumber(value, length = 4) {
  const exact = Math.max(0, Math.trunc(Number(value) || 0));
  const maximum = (10 ** length) - 1;
  const overflow = exact > maximum;
  const digits = String(Math.min(exact, maximum)).padStart(length, '0');
  return `<span class="seven-number ${overflow ? 'overflow' : ''}" role="img" aria-label="${exact}">${[...digits].map((digit) => `<span class="seven-digit digit-${digit}" aria-hidden="true">${segmentNames.map((segment) => `<i class="segment segment-${segment}"></i>`).join('')}</span>`).join('')}${overflow ? '<b class="seven-overflow" aria-hidden="true">+</b>' : ''}</span>`;
}

function displayWord(value, length = 4) {
  const exact = String(value || '---').toUpperCase().slice(0, length);
  const word = exact.padStart(length, ' ');
  return `<span class="seven-number seven-word" role="img" aria-label="${escapeHtml(exact)}">${[...word].map((character) => `<span class="seven-digit char-${character === ' ' ? 'blank' : character.toLowerCase()}" aria-hidden="true">${segmentNames.map((segment) => `<i class="segment segment-${segment}"></i>`).join('')}</span>`).join('')}</span>`;
}

function compactCount(value, suffix) {
  const count = Math.max(0, Math.trunc(Number(value) || 0));
  return `${count > 99 ? '99+' : count} ${suffix}`;
}

function activityCode(action = '') {
  const value = String(action).toUpperCase();
  if (/BROWSER|浏览器|\bWEB\b/.test(value)) return 'WEB';
  if (/TERMINAL|终端|PTY/.test(value)) return 'TERM';
  if (/SSH/.test(value)) return 'SSH';
  if (/API|HTTP|\bGET\b|\bPOST\b|\bPUT\b|\bPATCH\b|\bDELETE\b/.test(value)) return 'API';
  if (/FILL|填写|填入/.test(value)) return 'FILL';
  if (/TEST|测试|CHECK/.test(value)) return 'CHECK';
  return 'CALL';
}

function renderMetrics() {
  const total = state.connections.length;
  const enabled = state.connections.filter((item) => item.enabled).length;
  const disabled = total - enabled;
  const moduleCounts = {
    fill: state.connections.filter((item) => item.enabled && itemCapabilities(item).includes('fill')).length,
    ssh: state.connections.filter((item) => item.enabled && itemCapabilities(item).includes('ssh')).length,
    api: state.connections.filter((item) => item.enabled && itemCapabilities(item).includes('http')).length,
  };
  const latest = state.activities[0];
  const browserOn = ['listening', 'delegated'].includes(state.browserBridge.status);
  const mcpReady = state.mcp.status === 'ready';
  const lastStatus = !latest ? 'idle' : latest.status === 'error' ? 'error' : 'ok';
  const lastCode = lastStatus === 'idle' ? '--' : lastStatus === 'error' ? 'ERR' : 'OK';
  const lastAction = latest ? activityCode(latest.action) : 'NO CALL';
  const recentCalls = state.activities.slice(0, 8).reverse();
  const since24Hours = Date.now() - 86_400_000;
  const activities24h = state.activities.filter((activity) => {
    const timestamp = new Date(activity.time).getTime();
    return Number.isFinite(timestamp) && timestamp >= since24Hours;
  });
  const errors24h = activities24h.filter((activity) => activity.status === 'error').length;
  const passes24h = activities24h.length - errors24h;
  const actionTypes24h = new Set(activities24h.map((activity) => activityCode(activity.action)));
  const lastUseType = lastAction === 'WEB' ? 'FILL' : lastAction;
  const lastUseName = latest?.connectionName || (latest ? lastAction : 'NO CALL');
  const registeredAgents = agentClients.filter((client) => client.state === 'registered').length;
  const availableAgents = agentClients.filter((client) => client.state === 'available').length;
  const brokenAgents = agentClients.filter((client) => ['stale', 'conflict', 'error'].includes(client.state)).length;
  const displayCount = (count) => String(Math.min(Math.max(Number(count) || 0, 0), 9999)).padStart(4, '0');
  const agentMeter = agentClients.slice(0, 8).map((client) => {
    if (client.state === 'registered') return 'lit';
    if (client.state === 'available') return 'info';
    if (['stale', 'conflict', 'error'].includes(client.state)) return 'fault';
    return '';
  });
  const systemFault = state.mcp.status === 'error' || state.browserBridge.status === 'error';
  const systemNeedsSetup = !mcpReady || (browserOn && !state.browserBridge.paired);
  const systemCode = systemFault ? 'ERR' : systemNeedsSetup ? 'SET' : 'RDY';
  const settingsTelemetry = brokenAgents
    ? { status: 'error', label: 'AGENTS', code: 'ERR', action: `${displayCount(brokenAgents)} REPAIR` }
    : {
        status: registeredAgents ? 'ok' : 'idle',
        label: 'AGENTS',
        code: displayCount(registeredAgents),
        action: registeredAgents ? 'CONNECTED' : availableAgents ? 'READY TO ADD' : 'NO AGENT',
      };
  const models = {
    connections: {
      channels: [['A', 'FILL', moduleCounts.fill ? 'on' : ''], ['B', 'SSH', moduleCounts.ssh ? 'on' : ''], ['C', 'HTTP', moduleCounts.api ? 'on' : ''], ['D', 'OFF', disabled ? 'warn' : '']],
      minor: 'PAGE A', mode: 'VAULT', valueKind: 'number', value: total, unit: 'ITEM',
      ready: !total ? 'EMPTY' : enabled ? 'READY' : 'DISABLED', tag: disabled ? compactCount(disabled, 'OFF') : total ? 'ALL ON' : 'LOCAL', readyTone: disabled ? 'warn' : '',
      telemetryStatus: lastStatus, telemetryLabel: 'LAST USE', telemetryCode: lastCode, action: lastUseName,
      meter: recentCalls.map((activity) => `lit ${activity.status === 'error' ? 'fault' : ''} ${/BROWSER|浏览器|\bWEB\b/i.test(String(activity.action)) ? 'web' : ''}`),
      legend: `<span class="${lastUseType === 'FILL' ? 'lit' : ''}">FILL</span><span class="${lastUseType === 'SSH' ? 'lit' : ''}">SSH</span><span class="${lastUseType === 'API' ? 'lit' : ''}">HTTP</span>`,
    },
    activity: {
      channels: [['A', 'FILL', actionTypes24h.has('FILL') || actionTypes24h.has('WEB') ? 'on' : ''], ['B', 'SSH', actionTypes24h.has('SSH') ? 'on' : ''], ['C', 'HTTP', actionTypes24h.has('API') ? 'on' : ''], ['D', 'TERM', actionTypes24h.has('TERM') ? 'on' : '']],
      minor: 'PAGE B', mode: 'AUDIT', valueKind: 'number', value: activities24h.length, unit: '24H',
      ready: !activities24h.length ? 'IDLE' : errors24h ? 'ATTENTION' : 'CLEAN', tag: errors24h ? compactCount(errors24h, 'ERR') : 'NO ERR', readyTone: errors24h ? 'fault' : '',
      telemetryStatus: lastStatus, telemetryLabel: 'LATEST', telemetryCode: lastCode, action: lastAction,
      meter: recentCalls.map((activity) => `lit ${activity.status === 'error' ? 'fault' : ''}`),
      legend: `<span class="${passes24h ? 'lit' : ''}">PASS</span><span class="${errors24h ? 'fault' : ''}">ERR</span>`,
    },
    settings: {
      channels: [['A', 'MCP', mcpReady ? 'on' : 'error'], ['B', 'CRYPT', state.security.encrypted ? 'on' : 'error'], ['C', 'WEB', browserOn ? 'on web' : ''], ['D', 'PIN', ownerLockState.pinConfigured ? 'on' : '']],
      minor: 'PAGE C', mode: 'SYSTEM', valueKind: 'word', value: systemCode, unit: 'STATE',
      ready: systemFault ? 'SERVICE FAULT' : systemNeedsSetup ? 'ACTION NEEDED' : 'LOCAL READY', tag: state.security.encrypted ? 'SEALED' : 'CHECK', readyTone: systemFault ? 'fault' : systemNeedsSetup ? 'warn' : '',
      telemetryStatus: settingsTelemetry.status, telemetryLabel: settingsTelemetry.label, telemetryCode: settingsTelemetry.code, action: settingsTelemetry.action,
      meter: agentMeter,
      legend: `<span class="${registeredAgents ? 'lit' : ''}">ON</span><span class="${availableAgents ? 'info' : ''}">ADD</span><span class="${brokenAgents ? 'fault' : ''}">FIX</span>`,
    },
  };
  const model = models[activePage] || models.connections;
  const meter = Array.from({ length: 8 }, (_, index) => `<i class="${model.meter[index] || ''}"></i>`).join('');
  const reading = model.valueKind === 'word' ? displayWord(model.value) : sevenSegmentNumber(model.value);
  $('#metrics').innerHTML = `
    <div class="display-grain" aria-hidden="true"></div>
    <div class="display-channels" aria-label="${localized('设备通道状态', 'Device channel status')}">
      ${model.channels.map(([key, label, className]) => `<div class="display-channel ${className}"><b>${key}</b><span>${label}</span><i></i></div>`).join('')}
    </div>
    <div class="display-primary">
      <div class="display-mode"><span>${model.minor}</span><b>${model.mode}</b></div>
      <div class="display-count ${model.valueKind === 'word' ? 'is-word' : ''}">${reading}<span class="display-count-unit">${model.unit}</span></div>
      <div class="display-ready ${model.readyTone || ''}"><i class="display-play"></i><strong>${model.ready}</strong><em>${model.tag}</em></div>
      <div class="display-ghost-labels" aria-hidden="true"><span>MCP</span><span>WEB</span><span>LOCK</span><span>AUTH</span></div>
    </div>
    <div class="display-telemetry ${model.telemetryStatus} telemetry-page-${activePage}">
      <div class="telemetry-head"><span>${model.telemetryLabel}</span><i aria-hidden="true"></i></div>
      <div class="telemetry-reading"><strong>${model.telemetryCode}</strong><span>${escapeHtml(model.action)}</span></div>
      <div class="activity-meter" aria-label="${localized('当前页面状态', 'Current page status')}">${meter}</div>
      <div class="relay-legend">${model.legend}</div>
    </div>`;
}

function itemDetail(item) {
  const capabilities = itemCapabilities(item);
  const targets = [];
  if (capabilities.includes('ssh')) targets.push(`${item.host}:${item.port}`);
  if (capabilities.includes('http')) targets.push(item.baseUrl || localized('运行时 URL', 'RUNTIME URL'));
  if (targets.length) return targets.join(' · ');
  const count = (item.modules || []).filter((module) => module.secret).length || item.secret?.fields?.length || 0;
  return capabilities.includes('fill')
    ? `${count} ENCRYPTED FIELD${count === 1 ? '' : 'S'}`
    : localized('草稿 · 尚无可用动作', 'DRAFT · NO AVAILABLE ACTION');
}

function itemCapabilities(item) {
  const raw = Array.isArray(item.capabilities) ? item.capabilities : [];
  if (raw.length) return [...new Set(raw.map((value) => value === 'api' ? 'http' : value).filter((value) => ['fill', 'ssh', 'http'].includes(value)))];
  const modules = Array.isArray(item.modules) ? item.modules : [];
  if (modules.length) {
    const configured = (kind) => modules.some((module) => module.kind === kind && module.configured);
    const valued = (kind) => modules.some((module) => module.kind === kind && String(module.value || '').trim());
    const capabilities = [];
    if (modules.some((module) => module.secret && module.configured)) capabilities.push('fill');
    if (valued('host') && valued('port') && configured('username') && (configured('password') || configured('privateKey'))) capabilities.push('ssh');
    if (configured('apiCredential')) capabilities.push('http');
    return capabilities;
  }
  return item.type === 'ssh' ? ['fill', 'ssh'] : item.type === 'api' ? ['fill', 'http'] : item.type ? ['fill'] : [];
}

function itemAuthModule(item) {
  const capabilities = itemCapabilities(item);
  if (!capabilities.length) return 'DRAFT';
  return capabilities.map((value) => value === 'http' ? 'HTTP' : value.toUpperCase()).join(' · ');
}

function itemPermission(item) {
  const capabilities = itemCapabilities(item);
  if (capabilities.includes('http')) return (item.allowedMethods || []).join(' · ') || 'GET';
  if (capabilities.includes('ssh')) return 'SSH';
  return capabilities.includes('fill') ? 'FOCUS INPUT' : 'NOT EXPOSED';
}

const activityFilterDefinitions = {
  all: { key: 'A', label: 'ALL' },
  error: { key: 'B', label: 'ERROR' },
  success: { key: 'C', label: 'PASS' },
};

function setActivityFilterMenu(open) {
  $('#activity-filter-menu').classList.toggle('hidden', !open);
  $('#activity-filter-menu-button').setAttribute('aria-expanded', String(open));
}

function syncActivityFilterControl() {
  const selected = activityFilterDefinitions[currentActivityFilter] || activityFilterDefinitions.all;
  $('#activity-filter-current-key').textContent = selected.key;
  $('#activity-filter-current-label').textContent = selected.label;
  $$('#activity-filter-menu [data-activity-filter]').forEach((button) => button.classList.toggle('active', button.dataset.activityFilter === currentActivityFilter));
}

function renderConnections() {
  const query = normalizeSearch(pageSearch.connections);
  const items = state.connections.filter((item) => {
    if (!query) return true;
    const fields = (item.secret?.fields || []).map((field) => field.name).join(' ');
    return normalizeSearch([item.name, item.description, itemCapabilities(item).join(' '), itemDetail(item), itemPermission(item), fields].join(' ')).includes(query);
  });
  const container = $('#connections-list');
  if (!items.length) {
    const hasItems = state.connections.length > 0;
    container.innerHTML = `<div class="empty-state"><div><div class="empty-code">LOCAL VAULT</div><h3>${hasItems ? localized('没有匹配项目', 'NO MATCHING ITEMS') : localized('还没有秘密项目', 'NO VAULT ITEMS')}</h3><p>${hasItems ? localized('当前搜索没有结果。', 'No items match the current search.') : localized('KRU 保存秘密，并在 Agent 指定的最后一步完成写入。', 'KRU stores secrets and writes them only at the final step selected by an agent.')}</p><button class="button primary" data-action="${hasItems ? 'clear-connection-filters' : 'add'}">${hasItems ? localized('清除搜索', 'CLEAR SEARCH') : localized('添加项目', 'ADD ITEM')}</button></div></div>`;
    queueScrollThumbSync();
    return;
  }
  container.innerHTML = items.map((item) => {
    const stableIndex = state.connections.findIndex((candidate) => candidate.id === item.id) + 1;
    const authModule = itemAuthModule(item);
    const capabilities = itemCapabilities(item);
    const canTest = item.enabled && (capabilities.includes('ssh') || (capabilities.includes('http') && item.baseUrl));
    return `<article class="connection-card ${itemCapabilities(item).includes('ssh') ? 'ssh' : itemCapabilities(item).includes('http') ? 'http' : 'fill'} ${item.enabled ? '' : 'disabled'}">
      <div class="module-strip"><span>ITEM / ${String(stableIndex).padStart(2, '0')}</span><button class="module-state" type="button" data-action="toggle-enabled" data-id="${item.id}" aria-pressed="${item.enabled}" title="${item.enabled ? localized('点击停用；Agent 将无法使用其中的秘密', 'Disable this item; agents will no longer be able to use its secrets') : localized('点击启用；Agent 将可以使用其中的秘密', 'Enable this item so agents can use its secrets')}"><i class="status-dot ${item.enabled ? '' : 'off'}"></i>${item.enabled ? 'READY' : 'OFF'}</button></div>
      <div class="connection-top"><div class="connection-main"><div class="connection-name-row"><span class="connection-name"><span>${escapeHtml(item.name)}</span></span></div><div class="connection-address">${escapeHtml(itemDetail(item))}</div></div><div class="connection-symbol">${escapeHtml(authModule)}</div></div>
      ${item.description ? `<div class="connection-description">${escapeHtml(item.description)}</div>` : ''}
      <div class="card-actions"><button class="small-button" type="button" data-action="test" data-id="${item.id}" ${canTest ? '' : 'disabled'}>CHECK</button><button class="small-button" type="button" data-action="copy-name" data-id="${item.id}" title="${localized('复制 KRU MCP 使用提示', 'Copy KRU MCP use prompt')}" aria-label="${localized('复制 KRU MCP 使用提示', 'Copy KRU MCP use prompt')}">USE</button><button class="small-button" type="button" data-action="edit" data-id="${item.id}">EDIT</button><button class="small-button delete" type="button" data-action="delete" data-id="${item.id}">DEL</button></div>
    </article>`;
  }).join('');
  requestAnimationFrame(() => {
    $$('.connection-name', container).forEach((label) => {
      const text = label.firstElementChild;
      const distance = Math.max(0, Math.ceil(text.scrollWidth - label.clientWidth));
      label.classList.toggle('scrollable', distance > 0);
      label.style.setProperty('--name-scroll-distance', `${distance}px`);
      label.style.setProperty('--name-scroll-duration', `${Math.max(3, distance / 22 + 1.5)}s`);
    });
  });
  queueScrollThumbSync();
}

function draftSecretValues(secrets = {}) {
  const named = secrets.namedSecrets || {};
  return {
    ...named,
    password: secrets.password || named.password || '',
    passphrase: secrets.passphrase || named.passphrase || '',
    privateKey: secrets.privateKey || '',
    apiCredential: named.apiCredential || secrets.token || secrets.apiKey || '',
  };
}

function renderDrafts() {
  const button = $('#drafts-button');
  if (!button) return;
  const hasDraft = Boolean(editorDrafts[0]);
  const deleteButton = $('#delete-draft-button');
  button.disabled = !hasDraft;
  button.textContent = localized('草稿', 'DRAFT');
  button.title = hasDraft ? localized('继续最近的草稿', 'Continue the most recent draft') : localized('暂无草稿', 'No draft');
  deleteButton.classList.toggle('hidden', !hasDraft);
  deleteButton.title = localized('删除草稿', 'Delete draft');
}

async function refreshDrafts(showError = false) {
  if (!ownerLockState.unlocked) {
    editorDrafts = [];
    renderDrafts();
    return;
  }
  try {
    editorDrafts = await api.drafts();
    renderDrafts();
  } catch (error) {
    if (showError) toast(cleanError(error), 'error');
  }
}

function formatTime(value) {
  const diff = Date.now() - new Date(value).getTime();
  if (diff < 60_000) return localized('刚刚', 'JUST NOW');
  if (diff < 3_600_000) return localized(`${Math.floor(diff / 60_000)} 分钟前`, `${Math.floor(diff / 60_000)} MIN AGO`);
  if (diff < 86_400_000) return localized(`${Math.floor(diff / 3_600_000)} 小时前`, `${Math.floor(diff / 3_600_000)} HR AGO`);
  return new Date(value).toLocaleString(language === 'en' ? 'en-US' : 'zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function activityAction(action = '') {
  const raw = String(action);
  if (language !== 'en' || !HAN_TEXT.test(raw)) return raw;
  if (/测试连接/.test(raw)) return 'Test connection';
  if (/重置.*SSH.*主机信任/.test(raw)) return 'Reset SSH host trust';
  if (/导入备份/.test(raw)) return 'Import portable backup';
  if (/填写|填入/.test(raw)) return `Fill secret field (${activityCode(raw)})`;
  return 'KRU operation';
}

function activitySource(source = '') {
  if (language === 'en' && HAN_TEXT.test(String(source))) return 'APP';
  return source;
}

function renderActivity() {
  syncActivityFilterControl();
  const container = $('#activity-list');
  const query = normalizeSearch(pageSearch.activity);
  const activities = state.activities.map((activity, sourceIndex) => ({ activity, sourceIndex })).filter(({ activity }) => {
    if (currentActivityFilter !== 'all' && activity.status !== currentActivityFilter) return false;
    return !query || normalizeSearch([activity.action, activity.connectionName, activity.source, activity.status, activity.error].join(' ')).includes(query);
  });
  activityMatchCount = activities.length;
  if (!activities.length) {
    const hasActivity = state.activities.length > 0;
    container.innerHTML = `<div class="empty-state"><div><h3>${hasActivity ? localized('没有匹配记录', 'NO MATCHING ACTIVITY') : localized('暂无操作记录', 'NO ACTIVITY YET')}</h3><p>${hasActivity ? localized('当前搜索或结果筛选没有记录。', 'No activity matches the current search and result filter.') : localized('Agent 使用 KRU 后，这里只显示不含秘密的摘要。', 'After an agent uses KRU, only secret-free summaries appear here.')}</p>${hasActivity ? `<button class="button primary" data-action="clear-activity-filters">${localized('重置搜索与筛选', 'RESET SEARCH & FILTER')}</button>` : ''}</div></div>`;
    queueScrollThumbSync();
    return;
  }
  container.innerHTML = activities.slice(0, activityVisibleCount).map(({ activity, sourceIndex }) => {
    const errorExpanded = expandedActivityErrors.has(activity.id);
    return `<article class="activity-item"><div class="log-index">${String(state.activities.length - sourceIndex).padStart(4, '0')}</div><div class="activity-status ${activity.status === 'error' ? 'error' : ''}">${activity.status === 'error' ? '×' : '✓'}</div><div><div class="activity-title">${escapeHtml(activityAction(activity.action))} · ${escapeHtml(activity.connectionName)}</div><div class="activity-meta">${escapeHtml(activitySource(activity.source))} · ${activity.durationMs} ms</div>${activity.error ? `<button type="button" class="activity-error ${errorExpanded ? 'expanded' : ''}" data-expand-error="${activity.id}" aria-expanded="${errorExpanded}">${escapeHtml(publicMessage(activity.error, localized('操作失败', 'Operation failed. Details are available in the local log.')))}</button>` : ''}</div><time class="activity-time">${formatTime(activity.time)}</time></article>`;
  }).join('');
  queueScrollThumbSync();
}

function queueMoreActivities() {
  if (activityLoadPending || activityVisibleCount >= activityMatchCount) return;
  activityLoadPending = true;
  setTimeout(() => {
    activityVisibleCount = Math.min(activityVisibleCount + ACTIVITY_PAGE_SIZE, activityMatchCount);
    renderActivity();
    activityLoadPending = false;
  }, 120);
}

function applySettingsSearch() {
  const query = normalizeSearch(pageSearch.settings);
  let visible = 0;
  for (const card of $$('.settings-card')) {
    const matches = !query || normalizeSearch(`${card.dataset.module || ''} ${card.textContent}`).includes(query);
    card.classList.toggle('search-hidden', !matches);
    if (matches) visible += 1;
  }
  $('#settings-search-empty').classList.toggle('hidden', visible > 0);
  queueScrollThumbSync();
}

function renderSettings() {
  $('#mcp-endpoint').textContent = `${state.mcp.stdioCommand} mcp stdio`;
  const mcpFault = state.mcp.status === 'error';
  const mcpStrip = $('#mcp-status-strip');
  mcpStrip.className = `status-strip ${mcpFault ? 'error' : ''}`;
  mcpStrip.innerHTML = `<span class="status-dot"></span><span class="status-key">${mcpFault ? 'FAULT' : 'READY'}</span><span>${mcpFault ? escapeHtml(publicMessage(state.mcp.error)) : localized('Agent 使用时自动启动 stdio，无需常驻服务。', 'stdio starts on demand. No background service.')}</span>`;
  $('#agent-restart-notice').classList.toggle('hidden', !agentRestartRequired);
  $('#desktop-shortcut-enabled').checked = Boolean(systemIntegrationState.desktopShortcut);
  $('#launch-at-login-enabled').checked = Boolean(systemIntegrationState.launchAtLogin);
  $('#pin-enabled').checked = ownerLockState.pinConfigured || ownerPinSetupRequested;
  $('#close-behavior').value = state.settings.closeBehavior === 'exit' ? 'exit' : 'tray';
  $('#browser-enabled').checked = state.settings.browserEnabled;
  $('#browser-port').value = state.settings.browserPort;
  const bridge = state.browserBridge;
  const online = ['listening', 'delegated'].includes(bridge.status);
  const strip = $('#browser-status-strip');
  strip.className = `status-strip ${bridge.status === 'error' ? 'error' : online ? '' : 'offline'}`;
  strip.innerHTML = `<span class="status-dot"></span><span class="status-key">${bridge.status === 'error' ? 'FAULT' : online ? (bridge.connected ? 'CONNECTED' : bridge.paired ? 'WAITING' : 'READY') : 'OFF'}</span><span>${bridge.status === 'error' ? escapeHtml(publicMessage(bridge.error)) : online ? escapeHtml(bridge.endpoint) : localized('Browser Bridge 已关闭', 'Browser Bridge is off')}</span>`;
  $('#reset-pairing-button').disabled = !bridge.paired;
  renderAgents();
  applySettingsSearch();
}

const agentLabels = { notDetected: 'NOT FOUND', available: 'READY', registered: 'CONNECTED', stale: 'NEEDS REPAIR', conflict: 'CONFLICT', error: 'ERROR' };
function agentDetail(client) {
  const details = language === 'en'
    ? { notDetected: 'Not installed', available: 'Ready to connect', registered: 'Connected', stale: 'KRU setup needs repair', conflict: 'Config conflict', error: 'Detection failed' }
    : { notDetected: '未安装或未发现', available: '可连接', registered: '已连接', stale: 'KRU 连接或全局规则需要修复', conflict: '配置冲突', error: '检测失败' };
  return details[client.state] || publicMessage(client.message, localized('状态已更新', 'Status updated'));
}
function renderAgents() {
  const container = $('#agent-client-list');
  container.innerHTML = agentClients.length ? agentClients.map((client) => `<div class="agent-client-row ${client.canRegister ? '' : 'is-disabled'}"><span class="agent-client-copy"><strong>${escapeHtml(client.displayName)}</strong><span>${escapeHtml(agentDetail(client))}</span></span><div class="agent-row-controls"><span class="agent-state ${escapeHtml(client.state)}">${escapeHtml(agentLabels[client.state] || client.state)}</span><div class="agent-row-actions">${client.canRegister ? `<button type="button" class="agent-row-action primary" data-agent-action="connect" data-client-id="${escapeHtml(client.clientId)}">CONNECT</button>` : ''}${client.canRepair ? `<button type="button" class="agent-row-action primary" data-agent-action="repair" data-client-id="${escapeHtml(client.clientId)}">REPAIR</button>` : ''}${client.canRemove ? `<button type="button" class="agent-row-action" data-agent-action="remove" data-client-id="${escapeHtml(client.clientId)}">REMOVE</button>` : ''}</div></div></div>`).join('') : `<div class="agent-scan-placeholder">${localized('没有检测到支持的 Agent', 'NO SUPPORTED AGENT DETECTED')}</div>`;
  applySettingsSearch();
}

async function scanAgents(showToast = false) {
  try {
    agentClients = await api.agents();
    renderAgents();
    if (state) renderMetrics();
    if (showToast) toast(localized('Agent 扫描完成', 'Agent scan complete'));
  } catch (error) { toast(cleanError(error), 'error'); }
}

const MODULE_DEFS = {
  username: { code: 'USR', zh: '账号', en: 'USERNAME', secret: true },
  password: { code: 'PWD', zh: '密码', en: 'PASSWORD', secret: true },
  apiCredential: { code: 'API', zh: 'API 凭据', en: 'API CREDENTIAL', secret: true },
  privateKey: { code: 'KEY', zh: '私钥', en: 'PRIVATE KEY', secret: true },
  passphrase: { code: 'PPH', zh: '私钥口令', en: 'KEY PASSPHRASE', secret: true },
  totp: { code: 'OTP', zh: 'TOTP', en: 'TOTP', secret: true },
  customSecret: { code: 'SEC', zh: '自定义字段', en: 'CUSTOM FIELD', secret: true },
  host: { code: 'HST', zh: '主机 / IP', en: 'HOST / IP', secret: false },
  port: { code: 'PRT', zh: '端口', en: 'PORT', secret: false },
  url: { code: 'URL', zh: '服务 URL', en: 'SERVICE URL', secret: false },
};

function moduleHasPlaintextReveal(kind) {
  return Boolean(MODULE_DEFS[kind]?.secret);
}

function defaultModuleAgentVisible(kind) {
  return !moduleHasPlaintextReveal(kind);
}

function moduleSecretName(module) {
  return module.kind === 'customSecret' ? String(module.name || '').trim() : MODULE_DEFS[module.kind]?.secret ? module.kind : '';
}

function moduleLabel(kind) {
  const definition = MODULE_DEFS[kind] || MODULE_DEFS.customSecret;
  return language === 'en' ? definition.en : definition.zh;
}

function syncModuleDraft() {
  const rows = $$('.module-row', $('#module-list'));
  if (!rows.length) return;
  currentModules = rows.map((row, index) => {
    row.dataset.moduleIndex = String(index);
    return {
      kind: row.dataset.kind,
      name: $('[data-module-name]', row)?.value ?? row.dataset.name ?? '',
      value: $('[data-module-value]', row)?.value ?? '',
      secretValue: $('[data-secret-value]', row)?.value ?? '',
      configured: row.dataset.configured === 'true',
      existing: row.dataset.existing === 'true',
      privateKeyName: row.dataset.privateKeyName || '',
      pending: row.dataset.pending === 'true',
      agentVisible: $('[data-module-agent-visible]', row)?.getAttribute('aria-pressed') === 'true',
    };
  });
}

function editorModule(kind) {
  return currentModules.find((module) => module.kind === kind);
}

function moduleConfigured(module) {
  return Boolean(module && (String(module.secretValue || '').length || module.configured || module.pending));
}

function updateModuleStatus() {
  syncModuleDraft();
}

function renderModules() {
  const container = $('#module-list');
  if (!currentModules.length) {
    container.innerHTML = `<div class="module-empty"><b>EMPTY / DRAFT</b><span>${localized('选择模板或添加任意模块', 'Choose a template or add any module')}</span></div>`;
    updateModuleStatus();
    return;
  }
  container.innerHTML = currentModules.map((module, index) => {
    const definition = MODULE_DEFS[module.kind] || MODULE_DEFS.customSecret;
    const agentVisible = typeof module.agentVisible === 'boolean' ? module.agentVisible : defaultModuleAgentVisible(module.kind);
    const agentVisibilityLabel = agentVisible
      ? localized('Agent 可查看此值', 'Agent can see this value')
      : localized('不向 Agent 显示此值', 'Hidden from agent');
    const secretName = moduleSecretName(module);
    const customName = module.kind === 'customSecret'
      ? `<input class="input module-name-input" data-module-name value="${escapeHtml(module.name || '')}" placeholder="${localized('字段名称', 'FIELD NAME')}" />`
      : `<strong>${escapeHtml(moduleLabel(module.kind))}</strong>${secretName ? `<small>${escapeHtml(secretName)}</small>` : ''}`;
    let control = '';
    let actions = '';
    if (module.kind === 'privateKey') {
      const keyState = module.pending ? module.privateKeyName : module.configured ? (module.privateKeyName || 'IMPORTED KEY') : localized('尚未导入', 'NOT IMPORTED');
      control = `<div class="module-key-control"><span>${escapeHtml(keyState)}</span><button type="button" class="copy-secret-button" data-choose-module-key>SELECT</button></div>${module.secretValue ? `<div class="secret-input-control module-secret-control multiline module-key-secret"><textarea class="input textarea secret-masked" data-secret-value readonly>${escapeHtml(module.secretValue)}</textarea></div>` : '<input type="hidden" data-secret-value value="" />'}`;
      const keyActionsDisabled = !module.secretValue;
      actions = `${secretActionButton('reveal', true, keyActionsDisabled)}${secretActionButton('copy', true, keyActionsDisabled)}`;
    } else if (definition.secret) {
      const placeholder = module.kind === 'totp' ? localized('Base32 设置密钥', 'BASE32 SETUP KEY') : localized('输入秘密值', 'ENTER SECRET VALUE');
      control = `<div class="secret-input-control module-secret-control"><input class="input" data-secret-value type="password" autocomplete="off" value="${escapeHtml(module.secretValue || '')}" placeholder="${placeholder}" /></div>`;
      actions = `${secretActionButton('reveal')}${secretActionButton('copy')}`;
    } else {
      const inputType = module.kind === 'port' ? 'number' : 'text';
      const placeholder = module.kind === 'url' ? 'api.example.com/v1/' : module.kind === 'host' ? 'host.example.com' : '22';
      control = `<input class="input" data-module-value type="${inputType}" ${module.kind === 'port' ? 'min="1" max="65535"' : ''} value="${escapeHtml(module.value || '')}" placeholder="${placeholder}" />`;
      actions = `<span class="module-action-spacer" aria-hidden="true"></span>${secretActionButton('copy', false)}`;
    }
    const removeLabel = localized('删除模块', 'Remove module');
    return `<div class="module-row" data-module-index="${index}" data-kind="${escapeHtml(module.kind)}" data-name="${escapeHtml(module.name || '')}" data-existing="${Boolean(module.existing)}" data-configured="${Boolean(module.configured)}" data-private-key-name="${escapeHtml(module.privateKeyName || '')}" data-pending="${Boolean(module.pending)}"><button type="button" class="module-agent-toggle" data-module-agent-visible aria-pressed="${agentVisible}" aria-label="${agentVisibilityLabel}" title="${agentVisibilityLabel}"><i aria-hidden="true"></i></button><div class="module-identity">${customName}</div><div class="module-control">${control}</div><div class="module-actions ${actions ? 'full' : 'single'}">${actions}<button type="button" class="remove-module module-action-icon" data-remove-module aria-label="${removeLabel}" title="${removeLabel}"><svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 5.5h14M7.5 5.5V3.25h5v2.25M5.25 5.5l.75 11h8l.75-11M8.25 8.5v5M11.75 8.5v5"/></svg></button></div></div>`;
  }).join('');
  updateModuleStatus();
}

function secretActionButton(kind, secret = true, disabled = false) {
  const disabledAttribute = disabled ? ' disabled' : '';
  if (kind === 'reveal') {
    const label = localized('显示明文', 'Show secret');
    return `<button type="button" class="reveal-secret-button secret-icon-button module-action-icon" data-toggle-module-secret aria-pressed="false" aria-label="${label}" title="${label}"${disabledAttribute}><svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 10s2.4-4.75 7-4.75S17 10 17 10s-2.4 4.75-7 4.75S3 10 3 10Z"/><circle cx="10" cy="10" r="2.5"/><path class="secret-icon-slash" d="M3.5 3.5l13 13"/></svg></button>`;
  }
  const label = secret ? localized('复制隐私值', 'Copy private value') : localized('复制值', 'Copy value');
  const attribute = secret ? 'data-copy-module-secret' : 'data-copy-module-value';
  return `<button type="button" class="copy-secret-button secret-icon-button module-action-icon" ${attribute} aria-label="${label}" title="${label}"${disabledAttribute}><svg viewBox="0 0 20 20" aria-hidden="true"><rect x="7" y="7" width="10" height="10"/><path d="M14 7V3H3v11h4"/></svg></button>`;
}

function positionModuleMenu() {
  const menu = $('#module-menu');
  if (menu.classList.contains('hidden')) return;
  const buttonRect = $('#add-module-button').getBoundingClientRect();
  const gutter = 8;
  const menuWidth = Math.min(276, window.innerWidth - gutter * 2);
  menu.style.width = `${menuWidth}px`;
  menu.style.left = `${Math.round(Math.min(Math.max(gutter, buttonRect.right - menuWidth), window.innerWidth - menuWidth - gutter))}px`;
  menu.style.right = 'auto';
  menu.style.maxHeight = `${window.innerHeight - gutter * 2}px`;
  const menuHeight = Math.min(menu.scrollHeight, window.innerHeight - gutter * 2);
  const below = buttonRect.bottom + 4;
  const top = below + menuHeight <= window.innerHeight - gutter
    ? below
    : Math.max(gutter, buttonRect.top - menuHeight - 4);
  menu.style.top = `${Math.round(top)}px`;
}

function setModuleMenu(open) {
  const menu = $('#module-menu');
  const home = $('#add-module-button').closest('.module-add-wrap');
  if (open) {
    document.body.appendChild(menu);
    menu.classList.remove('hidden');
    positionModuleMenu();
  } else {
    menu.classList.add('hidden');
    home.appendChild(menu);
    menu.removeAttribute('style');
  }
  $('#add-module-button').setAttribute('aria-expanded', String(Boolean(open)));
}

function addModule(kind, options = {}) {
  syncModuleDraft();
  if (kind !== 'customSecret' && currentModules.some((module) => module.kind === kind)) {
    setModuleMenu(false);
    return toast(localized('这个模块已经存在', 'That module already exists'));
  }
  currentModules.push({
    kind,
    name: kind === 'customSecret' ? '' : kind,
    value: kind === 'port' ? '22' : '',
    secretValue: '',
    configured: false,
    existing: false,
    privateKeyName: '',
    pending: false,
    agentVisible: defaultModuleAgentVisible(kind),
    ...options,
  });
  setModuleMenu(false);
  $('#template-picker').classList.add('hidden');
  renderModules();
  const row = $$('.module-row').at(-1);
  ($('[data-module-name]', row) || $('[data-secret-value]', row) || $('[data-module-value]', row))?.focus();
}

function applyTemplate(template) {
  const presets = {
    login: ['username', 'password'],
    ssh: ['host', 'port', 'username', 'password'],
    api: ['apiCredential'],
    blank: [],
  };
  currentModules = (presets[template] || []).map((kind) => ({ kind, name: kind, value: kind === 'port' ? '22' : '', secretValue: '', configured: false, existing: false, privateKeyName: '', pending: false, agentVisible: defaultModuleAgentVisible(kind) }));
  $('#template-picker').classList.add('hidden');
  renderModules();
}

function updateAuthFields() {
  updateModuleStatus();
}

function value(selector, next) {
  const element = $(selector);
  if (arguments.length > 1) element.value = next ?? '';
  return element.value;
}

function updateEditorTitle() {
  $('#modal-title').textContent = editorOpenedFromDraft
    ? (editorExistingItem ? localized('继续编辑', 'CONTINUE EDIT') : localized('继续草稿', 'CONTINUE DRAFT'))
    : (editorExistingItem ? localized('编辑项目', 'EDIT ITEM') : localized('添加项目', 'ADD ITEM'));
}

async function openEditor(item = null, draft = null) {
  if (!draft && item) draft = editorDrafts.find((candidate) => candidate.input?.id === item.id) || null;
  if (!item && draft?.input?.id) item = state.connections.find((candidate) => candidate.id === draft.input.id) || null;
  let ownerValues = {};
  if (draft) {
    ownerValues = draftSecretValues(draft.input?.secrets);
  } else if (item) {
    try {
      const view = await api.ownerSecrets(item.id);
      ownerValues = Object.fromEntries(view.fields.map((field) => [field.name, field.value]));
    } catch (error) {
      toast(cleanError(error), 'error');
      await refreshOwnerLock(false);
      return;
    }
  }
  const source = draft?.input || item || null;
  removedSecretFields = new Set();
  editorExistingItem = item;
  editorSourceInput = source;
  editorOpenedFromDraft = Boolean(draft);
  currentDraftId = draft?.id || '';
  value('#connection-id', item?.id);
  value('#connection-name', source?.name);
  value('#connection-description', source?.description);
  $('#connection-enabled').checked = source?.enabled ?? true;
  updateEditorTitle();
  $('#template-picker').classList.toggle('hidden', Boolean(item || draft?.input?.modules?.length));
  currentModules = (source?.modules || []).map((module) => {
    const secretName = module.kind === 'customSecret' ? module.name : module.kind;
    const privateKeyName = draft?.input?.secrets?.privateKeyName || item?.privateKeyName || '';
    return { ...module, secretValue: ownerValues[secretName] || '', configured: Boolean(module.configured || ownerValues[secretName]), existing: Boolean(item), privateKeyName: module.kind === 'privateKey' ? privateKeyName : '', pending: false, agentVisible: typeof module.agentVisible === 'boolean' ? module.agentVisible : defaultModuleAgentVisible(module.kind) };
  });
  renderModules();
  $('#connection-modal').classList.remove('hidden');
  $('.form-scroll', $('#connection-modal')).scrollTop = 0;
  editorInitialSnapshot = JSON.stringify(serializeItem(false));
}

function closeEditor() {
  $('#connection-modal').classList.add('hidden');
  setModuleMenu(false);
  editorSourceInput = null;
  editorOpenedFromDraft = false;
  editorInitialSnapshot = '';
}

function collectModules(validate = true) {
  syncModuleDraft();
  const modules = [];
  const secrets = { namedSecrets: {} };
  const secretNames = new Set();
  for (const module of currentModules) {
    const name = moduleSecretName(module);
    if (module.kind === 'customSecret') {
      if (validate && !name) throw new Error(localized('请输入字段名称', 'Enter a field name'));
      const normalizedName = name.toLocaleLowerCase().replace(/[\s_-]+/g, '');
      if (validate && ['username', 'password', 'apicredential', 'privatekey', 'passphrase', 'totp', 'token', 'apikey'].includes(normalizedName)) throw new Error(localized(`字段名与内置模块冲突：${name}`, `Field name conflicts with a built-in module: ${name}`));
    }
    const uniqueName = name.toLocaleLowerCase().replace(/[\s_-]+/g, '');
    if (validate && name && secretNames.has(uniqueName)) throw new Error(localized(`字段名重复：${name}`, `Duplicate field name: ${name}`));
    if (name) secretNames.add(uniqueName);
    modules.push({ kind: module.kind, name: module.kind === 'customSecret' ? name : '', value: MODULE_DEFS[module.kind]?.secret ? '' : String(module.value || '').trim(), agentVisible: Boolean(module.agentVisible) });
    const fieldValue = module.secretValue || '';
    if (name === 'password') secrets.password = fieldValue;
    else if (name === 'passphrase') secrets.passphrase = fieldValue;
    else if (name === 'privateKey') secrets.privateKey = fieldValue;
    else if (name) secrets.namedSecrets[name] = fieldValue;
  }
  return { modules, secrets, privateKeyImportPath: currentModules.some((module) => module.kind === 'privateKey' && module.pending) ? 'pending' : '' };
}

function serializeItem(validate = true) {
  const name = value('#connection-name').trim();
  if (validate && !name) throw new Error(localized('请输入项目名称', 'Enter an item name'));
  const id = value('#connection-id') || null;
  if (validate && state.connections.some((item) => item.id !== id && item.name.trim().toLowerCase() === name.toLowerCase())) {
    throw new Error(localized('项目名称已存在，请使用其他名称', 'An item with this name already exists'));
  }
  syncModuleDraft();
  if (validate && !currentModules.length) throw new Error(localized('请至少添加一个模块', 'Add at least one module'));
  const collected = collectModules(validate);
  return {
    id,
    modules: collected.modules,
    name,
    description: value('#connection-description'),
    enabled: $('#connection-enabled').checked,
    httpAuthType: editorSourceInput?.httpAuthType || 'auto',
    authHeader: editorSourceInput?.authHeader || '',
    authLocation: editorSourceInput?.authLocation || '',
    authPrefix: editorSourceInput?.authPrefix || '',
    apiAuthHeaders: editorSourceInput?.apiAuthHeaders || [],
    allowedMethods: editorSourceInput?.allowedMethods || [],
    allowedPathPrefixes: editorSourceInput?.allowedPathPrefixes || [],
    testPath: editorSourceInput?.testPath || '',
    privateKeyImportPath: collected.privateKeyImportPath,
    removeSecretNames: [...removedSecretFields],
    secrets: collected.secrets,
  };
}

function editorHasDraftContent() {
  syncModuleDraft();
  return Boolean(value('#connection-name').trim() || value('#connection-description').trim() || currentModules.length);
}

async function closeEditorWithDraft() {
  try {
    const input = serializeItem(false);
    const changed = JSON.stringify(input) !== editorInitialSnapshot;
    if (!editorHasDraftContent() && !editorExistingItem) {
      if (currentDraftId) await api.deleteDraft(currentDraftId);
    } else if (changed || editorOpenedFromDraft || !editorExistingItem) {
      const saved = await api.saveDraft(currentDraftId || null, input);
      currentDraftId = saved.id;
      toast(editorExistingItem
        ? localized('未保存修改已保留，可随时继续', 'Unsaved changes kept for later')
        : localized('草稿已加密保存', 'Draft saved and encrypted'));
    }
    await refreshDrafts();
    closeEditor();
  } catch (error) {
    toast(cleanError(error), 'error');
  }
}

async function saveBrowserSettings() {
  try {
    state.settings = await api.settings({ browserEnabled: $('#browser-enabled').checked, browserPort: Number($('#browser-port').value) });
    toast(localized('Browser Bridge 设置已保存', 'Browser Bridge settings saved'));
    await refresh();
  } catch (error) {
    toast(cleanError(error), 'error');
    await refresh(false);
  }
}

async function saveDesktopSettings() {
  try {
    state.settings = await api.settings({
      closeBehavior: $('#close-behavior').value,
    });
    renderSettings();
    toast(localized('窗口设置已保存', 'Window settings saved'));
  } catch (error) {
    toast(cleanError(error), 'error');
    await refresh(false);
  }
}

async function setSystemIntegration(kind, enabled) {
  const input = kind === 'desktop' ? $('#desktop-shortcut-enabled') : $('#launch-at-login-enabled');
  input.disabled = true;
  try {
    systemIntegrationState = kind === 'desktop'
      ? await api.setDesktopShortcut(enabled)
      : await api.setLaunchAtLogin(enabled);
    renderSettings();
    toast(kind === 'desktop'
      ? (enabled ? localized('桌面快捷方式已创建', 'Desktop shortcut created') : localized('桌面快捷方式已移除', 'Desktop shortcut removed'))
      : (enabled ? localized('开机自启动已开启', 'Launch at login enabled') : localized('开机自启动已关闭', 'Launch at login disabled')));
  } catch (error) {
    input.checked = kind === 'desktop'
      ? Boolean(systemIntegrationState.desktopShortcut)
      : Boolean(systemIntegrationState.launchAtLogin);
    toast(cleanError(error), 'error');
  } finally {
    input.disabled = false;
  }
}

async function savePinSettings() {
  const toggle = $('#pin-enabled');
  if (toggle.checked) {
    ownerPinSetupRequested = true;
    renderOwnerLock();
    return;
  }
  if (!confirm(localized('关闭 PIN 锁会移除当前 PIN。继续？', 'Turning off the PIN lock removes the current PIN. Continue?'))) {
    toggle.checked = true;
    return;
  }
  toggle.disabled = true;
  try {
    ownerLockState = await api.ownerDisablePin();
    ownerPinSetupRequested = false;
    renderOwnerLock();
    renderMetrics();
    renderSettings();
    toast(localized('PIN 锁已关闭', 'PIN lock disabled'));
  } catch (error) {
    toast(cleanError(error), 'error');
    await refreshOwnerLock(false);
    renderSettings();
  } finally {
    toggle.disabled = false;
  }
}

async function setLanguage(next) {
  const selected = next === 'en' ? 'en' : 'zh';
  if (selected === language) return;
  language = selected;
  applyLanguage();
  if (state) {
    state.settings.language = language;
    renderOwnerLock();
    render();
    updateAuthFields();
    if (!$('#connection-modal').classList.contains('hidden')) renderModules();
    if (!$('#connection-modal').classList.contains('hidden')) updateEditorTitle();
    try {
      state.settings = await api.settings({ language });
    } catch (error) {
      toast(cleanError(error), 'error');
    }
  }
}

function toastImportSummary(summary) {
  toast(localized(`导入完成：新增 ${summary.added}，合并重复 ${summary.merged}`, `Import complete: ${summary.added} added, ${summary.merged} duplicates merged`));
}

async function exportBackup(button) {
  button.disabled = true;
  try {
    const path = await api.exportBackup();
    if (path) toast(localized('备份已导出，可由 KRU 自动解密导入', 'Backup exported and ready for automatic KRU import'));
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    button.disabled = false;
  }
}

async function importBackup(button) {
  button.disabled = true;
  try {
    const result = await api.importBackup();
    if (!result) return;
    toastImportSummary(result);
    await refresh();
  } catch (error) {
    toast(cleanError(error), 'error');
  } finally {
    button.disabled = false;
  }
}

document.addEventListener('click', async (event) => {
  const activityFilterMenuButton = event.target.closest('#activity-filter-menu-button');
  if (activityFilterMenuButton) setActivityFilterMenu(activityFilterMenuButton.getAttribute('aria-expanded') !== 'true');
  else if (!event.target.closest('#activity-filter-menu')) setActivityFilterMenu(false);
  const languageButton = event.target.closest('[data-language]');
  if (languageButton) await setLanguage(languageButton.dataset.language);
  const nav = event.target.closest('[data-page]');
  if (nav) {
    setActivityFilterMenu(false);
    activePage = nav.dataset.page;
    $('.nav').dataset.active = activePage;
    $$('.nav-item').forEach((item) => item.classList.toggle('active', item === nav));
    $$('.page').forEach((page) => page.classList.toggle('active', page.id === `page-${nav.dataset.page}`));
    renderMetrics();
    queueScrollThumbSync();
    if (nav.dataset.page === 'settings') scanAgents();
  }
  const windowButton = event.target.closest('[data-window-action]');
  if (windowButton) {
    if (windowButton.dataset.windowAction === 'close' && !$('#connection-modal').classList.contains('hidden')) await closeEditorWithDraft();
    await api.window(windowButton.dataset.windowAction);
    if (windowButton.dataset.windowAction === 'minimize') await refreshOwnerLock(false);
  }
  if (event.target.closest('#owner-lock-button')) {
    if (!$('#connection-modal').classList.contains('hidden')) await closeEditorWithDraft();
    await lockOwner();
  }
  const deleteDraftButton = event.target.closest('#delete-draft-button');
  if (deleteDraftButton && editorDrafts[0]) {
    if (!confirm(localized('删除当前草稿？此操作无法撤销。', 'Delete the current draft? This cannot be undone.'))) return;
    try {
      await api.deleteDraft(editorDrafts[0].id);
      editorDrafts = editorDrafts.slice(1);
      renderDrafts();
      toast(localized('草稿已删除', 'Draft deleted'));
    } catch (error) { toast(cleanError(error), 'error'); }
    return;
  }
  const draftsButton = event.target.closest('#drafts-button');
  if (draftsButton && editorDrafts[0]) await openEditor(null, editorDrafts[0]);
  const moduleButton = event.target.closest('#add-module-button');
  if (moduleButton) setModuleMenu(moduleButton.getAttribute('aria-expanded') !== 'true');
  else if (!event.target.closest('#module-menu')) setModuleMenu(false);
  const addModuleButton = event.target.closest('[data-add-module]');
  if (addModuleButton) addModule(addModuleButton.dataset.addModule);
  const templateButton = event.target.closest('[data-item-template]');
  if (templateButton) applyTemplate(templateButton.dataset.itemTemplate);
  if (event.target.closest('#add-connection-button') || event.target.closest('[data-action="add"]')) {
    await openEditor();
  }
  if (event.target === $('#connection-modal')) await closeEditorWithDraft();
  if (event.target.closest('[data-close-modal]')) await closeEditorWithDraft();
  const copyInput = event.target.closest('[data-copy-input]');
  const copyModule = event.target.closest('[data-copy-module-secret], [data-copy-module-value]');
  if (copyInput || copyModule) {
    const input = copyInput ? $(`#${copyInput.dataset.copyInput}`) : $('[data-secret-value], [data-module-value]', copyModule.closest('.module-row'));
    try { await api.copyOwnerValue(input.value); toast(localized('已复制', 'Copied')); } catch (error) { toast(cleanError(error), 'error'); }
  }
  const toggleModuleSecret = event.target.closest('[data-toggle-module-secret]');
  if (toggleModuleSecret) {
    const field = $('[data-secret-value]', toggleModuleSecret.closest('.module-row'));
    const revealed = toggleModuleSecret.getAttribute('aria-pressed') !== 'true';
    if (field.tagName === 'INPUT') field.type = revealed ? 'text' : 'password';
    else field.classList.toggle('secret-masked', !revealed);
    toggleModuleSecret.setAttribute('aria-pressed', String(revealed));
    const label = revealed ? localized('隐藏明文', 'Hide secret') : localized('显示明文', 'Show secret');
    toggleModuleSecret.setAttribute('aria-label', label);
    toggleModuleSecret.title = label;
  }
  const toggleAgentVisible = event.target.closest('[data-module-agent-visible]');
  if (toggleAgentVisible) {
    const visible = toggleAgentVisible.getAttribute('aria-pressed') !== 'true';
    toggleAgentVisible.setAttribute('aria-pressed', String(visible));
    const label = visible
      ? localized('Agent 可查看此值', 'Agent can see this value')
      : localized('不向 Agent 显示此值', 'Hidden from agent');
    toggleAgentVisible.setAttribute('aria-label', label);
    toggleAgentVisible.title = label;
    syncModuleDraft();
  }
  const chooseModuleKey = event.target.closest('[data-choose-module-key]');
  if (chooseModuleKey) {
    try {
      const name = await api.chooseKey();
      if (name) {
        syncModuleDraft();
        const index = Number(chooseModuleKey.closest('.module-row').dataset.moduleIndex);
        currentModules[index].pending = true;
        currentModules[index].configured = true;
        currentModules[index].privateKeyName = name;
        renderModules();
      }
    } catch (error) { toast(cleanError(error), 'error'); }
  }
  const removeModuleButton = event.target.closest('[data-remove-module]');
  if (removeModuleButton) {
    syncModuleDraft();
    const index = Number(removeModuleButton.closest('.module-row').dataset.moduleIndex);
    const removed = currentModules[index];
    if (removed?.existing && moduleSecretName(removed)) removedSecretFields.add(moduleSecretName(removed));
    currentModules.splice(index, 1);
    renderModules();
  }
  const action = event.target.closest('[data-action]');
  if (action?.dataset.action === 'clear-connection-filters') {
    pageSearch.connections = '';
    $('[data-page-search="connections"]').value = '';
    renderConnections();
  }
  if (action?.dataset.action === 'clear-activity-filters') {
    currentActivityFilter = 'all';
    pageSearch.activity = '';
    $('[data-page-search="activity"]').value = '';
    activityVisibleCount = ACTIVITY_PAGE_SIZE;
    renderActivity();
  }
  if (action?.dataset.id) {
    const item = state.connections.find((candidate) => candidate.id === action.dataset.id);
    if (action.dataset.action === 'toggle-enabled') {
      try {
        await api.setEnabled(item.id, !item.enabled);
        toast(item.enabled ? localized('项目已停用', 'Item disabled') : localized('项目已启用', 'Item enabled'));
        await refresh();
      } catch (error) { toast(cleanError(error), 'error'); }
    }
    if (action.dataset.action === 'edit') await openEditor(item);
    if (action.dataset.action === 'copy-name') {
      try {
        await api.copyOwnerValue(`use ${item.name} in KRU MCP`);
        toast(localized('KRU MCP 使用提示已复制', 'KRU MCP use prompt copied'));
      } catch (error) { toast(cleanError(error), 'error'); }
    }
    if (action.dataset.action === 'test') {
      try { toast(publicMessage(await api.test(item.id), localized('连接测试完成', 'Connection test complete'))); await refresh(false); } catch (error) { toast(cleanError(error), 'error'); }
    }
    if (action.dataset.action === 'delete' && confirm(localized(`删除“${item.name}”？此操作不可恢复。`, `Delete "${item.name}"? This cannot be undone.`))) {
      try { await api.remove(item.id); toast(localized('项目已删除', 'Item deleted')); await refresh(); } catch (error) { toast(cleanError(error), 'error'); }
    }
  }
  const activityFilter = event.target.closest('[data-activity-filter]');
  if (activityFilter) {
    currentActivityFilter = activityFilter.dataset.activityFilter;
    activityVisibleCount = ACTIVITY_PAGE_SIZE;
    syncActivityFilterControl();
    setActivityFilterMenu(false);
    renderActivity();
  }
  const errorDetail = event.target.closest('[data-expand-error]');
  if (errorDetail) {
    const expanded = errorDetail.getAttribute('aria-expanded') === 'true';
    if (expanded) expandedActivityErrors.delete(errorDetail.dataset.expandError);
    else expandedActivityErrors.add(errorDetail.dataset.expandError);
    errorDetail.setAttribute('aria-expanded', String(!expanded));
    errorDetail.classList.toggle('expanded', !expanded);
    queueScrollThumbSync();
  }
  const copy = event.target.closest('[data-copy-format]');
  if (copy) {
    try { await api.copyConfig(copy.dataset.copyFormat); toast(localized('stdio 配置已复制', 'stdio configuration copied')); } catch (error) { toast(cleanError(error), 'error'); }
  }
  const agentAction = event.target.closest('[data-agent-action]');
  if (agentAction) {
    try {
      const kind = agentAction.dataset.agentAction;
      const result = kind === 'connect'
        ? (await api.registerAgents([agentAction.dataset.clientId]))[0]
        : kind === 'repair'
          ? await api.repairAgent(agentAction.dataset.clientId)
          : await api.removeAgent(agentAction.dataset.clientId);
      if (result?.ok) {
        agentRestartRequired = true;
        $('#agent-restart-notice').classList.remove('hidden');
      }
      toast(result?.ok ? localized('已更新 · 新开 Agent 会话后生效', 'Updated · Open a new agent session to apply') : publicMessage(result?.message), result?.ok ? '' : 'error');
      await scanAgents();
    } catch (error) { toast(cleanError(error), 'error'); }
  }
});

document.addEventListener('input', (event) => {
  if (event.target.matches('.pin-cell-input')) {
    event.target.value = event.target.value.replace(/\D/g, '').slice(-1);
    if (event.target.value) {
      const inputs = $$('.pin-cell-input', event.target.closest('.pin-control'));
      inputs[inputs.indexOf(event.target) + 1]?.focus();
    }
  }
  if (event.target.closest('.module-row')) updateModuleStatus();
  const page = event.target.dataset.pageSearch;
  if (!page) return;
  pageSearch[page] = event.target.value;
  if (page === 'connections') renderConnections();
  if (page === 'activity') {
    activityVisibleCount = ACTIVITY_PAGE_SIZE;
    renderActivity();
  }
  if (page === 'settings') applySettingsSearch();
});

let draggedModuleRow = null;
let moduleDropTarget = null;
let moduleDropAfter = false;
let moduleDragPreview = null;
let modulePointerDrag = null;
let suppressModuleClick = false;
const moduleList = $('#module-list');
function clearModuleDropSeam() {
  $$('.module-row.drop-before, .module-row.drop-after', moduleList).forEach((row) => row.classList.remove('drop-before', 'drop-after'));
  moduleDropTarget = null;
  moduleDropAfter = false;
}

function beginModulePointerDrag(event) {
  draggedModuleRow = modulePointerDrag.row;
  draggedModuleRow.classList.add('is-dragging');
  moduleList.classList.add('is-sorting');
  document.body.classList.add('module-pointer-dragging');
  const definition = MODULE_DEFS[draggedModuleRow.dataset.kind] || MODULE_DEFS.customSecret;
  moduleDragPreview = document.createElement('div');
  moduleDragPreview.className = 'module-drag-preview';
  moduleDragPreview.innerHTML = `<b>${escapeHtml(definition.code)}</b><span>${escapeHtml(moduleLabel(draggedModuleRow.dataset.kind))}</span>`;
  document.body.appendChild(moduleDragPreview);
  modulePointerDrag.started = true;
  try { draggedModuleRow.setPointerCapture(event.pointerId); } catch (_) { /* document tracking remains active */ }
}

function updateModuleDropSeam(clientY) {
  clearModuleDropSeam();
  const rows = $$('.module-row', moduleList);
  if (!rows.length) return;
  const seams = rows.map((row) => ({ row, after: false, y: row.getBoundingClientRect().top }));
  const lastRow = rows.at(-1);
  seams.push({ row: lastRow, after: true, y: lastRow.getBoundingClientRect().bottom });
  const closest = seams.reduce((best, seam) => Math.abs(clientY - seam.y) < Math.abs(clientY - best.y) ? seam : best);
  moduleDropTarget = closest.row;
  moduleDropAfter = closest.after;
  moduleDropTarget.classList.add(moduleDropAfter ? 'drop-after' : 'drop-before');
}

function positionModuleDragPreview(clientX, clientY) {
  if (moduleDragPreview) moduleDragPreview.style.transform = `translate3d(${Math.round(clientX + 14)}px, ${Math.round(clientY + 14)}px, 0)`;
}

function autoScrollModuleEditor(clientY) {
  const scroller = $('.form-scroll', $('#connection-modal'));
  if (!scroller) return;
  const bounds = scroller.getBoundingClientRect();
  if (clientY < bounds.top + 34) scroller.scrollTop -= 12;
  else if (clientY > bounds.bottom - 34) scroller.scrollTop += 12;
}

function finishModulePointerDrag(commit) {
  if (!modulePointerDrag) return;
  const { row, pointerId, started } = modulePointerDrag;
  if (started && commit && moduleDropTarget) {
    moduleList.insertBefore(row, moduleDropAfter ? moduleDropTarget.nextElementSibling : moduleDropTarget);
  }
  try { if (row.hasPointerCapture(pointerId)) row.releasePointerCapture(pointerId); } catch (_) { /* capture may already be released */ }
  row.classList.remove('is-dragging');
  moduleList.classList.remove('is-sorting');
  document.body.classList.remove('module-pointer-dragging');
  moduleDragPreview?.remove();
  moduleDragPreview = null;
  draggedModuleRow = null;
  modulePointerDrag = null;
  clearModuleDropSeam();
  if (started) syncModuleDraft();
}

moduleList.addEventListener('dragstart', (event) => event.preventDefault());
moduleList.addEventListener('pointerdown', (event) => {
  if (event.button !== 0 || !event.isPrimary || event.target.closest?.('button')) return;
  const row = event.target.closest?.('.module-row');
  if (!row) return;
  modulePointerDrag = { row, pointerId: event.pointerId, startX: event.clientX, startY: event.clientY, started: false };
});
document.addEventListener('pointermove', (event) => {
  if (!modulePointerDrag || event.pointerId !== modulePointerDrag.pointerId) return;
  if (!modulePointerDrag.started && Math.hypot(event.clientX - modulePointerDrag.startX, event.clientY - modulePointerDrag.startY) < 6) return;
  if (!modulePointerDrag.started) beginModulePointerDrag(event);
  event.preventDefault();
  autoScrollModuleEditor(event.clientY);
  updateModuleDropSeam(event.clientY);
  positionModuleDragPreview(event.clientX, event.clientY);
}, { passive: false });
document.addEventListener('pointerup', (event) => {
  if (!modulePointerDrag || event.pointerId !== modulePointerDrag.pointerId) return;
  if (modulePointerDrag.started) {
    event.preventDefault();
    suppressModuleClick = true;
    setTimeout(() => { suppressModuleClick = false; }, 0);
  }
  finishModulePointerDrag(true);
});
document.addEventListener('pointercancel', (event) => {
  if (modulePointerDrag?.pointerId === event.pointerId) finishModulePointerDrag(false);
});
document.addEventListener('click', (event) => {
  if (!suppressModuleClick) return;
  suppressModuleClick = false;
  if (event.target.closest?.('.module-row')) {
    event.preventDefault();
    event.stopImmediatePropagation();
  }
}, true);
window.addEventListener('blur', () => {
  if (modulePointerDrag) finishModulePointerDrag(false);
});

document.addEventListener('paste', (event) => {
  if (!event.target.matches('.pin-cell-input')) return;
  const digits = event.clipboardData?.getData('text').replace(/\D/g, '').slice(0, 6) || '';
  if (!digits) return;
  event.preventDefault();
  const inputs = $$('.pin-cell-input', event.target.closest('.pin-control'));
  inputs.forEach((input, index) => { input.value = digits[index] || ''; });
  (inputs[Math.min(digits.length, inputs.length) - 1] || inputs[0])?.focus();
});

document.addEventListener('keydown', (event) => {
  if (event.target.matches('.pin-cell-input')) {
    const inputs = $$('.pin-cell-input', event.target.closest('.pin-control'));
    const index = inputs.indexOf(event.target);
    if (event.key === 'Backspace' && !event.target.value && index > 0) {
      event.preventDefault();
      inputs[index - 1].value = '';
      inputs[index - 1].focus();
      return;
    }
    if (event.key === 'ArrowLeft' && index > 0) { event.preventDefault(); inputs[index - 1].focus(); return; }
    if (event.key === 'ArrowRight' && index < inputs.length - 1) { event.preventDefault(); inputs[index + 1].focus(); return; }
  }
  const pageSearchAvailable = $('#connection-modal').classList.contains('hidden') && $('#owner-lock-layer').classList.contains('hidden');
  if (pageSearchAvailable && (event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'f' && !event.altKey) {
    event.preventDefault();
    const search = $(`[data-page-search="${activePage}"]`);
    search?.focus();
    search?.select();
    return;
  }
  if (event.key === 'Escape') {
    setActivityFilterMenu(false);
    const search = event.target.closest?.('[data-page-search]');
    if (search?.value) {
      const page = search.dataset.pageSearch;
      search.value = '';
      pageSearch[page] = '';
      if (page === 'connections') renderConnections();
      if (page === 'activity') { activityVisibleCount = ACTIVITY_PAGE_SIZE; renderActivity(); }
      if (page === 'settings') applySettingsSearch();
    }
  }
});

$('#connection-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('#save-connection-button');
  button.disabled = true;
  try {
    const input = serializeItem();
    await api.save(input);
    if (currentDraftId) await api.deleteDraft(currentDraftId);
    currentDraftId = '';
    closeEditor();
    toast(localized('项目已加密保存', 'Item saved and encrypted'));
    await refresh();
    await refreshDrafts();
  } catch (error) { toast(cleanError(error), 'error'); } finally { button.disabled = false; }
});
$('#owner-lock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const pin = readPin('owner-pin');
  if (!/^\d{6}$/.test(pin)) return toast(localized('PIN 必须是六位数字', 'PIN must contain six digits'), 'error');
  if (!ownerLockState.pinConfigured && pin !== readPin('owner-pin-confirm')) return toast(localized('两次 PIN 不一致', 'PIN entries do not match'), 'error');
  const button = $('#owner-unlock-action');
  const cancelButton = $('#owner-pin-cancel');
  button.disabled = true;
  cancelButton.disabled = true;
  try {
    const settingPin = !ownerLockState.pinConfigured;
    ownerLockState = ownerLockState.pinConfigured ? await api.ownerUnlock(pin) : await api.ownerSetPin(pin);
    ownerPinSetupRequested = false;
    renderOwnerLock();
    if (state) {
      renderMetrics();
      renderSettings();
    }
    if (settingPin) toast(localized('PIN 锁已开启', 'PIN lock enabled'));
    await refreshDrafts(true);
  } catch (error) {
    toast(cleanError(error), 'error');
    clearPin('owner-pin');
    focusPin('owner-pin');
  } finally {
    button.disabled = false;
    cancelButton.disabled = false;
  }
});
$('#owner-pin-cancel').addEventListener('click', () => {
  ownerPinSetupRequested = false;
  renderOwnerLock();
  renderSettings();
});
$('#clear-activity-button').addEventListener('click', async () => { if (!confirm(localized('清空本地操作记录？', 'Clear the local activity log?'))) return; await api.clear(); currentActivityFilter = 'all'; pageSearch.activity = ''; expandedActivityErrors.clear(); $('[data-page-search="activity"]').value = ''; await refresh(); });
$('#save-browser-settings-button').addEventListener('click', saveBrowserSettings);
$('#browser-enabled').addEventListener('change', saveBrowserSettings);
if (!isMacOS) $('#desktop-shortcut-enabled').addEventListener('change', (event) => setSystemIntegration('desktop', event.currentTarget.checked));
$('#launch-at-login-enabled').addEventListener('change', (event) => setSystemIntegration('startup', event.currentTarget.checked));
$('#pin-enabled').addEventListener('change', savePinSettings);
$('#close-behavior').addEventListener('change', saveDesktopSettings);
$('#quick-pairing-button').addEventListener('click', async () => { try { const message = await api.quickPair(Number($('#browser-port').value)); $('#browser-enabled').checked = true; toast(publicMessage(message, localized('浏览器配对已准备', 'Browser pairing is ready'))); await refresh(); } catch (error) { toast(cleanError(error), 'error'); } });
$('#reset-pairing-button').addEventListener('click', async () => { if (!confirm(localized('重置后所有已配对扩展会立即失效。继续？', 'Resetting immediately revokes every paired extension. Continue?'))) return; try { await api.resetPair(); toast(localized('配对已重置', 'Pairing reset')); await refresh(); } catch (error) { toast(cleanError(error), 'error'); } });
$('#open-extension-button').addEventListener('click', () => api.extensionFolder().catch((error) => toast(cleanError(error), 'error')));
$('#open-data-button').addEventListener('click', () => api.dataFolder().catch((error) => toast(cleanError(error), 'error')));
$('#rescan-agents').addEventListener('click', () => scanAgents(true));
$('#header-export-backup-button').addEventListener('click', (event) => exportBackup(event.currentTarget));
$('#header-import-backup-button').addEventListener('click', (event) => importBackup(event.currentTarget));

$('#page-activity .activity-panel').addEventListener('scroll', (event) => {
  const panel = event.currentTarget;
  if (panel.scrollHeight - panel.scrollTop - panel.clientHeight < 160) queueMoreActivities();
}, { passive: true });

window.__TAURI__.event.listen('state-changed', async () => { await refresh(false); await refreshDrafts(); });
window.__TAURI__.event.listen('pin-setup-requested', async () => {
  await refreshOwnerLock(false);
  if (ownerLockState.pinConfigured) return;
  ownerPinSetupRequested = true;
  renderOwnerLock();
  if (state) renderSettings();
});
window.addEventListener('focus', async () => { await refresh(false); await refreshOwnerLock(false); await refreshDrafts(); });
window.addEventListener('resize', positionModuleMenu);
$('.form-scroll', $('#connection-modal')).addEventListener('scroll', positionModuleMenu, { passive: true });
setInterval(() => { if ($('#page-activity').classList.contains('active')) refresh(false); }, 2000);

async function bootstrap() {
  applyLanguage();
  initFixedScrollThumbs();
  await refreshOwnerLock();
  await refresh();
  await refreshDrafts();
  scanAgents();
  queueScrollThumbSync();
}
bootstrap();

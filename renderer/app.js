const { invoke } = window.__TAURI__.core;
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const HAN_TEXT = /[\u3400-\u9fff]/;

let language = localStorage.getItem('kru-language') === 'en' ? 'en' : 'zh';

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
  ['[data-module="MCP / 01"] .settings-heading h2', 'text', 'Agent 接入', 'AGENT SETUP'],
  ['[data-module="MCP / 01"] .settings-heading p', 'text', '将 KRU 注册为本地 stdio MCP。', 'Register KRU as a local stdio MCP.'],
  ['[data-module="REVIEW / 02"] .settings-heading h2', 'text', '审核模式', 'APPROVAL MODE'],
  ['[data-module="REVIEW / 02"] .settings-heading p', 'text', 'Agent 每次使用秘密前，都要由你在 KRU 中明确允许。', 'Require your explicit approval before every agent use of a secret.'],
  ['.approval-mode-note span', 'text', '请求只显示调用方、项目和动作；超时或拒绝时不会使用秘密。', 'Requests show only the caller, item, and action. Timeout or denial prevents secret use.'],
  ['[data-module="APP / 03"] .settings-heading h2', 'text', '窗口与提醒', 'WINDOW & ALERTS'],
  ['[data-module="APP / 03"] .settings-heading p', 'text', '控制关闭按钮行为，以及审核请求的系统级提醒。', 'Control close-button behavior and system-level approval alerts.'],
  ['label[for="close-behavior"] strong', 'text', '关闭按钮', 'CLOSE BUTTON'],
  ['label[for="close-behavior"] small', 'text', '最小化可保持托盘菜单与审核提醒', 'Minimizing keeps tray controls and approval alerts available.'],
  ['#close-behavior option[value="tray"]', 'text', '最小化到托盘', 'MINIMIZE TO TRAY'],
  ['#close-behavior option[value="exit"]', 'text', '退出 KRU', 'QUIT KRU'],
  ['.desktop-option:nth-child(2) strong', 'text', '审核系统弹窗', 'SYSTEM APPROVAL POPUP'],
  ['.desktop-option:nth-child(2) small', 'text', '开启后同时保留 KRU 内审核窗口', 'KRU’s in-app approval window always remains available.'],
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
  ['[data-module="SAFE / 05"] .settings-heading p', 'text', '用独立密码导出可跨平台迁移的加密包。', 'Export an encrypted cross-platform package with a separate password.'],
  ['#open-data-button', 'text', '打开数据目录', 'OPEN DATA FOLDER'],
  ['#owner-lock-description', 'text', 'PIN 保护明文查看和调用审核；模块值默认隐藏，仅在你开启后对 Agent 可见。', 'The PIN protects plaintext viewing and call approval. Module values stay hidden unless you make them visible to agents.'],
  ['#owner-pin', 'label', '六位数字 PIN', 'SIX-DIGIT PIN'],
  ['#owner-pin-confirm', 'label', '再次输入 PIN', 'CONFIRM PIN'],
  ['.lock-note span', 'text', '秘密仍由本机随机主密钥加密；PIN 只是本地查看锁。', 'Secrets remain encrypted by the local random master key. The PIN only locks plaintext viewing.'],
  ['[data-close-modal].icon-button', 'aria-label', '关闭编辑器', 'Close editor'],
  ['#connection-name', 'label', '名称', 'NAME'],
  ['#connection-description', 'label-html', '备注 / 用途 <em>可选</em>', 'NOTES / PURPOSE <em>OPTIONAL</em>'],
  ['.template-copy strong', 'text', '从一个组合开始', 'START WITH A PRESET'],
  ['.template-copy small', 'text', '模板只添加模块，不会限制之后的修改。', 'Templates only add modules; you can change anything afterward.'],
  ['.module-editor-heading > div > strong', 'text', '项目模块', 'ITEM MODULES'],
  ['.module-editor-heading > div > small', 'text', '左侧开关控制明文是否对 Agent 可见', 'LEFT SWITCH: AGENT PLAINTEXT VISIBILITY'],
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
  ['#ssh-security-mode', 'label', '命令权限', 'COMMAND ACCESS'],
  ['#ssh-security-mode option[value="readonly"]', 'text', '观察（推荐）', 'OBSERVE (RECOMMENDED)'],
  ['#ssh-security-mode option[value="diagnostic"]', 'text', '诊断', 'DIAGNOSTIC'],
  ['#ssh-security-mode option[value="restricted"]', 'text', '受限命令', 'RESTRICTED'],
  ['#ssh-security-mode option[value="unrestricted"]', 'text', '完全控制', 'FULL CONTROL'],
  ['#ssh-fingerprint', 'label-html', '服务器身份指纹 <em>与密码/私钥无关</em>', 'SERVER FINGERPRINT <em>INDEPENDENT OF LOGIN METHOD</em>'],
  ['#ssh-fingerprint', 'placeholder', '首次连接自动记录', 'RECORDED ON FIRST CONNECTION'],
  ['#ssh-allowed-commands', 'label-html', '允许的命令前缀 <em>每行一个</em>', 'ALLOWED COMMAND PREFIXES <em>ONE PER LINE</em>'],
  ['#ssh-options summary', 'text', 'SSH 高级设置', 'SSH ADVANCED SETTINGS'],
  ['.check-row strong', 'text', '启用此项目', 'ENABLE ITEM'],
  ['.check-row small', 'text', '禁用后 Agent 无法使用', 'Agents cannot use a disabled item.'],
  ['.secret-hint', 'text', '当前项目的明文只在已解锁 GUI 中显示', 'Plaintext is visible only in the unlocked GUI.'],
  ['#connection-form .modal-footer [data-close-modal]', 'text', '取消', 'CANCEL'],
  ['#save-connection-button', 'text', '保存', 'SAVE'],
  ['#backup-password', 'label', '备份密码', 'BACKUP PASSWORD'],
  ['#backup-password-confirm', 'label', '再次输入', 'CONFIRM PASSWORD'],
  ['#backup-cancel', 'text', '取消', 'CANCEL'],
  ['#backup-action', 'text', '继续', 'CONTINUE'],
  ['#approval-title', 'text', '允许本次调用？', 'ALLOW THIS CALL?'],
  ['.approval-details > div:nth-child(1) dt', 'text', '调用方', 'CALLER'],
  ['.approval-details > div:nth-child(2) dt', 'text', '项目', 'ITEM'],
  ['.approval-details > div:nth-child(3) dt', 'text', '动作', 'ACTION'],
  ['.approval-details > div:nth-child(4) dt', 'text', '目标', 'TARGET'],
  ['#approval-deny', 'text', '拒绝', 'DENY'],
  ['#approval-allow', 'text', '允许一次', 'ALLOW ONCE'],
];

function applyLanguage() {
  document.documentElement.lang = language === 'en' ? 'en' : 'zh-CN';
  localStorage.setItem('kru-language', language);
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
}

function publicMessage(value, fallback = localized('操作失败', 'Operation failed')) {
  const raw = String(value || '').replace(/^Error:\s*/, '');
  if (language !== 'en' || !HAN_TEXT.test(raw)) return raw || fallback;
  return fallback;
}

const api = {
  state: () => invoke('get_state'),
  ownerStatus: () => invoke('owner_status'),
  ownerSetPin: (pin) => invoke('owner_set_pin', { pin }),
  ownerUnlock: (pin) => invoke('owner_unlock', { pin }),
  ownerTouch: () => invoke('owner_touch'),
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
  resetTrust: (id) => invoke('reset_ssh_fingerprint', { id }),
  settings: (settings) => invoke('update_settings', { settings }),
  approvals: () => invoke('approval_requests'),
  resolveApproval: (id, approved) => invoke('resolve_approval', { id, approved }),
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
  exportBackup: (password) => invoke('export_backup', { password }),
  importBackup: (password) => invoke('import_backup', { password }),
  dataFolder: () => invoke('open_data_folder'),
  window: (action) => invoke('window_action', { action }),
};

let state;
let activePage = 'connections';
let currentActivityFilter = 'all';
const pageSearch = { connections: '', activity: '', settings: '' };
let currentModules = [];
let editorDrafts = [];
let currentDraftId = '';
let removedSecretFields = new Set();
let editorExistingItem = null;
let agentClients = [];
let agentRestartRequired = false;
let pendingApprovals = [];
let approvalRefreshBusy = false;
let lastApprovalNotifiedId = '';
let backupMode = 'export';
const ACTIVITY_PAGE_SIZE = 50;
let activityVisibleCount = ACTIVITY_PAGE_SIZE;
let activityMatchCount = 0;
let activityLoadPending = false;
const expandedActivityErrors = new Set();
let ownerLockState = { pinConfigured: false, unlocked: false, expiresInSeconds: 0 };
let lastOwnerActivity = Date.now();
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
  $('#owner-lock-layer').classList.toggle('hidden', unlocked);
  $('#owner-lock-button').classList.toggle('hidden', !unlocked);
  $('#owner-pin-confirm-field').classList.toggle('hidden', configured);
  pinInputs('owner-pin-confirm').forEach((input) => { input.required = !configured; });
  $('#owner-lock-mode').textContent = configured ? 'OWNER VERIFY' : 'SET LOCAL PIN';
  $('#owner-lock-title').textContent = configured
    ? localized('输入六位 PIN', 'ENTER SIX-DIGIT PIN')
    : localized('设置六位 PIN', 'SET SIX-DIGIT PIN');
  $('#owner-lock-code').textContent = configured ? 'LOCK' : 'INIT';
  $('#owner-unlock-action').textContent = configured ? 'UNLOCK' : 'SET PIN';
  if (!unlocked) {
    clearOwnerPlaintext();
    editorDrafts = [];
    renderDrafts();
  }
  clearPin('owner-pin');
  clearPin('owner-pin-confirm');
  if (!unlocked) setTimeout(() => focusPin('owner-pin'), 0);
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
    fill: enabled,
    ssh: state.connections.filter((item) => item.enabled && itemCapabilities(item).includes('ssh')).length,
    api: state.connections.filter((item) => item.enabled && itemCapabilities(item).includes('http')).length,
  };
  const latest = state.activities[0];
  const browserOn = ['listening', 'delegated'].includes(state.browserBridge.status);
  const browserReady = browserOn && state.browserBridge.paired;
  const approvalOn = Boolean(state.settings.approvalMode);
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
  const systemFault = state.mcp.status === 'error' || state.browserBridge.status === 'error';
  const systemNeedsSetup = !mcpReady || !ownerLockState.pinConfigured || (browserOn && !browserReady);
  const systemCode = systemFault ? 'ERR' : systemNeedsSetup ? 'SET' : 'RDY';
  const browserCode = state.browserBridge.status === 'error' ? 'ERR' : !browserOn ? 'OFF' : browserReady ? 'RDY' : 'PAIR';
  const models = {
    connections: {
      channels: [['A', 'FILL', moduleCounts.fill ? 'on' : ''], ['B', 'SSH', moduleCounts.ssh ? 'on' : ''], ['C', 'HTTP', moduleCounts.api ? 'on' : ''], ['D', 'OFF', disabled ? 'warn' : '']],
      minor: 'PAGE A', mode: 'VAULT', valueKind: 'number', value: total, unit: 'ITEM',
      ready: !total ? 'EMPTY' : enabled ? 'READY' : 'DISABLED', tag: disabled ? compactCount(disabled, 'OFF') : total ? 'ALL ON' : 'LOCAL', readyTone: disabled ? 'warn' : '',
      telemetryStatus: lastStatus, telemetryLabel: 'LAST USE', telemetryCode: lastCode, action: lastAction,
      meter: recentCalls.map((activity) => `lit ${activity.status === 'error' ? 'fault' : ''} ${/BROWSER|浏览器|\bWEB\b/i.test(String(activity.action)) ? 'web' : ''}`),
      legend: `<span class="${mcpReady ? 'lit' : ''}">MCP</span><span class="${browserReady ? 'lit web' : ''}">WEB</span><span class="${ownerLockState.pinConfigured ? 'lit' : ''}">PIN</span>`,
    },
    activity: {
      channels: [['A', 'FILL', actionTypes24h.has('FILL') || actionTypes24h.has('WEB') ? 'on' : ''], ['B', 'SSH', actionTypes24h.has('SSH') ? 'on' : ''], ['C', 'HTTP', actionTypes24h.has('API') ? 'on' : ''], ['D', 'TERM', actionTypes24h.has('TERM') ? 'on' : '']],
      minor: 'PAGE B', mode: 'AUDIT', valueKind: 'number', value: activities24h.length, unit: '24H',
      ready: !activities24h.length ? 'IDLE' : errors24h ? 'ATTENTION' : 'CLEAN', tag: errors24h ? compactCount(errors24h, 'ERR') : 'NO ERR', readyTone: errors24h ? 'fault' : '',
      telemetryStatus: lastStatus, telemetryLabel: 'LATEST', telemetryCode: lastCode, action: lastAction,
      meter: recentCalls.map((activity) => `lit ${activity.status === 'error' ? 'fault' : ''}`),
      legend: `<span class="${passes24h ? 'lit' : ''}">PASS</span><span class="${errors24h ? 'fault' : ''}">ERR</span><span class="lit">24H</span>`,
    },
    settings: {
      channels: [['A', 'MCP', mcpReady ? 'on' : 'error'], ['B', 'CRYPT', state.security.encrypted ? 'on' : 'error'], ['C', 'WEB', browserOn ? 'on web' : ''], ['D', 'REVIEW', approvalOn ? 'on' : '']],
      minor: 'PAGE C', mode: 'SYSTEM', valueKind: 'word', value: systemCode, unit: 'STATE',
      ready: systemFault ? 'SERVICE FAULT' : systemNeedsSetup ? 'ACTION NEEDED' : 'LOCAL READY', tag: state.security.encrypted ? 'SEALED' : 'CHECK', readyTone: systemFault ? 'fault' : systemNeedsSetup ? 'warn' : '',
      telemetryStatus: state.browserBridge.status === 'error' ? 'error' : browserOn ? 'ok' : 'idle', telemetryLabel: 'BROWSER', telemetryCode: browserCode, action: state.browserBridge.status === 'error' ? 'CHECK LOG' : !browserOn ? 'OPTIONAL' : browserReady ? 'PAIRED' : 'PAIR EXT',
      meter: [mcpReady ? 'lit' : '', state.security.encrypted ? 'lit' : 'fault', ownerLockState.pinConfigured ? 'lit' : 'fault', approvalOn ? 'lit' : '', browserOn ? 'lit web' : '', browserReady ? 'lit web' : ''],
      legend: `<span class="${mcpReady ? 'lit' : ''}">MCP</span><span class="${approvalOn ? 'lit' : ''}">REVIEW</span><span class="${ownerLockState.pinConfigured ? 'lit' : 'fault'}">PIN</span>`,
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
    <div class="display-telemetry ${model.telemetryStatus}">
      <div class="last-result"><span>${model.telemetryLabel}</span><strong>${model.telemetryCode}</strong></div>
      <div class="last-action">${escapeHtml(model.action)}</div>
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
  if (capabilities.includes('ssh')) return language === 'en'
    ? ({ readonly: 'OBSERVE', diagnostic: 'DIAGNOSTIC', restricted: 'RESTRICTED', unrestricted: 'FULL CONTROL' })[item.securityMode] || 'OBSERVE'
    : ({ readonly: '观察', diagnostic: '诊断', restricted: '受限', unrestricted: '完全控制' })[item.securityMode] || '观察';
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
    const checkLabel = authModule === 'FILL' ? 'VERIFY' : 'CHECK';
    const capabilities = itemCapabilities(item);
    const canTest = item.enabled && (capabilities.includes('ssh') || (capabilities.includes('http') && item.baseUrl) || (capabilities.includes('fill') && !capabilities.includes('http')));
    return `<article class="connection-card ${itemCapabilities(item).includes('ssh') ? 'ssh' : itemCapabilities(item).includes('http') ? 'http' : 'fill'} ${item.enabled ? '' : 'disabled'}">
      <div class="module-strip"><span>ITEM / ${String(stableIndex).padStart(2, '0')}</span><button class="module-state" type="button" data-action="toggle-enabled" data-id="${item.id}" aria-pressed="${item.enabled}" title="${item.enabled ? localized('点击停用；Agent 将无法使用其中的秘密', 'Disable this item; agents will no longer be able to use its secrets') : localized('点击启用；Agent 将可以使用其中的秘密', 'Enable this item so agents can use its secrets')}"><i class="status-dot ${item.enabled ? '' : 'off'}"></i>${item.enabled ? 'READY' : 'OFF'}</button></div>
      <div class="connection-top"><div class="connection-main"><div class="connection-name-row"><span class="connection-name"><span>${escapeHtml(item.name)}</span></span></div><div class="connection-address">${escapeHtml(itemDetail(item))}</div></div><div class="connection-symbol">${escapeHtml(authModule)}</div></div>
      ${item.description ? `<div class="connection-description">${escapeHtml(item.description)}</div>` : ''}
      <div class="card-actions"><button class="small-button" data-action="test" data-id="${item.id}" ${canTest ? '' : 'disabled'}>${checkLabel}</button><button class="small-button" data-action="edit" data-id="${item.id}">EDIT</button><button class="small-button delete" data-action="delete" data-id="${item.id}">DEL</button></div>
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
  button.title = hasDraft ? localized('继续编辑唯一草稿', 'Continue the saved draft') : localized('暂无草稿', 'No draft');
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
  const approvalOn = Boolean(state.settings.approvalMode);
  $('#approval-enabled').checked = approvalOn;
  $('#close-behavior').value = state.settings.closeBehavior === 'exit' ? 'exit' : 'tray';
  $('#system-approval-popup').checked = Boolean(state.settings.systemApprovalPopup);
  const approvalStrip = $('#approval-status-strip');
  approvalStrip.className = `status-strip ${approvalOn ? '' : 'offline'}`;
  approvalStrip.innerHTML = `<span class="status-dot"></span><span class="status-key">${approvalOn ? 'ARMED' : 'OFF'}</span><span>${approvalOn ? localized('每次秘密调用等待本机确认。', 'Every secret call waits for local approval.') : localized('按项目已保存权限直接执行。', 'Calls run under each item’s saved permissions.')}</span>`;
  $('#browser-enabled').checked = state.settings.browserEnabled;
  $('#browser-port').value = state.settings.browserPort;
  const bridge = state.browserBridge;
  const online = ['listening', 'delegated'].includes(bridge.status);
  const strip = $('#browser-status-strip');
  strip.className = `status-strip ${bridge.status === 'error' ? 'error' : online ? '' : 'offline'}`;
  strip.innerHTML = `<span class="status-dot"></span><span class="status-key">${bridge.status === 'error' ? 'FAULT' : online ? (bridge.paired ? 'PAIRED' : 'READY') : 'OFF'}</span><span>${bridge.status === 'error' ? escapeHtml(publicMessage(bridge.error)) : online ? escapeHtml(bridge.endpoint) : localized('Browser Bridge 已关闭', 'Browser Bridge is off')}</span>`;
  $('#reset-pairing-button').disabled = !bridge.paired;
  renderAgents();
  applySettingsSearch();
  renderApprovalRequest();
}

function renderApprovalRequest() {
  const request = state?.settings?.approvalMode ? pendingApprovals[0] : null;
  const strip = $('#approval-status-strip');
  if (strip && state?.settings?.approvalMode) {
    strip.className = `status-strip ${request ? 'waiting' : ''}`;
    strip.innerHTML = `<span class="status-dot"></span><span class="status-key">${request ? 'WAIT' : 'ARMED'}</span><span>${request ? localized(`${pendingApprovals.length} 条调用等待审核。`, `${pendingApprovals.length} call(s) waiting for approval.`) : localized('每次秘密调用等待本机确认。', 'Every secret call waits for local approval.')}</span>`;
  }
  $('#approval-modal').classList.toggle('hidden', !request);
  document.title = request ? 'KRU · APPROVAL' : 'KRU';
  if (!request) return;
  $('#approval-summary').textContent = localized(
    `${request.source} 正在请求 KRU 使用一个已保存秘密。`,
    `${request.source} is asking KRU to use a saved secret.`,
  );
  $('#approval-source').textContent = request.source;
  $('#approval-item').textContent = request.itemName;
  $('#approval-action').textContent = request.action;
  $('#approval-detail').textContent = request.detail || '—';
  $('#approval-queue').textContent = pendingApprovals.length > 1
    ? localized(`另有 ${pendingApprovals.length - 1} 条等待审核`, `${pendingApprovals.length - 1} MORE WAITING`)
    : localized('只允许当前这一次调用', 'THIS CALL ONLY');
}

async function refreshApprovals() {
  if (approvalRefreshBusy || !state?.settings?.approvalMode || !ownerLockState.unlocked) {
    if (!state?.settings?.approvalMode || !ownerLockState.unlocked) {
      pendingApprovals = [];
      renderApprovalRequest();
    }
    return;
  }
  approvalRefreshBusy = true;
  try {
    pendingApprovals = await api.approvals();
    if (pendingApprovals[0] && pendingApprovals[0].id !== lastApprovalNotifiedId) {
      lastApprovalNotifiedId = pendingApprovals[0].id;
      api.window('attention').catch(() => {});
    }
    renderApprovalRequest();
  } catch (_) {
    pendingApprovals = [];
    renderApprovalRequest();
  } finally {
    approvalRefreshBusy = false;
  }
}

const agentLabels = { notDetected: 'NOT FOUND', available: 'READY', registered: 'CONNECTED', stale: 'PATH CHANGED', conflict: 'CONFLICT', error: 'ERROR' };
function agentDetail(client) {
  const details = language === 'en'
    ? { notDetected: 'Not installed', available: 'Ready to connect', registered: 'Connected', stale: 'KRU path changed', conflict: 'Config conflict', error: 'Detection failed' }
    : { notDetected: '未安装或未发现', available: '可连接', registered: '已连接', stale: 'KRU 路径已变更', conflict: '配置冲突', error: '检测失败' };
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
  currentModules = rows.map((row) => ({
    kind: row.dataset.kind,
    name: $('[data-module-name]', row)?.value ?? row.dataset.name ?? '',
    value: $('[data-module-value]', row)?.value ?? '',
    secretValue: $('[data-secret-value]', row)?.value ?? '',
    configured: row.dataset.configured === 'true',
    existing: row.dataset.existing === 'true',
    privateKeyName: row.dataset.privateKeyName || '',
    pending: row.dataset.pending === 'true',
    agentVisible: $('[data-module-agent-visible]', row)?.getAttribute('aria-pressed') === 'true',
  }));
}

function editorModule(kind) {
  return currentModules.find((module) => module.kind === kind);
}

function moduleConfigured(module) {
  return Boolean(module && (String(module.secretValue || '').length || module.configured || module.pending));
}

function deriveEditorActions() {
  const actions = [];
  if (currentModules.some((module) => MODULE_DEFS[module.kind]?.secret && moduleConfigured(module))) actions.push('FILL');
  const host = editorModule('host');
  const port = editorModule('port');
  if (String(host?.value || '').trim() && Number(port?.value) > 0 && moduleConfigured(editorModule('username')) && (moduleConfigured(editorModule('password')) || moduleConfigured(editorModule('privateKey')))) actions.push('SSH');
  if (moduleConfigured(editorModule('apiCredential'))) actions.push('HTTP');
  return actions;
}

function updateModuleStatus() {
  syncModuleDraft();
  const actions = deriveEditorActions();
  $('#derived-actions').innerHTML = (actions.length ? actions : ['DRAFT']).map((action) => `<b class="${action === 'DRAFT' ? 'draft' : ''}">${action}</b>`).join('');
  $('#derived-help').textContent = actions.length
    ? localized('仅这些已完成组合会向 Agent 开放。', 'Only these complete combinations are exposed to agents.')
    : localized('可以保存草稿；尚不会向 Agent 暴露。', 'This draft can be saved and is not exposed to agents yet.');
  $('#ssh-options').classList.toggle('hidden', !currentModules.some((module) => ['host', 'port', 'privateKey'].includes(module.kind)));
  $('#allowed-commands-field').classList.toggle('hidden', $('#ssh-security-mode').value !== 'restricted');
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
    const agentVisible = typeof module.agentVisible === 'boolean' ? module.agentVisible : !definition.secret;
    const agentVisibilityLabel = agentVisible
      ? localized('Agent 可查看此值', 'Agent can see this value')
      : localized('不向 Agent 显示此值', 'Hidden from agent');
    const secretName = moduleSecretName(module);
    const customName = module.kind === 'customSecret'
      ? `<input class="input module-name-input" data-module-name value="${escapeHtml(module.name || '')}" placeholder="field_name" />`
      : `<strong>${escapeHtml(moduleLabel(module.kind))}</strong>${secretName ? `<small>${escapeHtml(secretName)}</small>` : ''}`;
    let control = '';
    let actions = '';
    if (module.kind === 'privateKey') {
      const keyState = module.pending ? module.privateKeyName : module.configured ? (module.privateKeyName || 'IMPORTED KEY') : localized('尚未导入', 'NOT IMPORTED');
      control = `<div class="module-key-control"><span>${escapeHtml(keyState)}</span><button type="button" class="copy-secret-button" data-choose-module-key>SELECT</button></div>${module.secretValue ? `<div class="secret-input-control module-secret-control multiline module-key-secret"><textarea class="input textarea secret-masked" data-secret-value readonly>${escapeHtml(module.secretValue)}</textarea></div>` : '<input type="hidden" data-secret-value value="" />'}`;
      if (module.secretValue) actions = `${secretActionButton('reveal')}${secretActionButton('copy')}`;
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

function secretActionButton(kind, secret = true) {
  if (kind === 'reveal') {
    const label = localized('显示明文', 'Show secret');
    return `<button type="button" class="reveal-secret-button secret-icon-button module-action-icon" data-toggle-module-secret aria-pressed="false" aria-label="${label}" title="${label}"><svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 10s2.4-4.75 7-4.75S17 10 17 10s-2.4 4.75-7 4.75S3 10 3 10Z"/><circle cx="10" cy="10" r="2.5"/><path class="secret-icon-slash" d="M3.5 3.5l13 13"/></svg></button>`;
  }
  const label = secret ? localized('复制隐私值', 'Copy private value') : localized('复制值', 'Copy value');
  const attribute = secret ? 'data-copy-module-secret' : 'data-copy-module-value';
  return `<button type="button" class="copy-secret-button secret-icon-button module-action-icon" ${attribute} aria-label="${label}" title="${label}"><svg viewBox="0 0 20 20" aria-hidden="true"><rect x="7" y="7" width="10" height="10"/><path d="M14 7V3H3v11h4"/></svg></button>`;
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
    agentVisible: !MODULE_DEFS[kind]?.secret,
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
  currentModules = (presets[template] || []).map((kind) => ({ kind, name: kind, value: kind === 'port' ? '22' : '', secretValue: '', configured: false, existing: false, privateKeyName: '', pending: false, agentVisible: !MODULE_DEFS[kind]?.secret }));
  $('#template-picker').classList.add('hidden');
  renderModules();
}

function legacyModules(item, ownerValues) {
  const modules = [];
  const add = (kind, name = kind, value = '') => { if (!modules.some((module) => module.kind === kind)) modules.push({ kind, name, value, secretValue: ownerValues[name] || '', configured: Boolean(ownerValues[name]), existing: true, agentVisible: !MODULE_DEFS[kind]?.secret }); };
  if (item.host) { add('host', '', item.host); add('port', '', String(item.port || 22)); }
  for (const field of item.secret?.fields || []) {
    const kind = field.name === 'token' || field.name === 'apiKey' || field.name === 'api_key' ? 'apiCredential' : MODULE_DEFS[field.name] ? field.name : 'customSecret';
    add(kind, kind === 'customSecret' ? field.name : kind, '');
    const module = modules.at(-1);
    module.secretValue = ownerValues[field.name] || ownerValues[kind] || '';
    module.configured = Boolean(module.secretValue);
  }
  if (item.baseUrl) add('url', '', item.baseUrl);
  return modules;
}

function updateAuthFields() {
  updateModuleStatus();
}

function value(selector, next) {
  const element = $(selector);
  if (arguments.length > 1) element.value = next ?? '';
  return element.value;
}

async function openEditor(item = null, draft = null) {
  let ownerValues = {};
  if (item) {
    try {
      const view = await api.ownerSecrets(item.id);
      ownerValues = Object.fromEntries(view.fields.map((field) => [field.name, field.value]));
    } catch (error) {
      toast(cleanError(error), 'error');
      await refreshOwnerLock(false);
      return;
    }
  } else if (draft) {
    ownerValues = draftSecretValues(draft.input?.secrets);
  }
  const source = item || draft?.input || null;
  removedSecretFields = new Set();
  editorExistingItem = item;
  currentDraftId = draft?.id || '';
  value('#connection-id', item?.id);
  value('#connection-name', source?.name);
  value('#connection-description', source?.description);
  $('#connection-enabled').checked = source?.enabled ?? true;
  $('#modal-title').textContent = item ? localized('编辑项目', 'EDIT ITEM') : draft ? localized('继续草稿', 'CONTINUE DRAFT') : localized('添加项目', 'ADD ITEM');
  $('#template-picker').classList.toggle('hidden', Boolean(item || draft?.input?.modules?.length));
  currentModules = item
    ? ((item.modules?.length ? item.modules : legacyModules(item, ownerValues)).map((module) => {
        const secretName = module.kind === 'customSecret' ? module.name : module.kind;
        return { ...module, secretValue: ownerValues[secretName] || '', configured: Boolean(module.configured || ownerValues[secretName]), existing: true, privateKeyName: module.kind === 'privateKey' ? item.privateKeyName || '' : '', pending: false, agentVisible: typeof module.agentVisible === 'boolean' ? module.agentVisible : !MODULE_DEFS[module.kind]?.secret };
      }))
    : draft
      ? (draft.input?.modules || []).map((module) => {
          const secretName = module.kind === 'customSecret' ? module.name : module.kind;
          return { ...module, secretValue: ownerValues[secretName] || '', configured: Boolean(ownerValues[secretName]), existing: false, privateKeyName: module.kind === 'privateKey' ? draft.input?.secrets?.privateKeyName || '' : '', pending: false, agentVisible: typeof module.agentVisible === 'boolean' ? module.agentVisible : !MODULE_DEFS[module.kind]?.secret };
        })
      : [];
  value('#ssh-security-mode', source?.securityMode || 'readonly'); value('#ssh-fingerprint', item?.hostFingerprint); value('#ssh-allowed-commands', (source?.allowedCommands || []).join('\n'));
  $('#reset-ssh-trust').classList.toggle('hidden', !(itemCapabilities(item || {}).includes('ssh') && item?.hostFingerprint));
  renderModules();
  $('#connection-modal').classList.remove('hidden');
  $('.form-scroll', $('#connection-modal')).scrollTop = 0;
}

function closeEditor() {
  $('#connection-modal').classList.add('hidden');
  setModuleMenu(false);
}

function collectModules(validate = true) {
  syncModuleDraft();
  const modules = [];
  const secrets = { namedSecrets: {} };
  const secretNames = new Set();
  for (const module of currentModules) {
    const name = moduleSecretName(module);
    if (module.kind === 'customSecret') {
      if (validate && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error(localized(`字段名无效：${name}`, `Invalid field name: ${name}`));
      if (validate && (MODULE_DEFS[name] || ['token', 'apiKey', 'api_key'].includes(name))) throw new Error(localized(`字段名与内置模块冲突：${name}`, `Field name conflicts with a built-in module: ${name}`));
    }
    if (validate && name && secretNames.has(name)) throw new Error(localized(`字段名重复：${name}`, `Duplicate field name: ${name}`));
    if (name) secretNames.add(name);
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
  syncModuleDraft();
  if (validate && !currentModules.length) throw new Error(localized('请至少添加一个模块', 'Add at least one module'));
  const collected = collectModules(validate);
  return {
    id: value('#connection-id') || null,
    modules: collected.modules,
    name,
    description: value('#connection-description'),
    enabled: $('#connection-enabled').checked,
    authType: 'auto',
    sshAuthType: '',
    httpAuthType: 'auto',
    privateKeyImportPath: collected.privateKeyImportPath,
    securityMode: value('#ssh-security-mode'),
    allowedCommands: value('#ssh-allowed-commands').split('\n').map((line) => line.trim()).filter(Boolean),
    removeSecretNames: [...removedSecretFields],
    secrets: collected.secrets,
  };
}

function editorHasDraftContent() {
  syncModuleDraft();
  return Boolean(value('#connection-name').trim() || value('#connection-description').trim() || currentModules.length);
}

async function closeEditorWithDraft() {
  if (editorExistingItem) {
    closeEditor();
    return;
  }
  try {
    if (!editorHasDraftContent()) {
      if (currentDraftId) await api.deleteDraft(currentDraftId);
    } else {
      const saved = await api.saveDraft(currentDraftId || null, serializeItem(false));
      currentDraftId = saved.id;
      toast(localized('草稿已加密保存', 'Draft saved and encrypted'));
    }
    await refreshDrafts();
    closeEditor();
  } catch (error) {
    toast(cleanError(error), 'error');
  }
}

async function saveBrowserSettings() {
  try {
    await api.settings({ ...state.settings, language, browserEnabled: $('#browser-enabled').checked, browserPort: Number($('#browser-port').value) });
    toast(localized('Browser Bridge 设置已保存', 'Browser Bridge settings saved'));
    await refresh();
  } catch (error) {
    toast(cleanError(error), 'error');
    await refresh(false);
  }
}

async function saveApprovalSettings() {
  const enabled = $('#approval-enabled').checked;
  try {
    state.settings = await api.settings({ ...state.settings, language, approvalMode: enabled });
    if (!enabled) pendingApprovals = [];
    renderMetrics();
    renderSettings();
    toast(enabled
      ? localized('审核模式已开启', 'Approval mode enabled')
      : localized('审核模式已关闭', 'Approval mode disabled'));
    await refreshApprovals();
  } catch (error) {
    toast(cleanError(error), 'error');
    await refresh(false);
  }
}

async function saveDesktopSettings() {
  try {
    state.settings = await api.settings({
      ...state.settings,
      language,
      closeBehavior: $('#close-behavior').value,
      systemApprovalPopup: $('#system-approval-popup').checked,
    });
    renderSettings();
    toast(localized('窗口与提醒设置已保存', 'Window and alert settings saved'));
  } catch (error) {
    toast(cleanError(error), 'error');
    await refresh(false);
  }
}

async function resolveCurrentApproval(approved) {
  const request = pendingApprovals[0];
  if (!request) return;
  const buttons = [$('#approval-deny'), $('#approval-allow')];
  buttons.forEach((button) => { button.disabled = true; });
  try {
    await api.resolveApproval(request.id, approved);
    api.window('attention-clear').catch(() => {});
    pendingApprovals = pendingApprovals.filter((candidate) => candidate.id !== request.id);
    renderApprovalRequest();
    const desktopFill = approved && request.detail.toLowerCase().startsWith('desktop');
    toast(approved
      ? desktopFill
        ? localized('已允许 · 请在 5 秒内切回目标输入框', 'Approved · Return to the target field within 5 seconds')
        : localized('已允许本次调用', 'Call approved')
      : localized('已拒绝本次调用', 'Call denied'));
    await refreshApprovals();
  } catch (error) {
    toast(cleanError(error), 'error');
    await refreshApprovals();
  } finally {
    buttons.forEach((button) => { button.disabled = false; });
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
    if (!$('#connection-modal').classList.contains('hidden')) {
      $('#modal-title').textContent = value('#connection-id') ? localized('编辑项目', 'EDIT ITEM') : currentDraftId ? localized('继续草稿', 'CONTINUE DRAFT') : localized('添加项目', 'ADD ITEM');
    }
    if (!$('#backup-modal').classList.contains('hidden')) {
      $('#backup-title').textContent = backupMode === 'export' ? localized('导出便携备份', 'EXPORT PORTABLE BACKUP') : localized('导入便携备份', 'IMPORT PORTABLE BACKUP');
      $('#backup-description').textContent = backupMode === 'export'
        ? localized('使用独立密码加密，可在 Windows、macOS 与 Linux 间迁移。', 'Encrypted with a separate password for transfer across Windows, macOS, and Linux.')
        : localized('同 UUID 覆盖，不同 UUID 追加。', 'Matching UUIDs are replaced; new UUIDs are appended.');
    }
    try {
      state.settings = await api.settings({ ...state.settings, language });
    } catch (error) {
      toast(cleanError(error), 'error');
    }
  }
}

function openBackup(mode) {
  backupMode = mode;
  $('#backup-title').textContent = mode === 'export' ? localized('导出便携备份', 'EXPORT PORTABLE BACKUP') : localized('导入便携备份', 'IMPORT PORTABLE BACKUP');
  $('#backup-description').textContent = mode === 'export'
    ? localized('使用独立密码加密，可在 Windows、macOS 与 Linux 间迁移。', 'Encrypted with a separate password for transfer across Windows, macOS, and Linux.')
    : localized('同 UUID 覆盖，不同 UUID 追加。', 'Matching UUIDs are replaced; new UUIDs are appended.');
  $('#backup-confirm-field').classList.toggle('hidden', mode !== 'export');
  value('#backup-password', ''); value('#backup-password-confirm', '');
  $('#backup-modal').classList.remove('hidden');
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
      editorDrafts = [];
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
  const pageSearchAvailable = $('#connection-modal').classList.contains('hidden') && $('#backup-modal').classList.contains('hidden') && $('#approval-modal').classList.contains('hidden') && $('#owner-lock-layer').classList.contains('hidden');
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
    const existing = state.connections.find((item) => item.id === input.id);
    const nextHost = input.modules.find((module) => module.kind === 'host')?.value || '';
    const nextPort = Number(input.modules.find((module) => module.kind === 'port')?.value || 0);
    const trustReset = Boolean(existing && itemCapabilities(existing).includes('ssh') && (existing.host.toLocaleLowerCase() !== nextHost.toLocaleLowerCase() || existing.port !== nextPort));
    await api.save(input);
    if (currentDraftId) await api.deleteDraft(currentDraftId);
    currentDraftId = '';
    closeEditor();
    toast(trustReset
      ? localized('地址已变化 · 旧主机信任已清除，下次连接将重新固定', 'Address changed · Old host trust cleared; the next connection will pin the new host')
      : localized('项目已加密保存', 'Item saved and encrypted'));
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
  button.disabled = true;
  try {
    ownerLockState = ownerLockState.pinConfigured ? await api.ownerUnlock(pin) : await api.ownerSetPin(pin);
    lastOwnerActivity = Date.now();
    renderOwnerLock();
    await refreshDrafts(true);
    await refreshApprovals();
  } catch (error) {
    toast(cleanError(error), 'error');
    clearPin('owner-pin');
    focusPin('owner-pin');
  } finally { button.disabled = false; }
});
$('#ssh-security-mode').addEventListener('change', updateAuthFields);
$('#reset-ssh-trust').addEventListener('click', async () => { const id = value('#connection-id'); if (!id || !confirm(localized('重置后，下次连接将固定新的服务器指纹。继续？', 'After reset, the next connection will pin a new server fingerprint. Continue?'))) return; try { await api.resetTrust(id); value('#ssh-fingerprint', ''); $('#reset-ssh-trust').classList.add('hidden'); toast(localized('SSH 主机信任已重置', 'SSH host trust reset')); } catch (error) { toast(cleanError(error), 'error'); } });
$('#clear-activity-button').addEventListener('click', async () => { if (!confirm(localized('清空本地操作记录？', 'Clear the local activity log?'))) return; await api.clear(); currentActivityFilter = 'all'; pageSearch.activity = ''; expandedActivityErrors.clear(); $('[data-page-search="activity"]').value = ''; await refresh(); });
$('#save-browser-settings-button').addEventListener('click', saveBrowserSettings);
$('#browser-enabled').addEventListener('change', saveBrowserSettings);
$('#approval-enabled').addEventListener('change', saveApprovalSettings);
$('#close-behavior').addEventListener('change', saveDesktopSettings);
$('#system-approval-popup').addEventListener('change', saveDesktopSettings);
$('#approval-deny').addEventListener('click', () => resolveCurrentApproval(false));
$('#approval-allow').addEventListener('click', () => resolveCurrentApproval(true));
$('#quick-pairing-button').addEventListener('click', async () => { try { const message = await api.quickPair(Number($('#browser-port').value)); $('#browser-enabled').checked = true; toast(publicMessage(message, localized('浏览器配对已准备', 'Browser pairing is ready'))); await refresh(); } catch (error) { toast(cleanError(error), 'error'); } });
$('#reset-pairing-button').addEventListener('click', async () => { if (!confirm(localized('重置后所有已配对扩展会立即失效。继续？', 'Resetting immediately revokes every paired extension. Continue?'))) return; try { await api.resetPair(); toast(localized('配对已重置', 'Pairing reset')); await refresh(); } catch (error) { toast(cleanError(error), 'error'); } });
$('#open-extension-button').addEventListener('click', () => api.extensionFolder().catch((error) => toast(cleanError(error), 'error')));
$('#open-data-button').addEventListener('click', () => api.dataFolder().catch((error) => toast(cleanError(error), 'error')));
$('#rescan-agents').addEventListener('click', () => scanAgents(true));
$('#header-export-backup-button').addEventListener('click', () => openBackup('export'));
$('#header-import-backup-button').addEventListener('click', () => openBackup('import'));
$('#backup-cancel').addEventListener('click', () => $('#backup-modal').classList.add('hidden'));
$('#backup-action').addEventListener('click', async () => {
  const password = value('#backup-password');
  if (password.length < 8) return toast(localized('备份密码至少 8 位', 'Backup password must be at least 8 characters'), 'error');
  if (backupMode === 'export' && password !== value('#backup-password-confirm')) return toast(localized('两次密码不一致', 'Password entries do not match'), 'error');
  try { const result = backupMode === 'export' ? await api.exportBackup(password) : await api.importBackup(password); if (result) { $('#backup-modal').classList.add('hidden'); toast(backupMode === 'export' ? localized('备份已导出', 'Backup exported') : localized(`导入完成：新增 ${result.added}，更新 ${result.updated}`, `Import complete: ${result.added} added, ${result.updated} updated`)); await refresh(); } } catch (error) { toast(cleanError(error), 'error'); }
});

$('#page-activity .activity-panel').addEventListener('scroll', (event) => {
  const panel = event.currentTarget;
  if (panel.scrollHeight - panel.scrollTop - panel.clientHeight < 160) queueMoreActivities();
}, { passive: true });

window.__TAURI__.event.listen('state-changed', async () => { await refresh(false); await refreshDrafts(); await refreshApprovals(); });
window.addEventListener('focus', async () => { await refresh(false); await refreshOwnerLock(false); await refreshDrafts(); await refreshApprovals(); });
window.addEventListener('resize', positionModuleMenu);
$('.form-scroll', $('#connection-modal')).addEventListener('scroll', positionModuleMenu, { passive: true });
for (const eventName of ['pointerdown', 'keydown']) document.addEventListener(eventName, () => { if (ownerLockState.unlocked) lastOwnerActivity = Date.now(); }, { passive: true });
setInterval(() => { if ($('#page-activity').classList.contains('active')) refresh(false); }, 2000);
setInterval(refreshApprovals, 750);
setInterval(async () => {
  if (!ownerLockState.unlocked) return;
  try {
    ownerLockState = Date.now() - lastOwnerActivity < 45_000 ? await api.ownerTouch() : await api.ownerStatus();
    if (!ownerLockState.unlocked) renderOwnerLock();
  } catch (_) { await refreshOwnerLock(false); }
}, 15_000);

async function bootstrap() {
  applyLanguage();
  initFixedScrollThumbs();
  await refreshOwnerLock();
  await refresh();
  await refreshDrafts();
  await refreshApprovals();
  scanAgents();
  queueScrollThumbSync();
}
bootstrap();

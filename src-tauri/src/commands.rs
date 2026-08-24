use crate::{
    agent_registry::{AgentActionResult, AgentClientStatus, AgentRegistry},
    backup,
    browser::BrowserBridge,
    executor, mcp,
    model::{
        AppState, ApprovalRequest, ConnectionInput, ImportSummary, NewActivity, OwnerEditorDraft,
        OwnerLockState, OwnerSecretView, PublicConnection, Settings,
    },
    vault::Vault,
};
use anyhow::{Context, Result};
use std::{
    collections::HashSet,
    path::PathBuf,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tauri::{
    AppHandle, Emitter, LogicalSize, Manager, State, WebviewWindow,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tauri_plugin_opener::OpenerExt;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct AppRuntime {
    vault: Vault,
    executable: String,
    browser: BrowserBridge,
    pending_private_key: Mutex<Option<PathBuf>>,
    owner_session: Mutex<OwnerSession>,
    agent_registry: AgentRegistry,
}

#[derive(Default)]
struct OwnerSession {
    unlocked_until: Option<Instant>,
}

const OWNER_SESSION_DURATION: Duration = Duration::from_secs(10 * 60);
const WINDOW_LOGICAL_WIDTH: f64 = 460.0;
const WINDOW_LOGICAL_HEIGHT: f64 = 690.0;

async fn owner_lock_state(runtime: &AppRuntime) -> Result<OwnerLockState, String> {
    let pin_configured = runtime
        .vault
        .owner_pin_configured()
        .map_err(command_error)?;
    let mut session = runtime.owner_session.lock().await;
    let expires_in_seconds = session
        .unlocked_until
        .and_then(|until| until.checked_duration_since(Instant::now()))
        .map(|remaining| remaining.as_secs())
        .unwrap_or(0);
    if expires_in_seconds == 0 {
        session.unlocked_until = None;
    }
    Ok(OwnerLockState {
        pin_configured,
        unlocked: pin_configured && expires_in_seconds > 0,
        expires_in_seconds,
    })
}

async fn require_owner_unlocked(runtime: &AppRuntime) -> Result<(), String> {
    if owner_lock_state(runtime).await?.unlocked {
        Ok(())
    } else {
        Err("GUI 已锁定，请输入六位 PIN".to_owned())
    }
}

async fn extend_owner_session(runtime: &AppRuntime) {
    runtime.owner_session.lock().await.unlocked_until =
        Some(Instant::now() + OWNER_SESSION_DURATION);
}

fn command_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn emit_changed(app: &AppHandle) {
    let _ = app.emit("state-changed", ());
}

#[tauri::command]
async fn get_state(runtime: State<'_, AppRuntime>) -> Result<AppState, String> {
    runtime.browser.sync().await;
    let browser = runtime.browser.status().await;
    runtime
        .vault
        .app_state(&runtime.executable, browser)
        .map_err(command_error)
}

#[tauri::command]
async fn owner_status(runtime: State<'_, AppRuntime>) -> Result<OwnerLockState, String> {
    owner_lock_state(&runtime).await
}

#[tauri::command]
async fn owner_set_pin(
    runtime: State<'_, AppRuntime>,
    pin: String,
) -> Result<OwnerLockState, String> {
    runtime.vault.set_owner_pin(&pin).map_err(command_error)?;
    extend_owner_session(&runtime).await;
    owner_lock_state(&runtime).await
}

#[tauri::command]
async fn owner_unlock(
    runtime: State<'_, AppRuntime>,
    pin: String,
) -> Result<OwnerLockState, String> {
    if !runtime
        .vault
        .verify_owner_pin(&pin)
        .map_err(command_error)?
    {
        return Err("PIN 不正确".to_owned());
    }
    extend_owner_session(&runtime).await;
    owner_lock_state(&runtime).await
}

#[tauri::command]
async fn owner_touch(runtime: State<'_, AppRuntime>) -> Result<OwnerLockState, String> {
    require_owner_unlocked(&runtime).await?;
    extend_owner_session(&runtime).await;
    owner_lock_state(&runtime).await
}

#[tauri::command]
async fn owner_lock(runtime: State<'_, AppRuntime>) -> Result<OwnerLockState, String> {
    runtime.owner_session.lock().await.unlocked_until = None;
    owner_lock_state(&runtime).await
}

#[tauri::command]
async fn owner_secret_view(
    runtime: State<'_, AppRuntime>,
    id: Uuid,
) -> Result<OwnerSecretView, String> {
    require_owner_unlocked(&runtime).await?;
    extend_owner_session(&runtime).await;
    runtime.vault.owner_secret_view(id).map_err(command_error)
}

#[tauri::command]
async fn owner_editor_drafts(
    runtime: State<'_, AppRuntime>,
) -> Result<Vec<OwnerEditorDraft>, String> {
    require_owner_unlocked(&runtime).await?;
    extend_owner_session(&runtime).await;
    runtime.vault.list_editor_drafts().map_err(command_error)
}

#[tauri::command]
async fn save_editor_draft(
    runtime: State<'_, AppRuntime>,
    draft_id: Option<Uuid>,
    mut input: ConnectionInput,
) -> Result<OwnerEditorDraft, String> {
    require_owner_unlocked(&runtime).await?;
    extend_owner_session(&runtime).await;
    if input.private_key_import_path == "pending" {
        let path = runtime
            .pending_private_key
            .lock()
            .await
            .take()
            .ok_or_else(|| "请重新选择 SSH 私钥".to_owned())?;
        let metadata = std::fs::metadata(&path).map_err(command_error)?;
        if metadata.len() > 1_048_576 {
            return Err("SSH 私钥文件不能超过 1 MB".to_owned());
        }
        input.secrets.private_key = Some(std::fs::read_to_string(&path).map_err(command_error)?);
        input.secrets.private_key_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned);
    }
    input.private_key_import_path.clear();
    runtime
        .vault
        .save_editor_draft(draft_id, input)
        .map_err(command_error)
}

#[tauri::command]
async fn delete_editor_draft(runtime: State<'_, AppRuntime>, id: Uuid) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime.vault.delete_editor_draft(id).map_err(command_error)
}

#[tauri::command]
async fn copy_owner_value(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    value: String,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    extend_owner_session(&runtime).await;
    app.clipboard().write_text(&value).map_err(command_error)
}

#[tauri::command]
async fn save_connection(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    mut input: ConnectionInput,
) -> Result<PublicConnection, String> {
    require_owner_unlocked(&runtime).await?;
    if input.private_key_import_path == "pending" {
        let selected = runtime
            .pending_private_key
            .lock()
            .await
            .take()
            .ok_or_else(|| "请重新选择 SSH 私钥".to_owned())?;
        input.private_key_import_path = selected.to_string_lossy().into_owned();
    } else {
        input.private_key_import_path.clear();
    }
    let connection = runtime
        .vault
        .save_connection(input)
        .map_err(command_error)?;
    emit_changed(&app);
    Ok(connection)
}

#[tauri::command]
async fn set_connection_enabled(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
    enabled: bool,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime
        .vault
        .set_connection_enabled(id, enabled)
        .map_err(command_error)?;
    emit_changed(&app);
    Ok(())
}

#[tauri::command]
async fn delete_connection(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    runtime.vault.delete_connection(id).map_err(command_error)?;
    emit_changed(&app);
    Ok(())
}

#[tauri::command]
async fn test_connection(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
) -> Result<String, String> {
    let started = Instant::now();
    let connection = runtime.vault.get_connection(id).map_err(command_error)?;
    let connection_name = connection.stored.name.clone();
    let result: anyhow::Result<String> =
        if connection.stored.has_capability("ssh") || connection.stored.has_capability("http") {
            executor::test_connection(&runtime.vault, &connection).await
        } else {
            Ok(format!(
                "安全填入就绪 · {} 个字段",
                connection
                    .secrets
                    .available_fields(connection.stored.secret.as_ref())
                    .len()
            ))
        }
        .map_err(|error| {
            anyhow::anyhow!(crate::policy::redact(
                error.to_string(),
                &connection.stored,
                &connection.secrets,
            ))
        });
    let (status, error) = match &result {
        Ok(_) => ("success", String::new()),
        Err(error) => ("error", error.to_string()),
    };
    let _ = runtime.vault.add_activity(NewActivity {
        status: status.to_owned(),
        source: "应用".to_owned(),
        connection_name,
        action: "测试连接".to_owned(),
        duration_ms: started.elapsed().as_millis() as u64,
        error,
    });
    emit_changed(&app);
    result.map_err(command_error)
}

#[tauri::command]
async fn reset_ssh_fingerprint(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
) -> Result<(), String> {
    let connection = runtime.vault.get_connection(id).map_err(command_error)?;
    if !connection.stored.has_capability("ssh") {
        return Err("所选项目的模块尚未形成可用 SSH 动作".to_owned());
    }
    runtime
        .vault
        .reset_ssh_fingerprint(id)
        .map_err(command_error)?;
    let _ = runtime.vault.add_activity(NewActivity {
        status: "success".to_owned(),
        source: "应用".to_owned(),
        connection_name: connection.stored.name,
        action: "重置 SSH 主机信任".to_owned(),
        duration_ms: 0,
        error: String::new(),
    });
    emit_changed(&app);
    Ok(())
}

#[tauri::command]
async fn update_settings(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    settings: Settings,
) -> Result<Settings, String> {
    let settings = runtime
        .vault
        .update_settings(settings)
        .map_err(command_error)?;
    runtime.browser.sync().await;
    emit_changed(&app);
    Ok(settings)
}

#[tauri::command]
async fn clear_activities(app: AppHandle, runtime: State<'_, AppRuntime>) -> Result<(), String> {
    runtime.vault.clear_activities().map_err(command_error)?;
    emit_changed(&app);
    Ok(())
}

#[tauri::command]
async fn approval_requests(runtime: State<'_, AppRuntime>) -> Result<Vec<ApprovalRequest>, String> {
    require_owner_unlocked(&runtime).await?;
    runtime.vault.pending_approvals().map_err(command_error)
}

#[tauri::command]
async fn resolve_approval(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    id: Uuid,
    approved: bool,
) -> Result<(), String> {
    require_owner_unlocked(&runtime).await?;
    extend_owner_session(&runtime).await;
    runtime
        .vault
        .resolve_approval(id, approved)
        .map_err(command_error)?;
    emit_changed(&app);
    Ok(())
}

#[tauri::command]
async fn copy_mcp_config(
    app: AppHandle,
    _runtime: State<'_, AppRuntime>,
    format: String,
) -> Result<String, String> {
    let config = mcp::render_config(&format).map_err(command_error)?;
    app.clipboard().write_text(&config).map_err(command_error)?;
    Ok(config)
}

#[tauri::command]
async fn agent_mcp_status(
    runtime: State<'_, AppRuntime>,
) -> Result<Vec<AgentClientStatus>, String> {
    Ok(runtime.agent_registry.list().await)
}

#[tauri::command]
async fn agent_mcp_register(
    runtime: State<'_, AppRuntime>,
    client_ids: Vec<String>,
) -> Result<Vec<AgentActionResult>, String> {
    Ok(runtime.agent_registry.register(&client_ids).await)
}

#[tauri::command]
async fn agent_mcp_repair(
    runtime: State<'_, AppRuntime>,
    client_id: String,
) -> Result<AgentActionResult, String> {
    Ok(runtime.agent_registry.repair(&client_id).await)
}

#[tauri::command]
async fn agent_mcp_remove(
    runtime: State<'_, AppRuntime>,
    client_id: String,
) -> Result<AgentActionResult, String> {
    Ok(runtime.agent_registry.remove(&client_id).await)
}

#[tauri::command]
async fn complete_agent_onboarding(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<(), String> {
    runtime
        .vault
        .complete_agent_mcp_onboarding()
        .map_err(command_error)?;
    emit_changed(&app);
    Ok(())
}

#[tauri::command]
async fn choose_private_key(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<Option<String>, String> {
    require_owner_unlocked(&runtime).await?;
    let selected = app
        .dialog()
        .file()
        .add_filter("SSH 私钥", &["pem", "key", "ppk", "txt"])
        .blocking_pick_file();
    let Some(path) = selected else {
        return Ok(None);
    };
    let path = path.into_path().map_err(command_error)?;
    let metadata = std::fs::metadata(&path).map_err(command_error)?;
    if metadata.len() > 1_048_576 {
        return Err("SSH 私钥文件不能超过 1 MB".to_owned());
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("SSH KEY")
        .to_owned();
    *runtime.pending_private_key.lock().await = Some(path);
    Ok(Some(name))
}

#[tauri::command]
async fn quick_pair_browser(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    port: u16,
) -> Result<String, String> {
    let mut settings = runtime.vault.settings().map_err(command_error)?;
    settings.browser_enabled = true;
    settings.browser_port = port;
    runtime
        .vault
        .update_settings(settings)
        .map_err(command_error)?;
    runtime.browser.sync().await;
    runtime
        .browser
        .start_quick_pairing()
        .await
        .map_err(command_error)?;

    let folder_opened = browser_extension_path(&app).is_ok_and(|extension_path| {
        app.opener()
            .open_path(extension_path.to_string_lossy(), None::<&str>)
            .is_ok()
    });
    let browser_opened = open_chromium_extensions_page();
    emit_changed(&app);

    Ok(match (browser_opened, folder_opened) {
        (true, true) => "自动配对已开启 · 首次使用请在扩展页加载已打开的目录".to_owned(),
        (true, false) => "自动配对已开启 · 请在扩展页加载 browser-extension 目录".to_owned(),
        (false, true) => "自动配对已开启 · 请手动打开 chrome://extensions 加载该目录".to_owned(),
        (false, false) => "自动配对已开启 · 已安装扩展会自动连接".to_owned(),
    })
}

#[tauri::command]
async fn reset_browser_pairing(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
) -> Result<(), String> {
    runtime
        .browser
        .reset_pairing()
        .await
        .map_err(command_error)?;
    emit_changed(&app);
    Ok(())
}

#[tauri::command]
async fn open_browser_extension_folder(app: AppHandle) -> Result<(), String> {
    let path = browser_extension_path(&app)?;
    app.opener()
        .open_path(path.to_string_lossy(), None::<&str>)
        .map_err(command_error)
}

fn browser_extension_path(app: &AppHandle) -> Result<PathBuf, String> {
    let bundled = app
        .path()
        .resource_dir()
        .ok()
        .map(|path| path.join("browser-extension"))
        .filter(|path| path.is_dir());
    let executable = std::env::current_exe().map_err(command_error)?;
    let portable = executable
        .parent()
        .map(|path| path.join("browser-extension"))
        .filter(|path| path.is_dir());
    let development = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|path| path.join("browser-extension"))
        .filter(|path| path.is_dir());
    let path = bundled
        .or(portable)
        .or(development)
        .ok_or_else(|| "未找到 browser-extension 目录，请使用完整的便携 ZIP".to_owned())?;
    Ok(path)
}

#[cfg(windows)]
fn open_chromium_extensions_page() -> bool {
    let mut candidates = Vec::new();
    for root in ["LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)"] {
        let Some(root) = std::env::var_os(root) else {
            continue;
        };
        let root = PathBuf::from(root);
        candidates.push(root.join("Google/Chrome/Application/chrome.exe"));
        candidates.push(root.join("Microsoft/Edge/Application/msedge.exe"));
        candidates.push(root.join("BraveSoftware/Brave-Browser/Application/brave.exe"));
    }
    candidates.extend(["chrome.exe", "msedge.exe", "brave.exe"].map(PathBuf::from));
    candidates.into_iter().any(|candidate| {
        if candidate.components().count() > 1 && !candidate.is_file() {
            return false;
        }
        Command::new(candidate)
            .arg("--new-tab")
            .arg("chrome://extensions")
            .spawn()
            .is_ok()
    })
}

#[cfg(target_os = "macos")]
fn open_chromium_extensions_page() -> bool {
    ["Google Chrome", "Microsoft Edge", "Brave Browser"]
        .into_iter()
        .any(|browser| {
            Command::new("open")
                .args(["-a", browser, "chrome://extensions"])
                .spawn()
                .is_ok()
        })
}

#[cfg(all(unix, not(target_os = "macos")))]
fn open_chromium_extensions_page() -> bool {
    [
        "google-chrome",
        "microsoft-edge",
        "brave-browser",
        "chromium",
    ]
    .into_iter()
    .any(|browser| {
        Command::new(browser)
            .args(["--new-tab", "chrome://extensions"])
            .spawn()
            .is_ok()
    })
}

#[tauri::command]
async fn export_backup(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    password: String,
) -> Result<Option<String>, String> {
    let selected = app
        .dialog()
        .file()
        .add_filter("KRU 备份", &["mvault"])
        .set_file_name("kru-backup.mvault")
        .blocking_save_file();
    let Some(path) = selected else {
        return Ok(None);
    };
    let path = path.into_path().map_err(command_error)?;
    backup::export_to_file(&runtime.vault, &path, &password).map_err(command_error)?;
    Ok(Some(path.to_string_lossy().into_owned()))
}

#[tauri::command]
async fn import_backup(
    app: AppHandle,
    runtime: State<'_, AppRuntime>,
    password: String,
) -> Result<Option<ImportSummary>, String> {
    let selected = app
        .dialog()
        .file()
        .add_filter("KRU 备份", &["mvault"])
        .blocking_pick_file();
    let Some(path) = selected else {
        return Ok(None);
    };
    let path = path.into_path().map_err(command_error)?;
    let summary =
        backup::import_from_file(&runtime.vault, path, &password).map_err(command_error)?;
    emit_changed(&app);
    Ok(Some(summary))
}

#[tauri::command]
async fn open_data_folder(app: AppHandle, runtime: State<'_, AppRuntime>) -> Result<(), String> {
    app.opener()
        .open_path(runtime.vault.data_dir().to_string_lossy(), None::<&str>)
        .map_err(command_error)
}

#[tauri::command]
async fn window_action(
    window: WebviewWindow,
    runtime: State<'_, AppRuntime>,
    action: String,
) -> Result<(), String> {
    match action.as_str() {
        "minimize" => {
            runtime.owner_session.lock().await.unlocked_until = None;
            window.hide().map_err(command_error)
        }
        "close" => {
            let close_behavior = runtime
                .vault
                .settings()
                .map_err(command_error)?
                .close_behavior;
            if close_behavior == "exit" {
                window.app_handle().exit(0);
                Ok(())
            } else {
                runtime.owner_session.lock().await.unlocked_until = None;
                window.hide().map_err(command_error)
            }
        }
        "attention" => window
            .request_user_attention(Some(tauri::UserAttentionType::Critical))
            .map_err(command_error),
        "attention-clear" => window.request_user_attention(None).map_err(command_error),
        _ => Err("未知窗口操作".to_owned()),
    }
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn install_tray(app: &tauri::App) -> Result<()> {
    let open = MenuItem::with_id(app, "tray-open", "OPEN KRU", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "tray-lock", "LOCK", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "tray-quit", "QUIT", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &lock, &separator, &quit])?;
    let icon = app
        .default_window_icon()
        .context("找不到 KRU 托盘图标")?
        .clone();

    TrayIconBuilder::with_id("kru-tray")
        .icon(icon)
        .tooltip("KRU — LOCAL VAULT")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| {
            if event.id() == "tray-open" {
                show_main_window(app);
            } else if event.id() == "tray-lock" {
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    handle
                        .state::<AppRuntime>()
                        .owner_session
                        .lock()
                        .await
                        .unlocked_until = None;
                    show_main_window(&handle);
                });
            } else if event.id() == "tray-quit" {
                app.exit(0);
            }
        })
        .on_tray_icon_event(|tray, event| match event {
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            }
            | TrayIconEvent::DoubleClick {
                button: MouseButton::Left,
                ..
            } => show_main_window(tray.app_handle()),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

fn spawn_approval_popup_watcher(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut notified = HashSet::new();
        let dialog_open = Arc::new(AtomicBool::new(false));

        loop {
            tokio::time::sleep(Duration::from_millis(750)).await;
            let runtime = app.state::<AppRuntime>();
            let Ok(settings) = runtime.vault.settings() else {
                continue;
            };
            if !settings.approval_mode || !settings.system_approval_popup {
                notified.clear();
                continue;
            }

            let Ok(requests) = runtime.vault.pending_approvals() else {
                continue;
            };
            let active_ids: HashSet<_> = requests.iter().map(|request| request.id).collect();
            notified.retain(|id| active_ids.contains(id));
            if dialog_open.load(Ordering::Acquire) {
                continue;
            }
            let Some(request) = requests
                .iter()
                .find(|request| !notified.contains(&request.id))
            else {
                continue;
            };

            notified.insert(request.id);
            dialog_open.store(true, Ordering::Release);
            let english = settings.language == "en";
            let title = if english {
                "KRU · APPROVAL REQUIRED"
            } else {
                "KRU · 等待审核"
            };
            let body = if english {
                format!(
                    "{} requests access to “{}”.\nAction: {}\nReview this request inside KRU.",
                    request.source, request.item_name, request.action
                )
            } else {
                format!(
                    "{} 请求使用「{}」。\n动作：{}\n请在 KRU 内完成审核。",
                    request.source, request.item_name, request.action
                )
            };
            let open_label = if english { "OPEN KRU" } else { "打开 KRU" };
            let callback_app = app.clone();
            let callback_open = dialog_open.clone();
            app.dialog()
                .message(body)
                .title(title)
                .kind(MessageDialogKind::Warning)
                .buttons(MessageDialogButtons::OkCustom(open_label.to_owned()))
                .show(move |open| {
                    callback_open.store(false, Ordering::Release);
                    if open {
                        show_main_window(&callback_app);
                    }
                });
        }
    });
}

fn app_data_dir() -> Result<PathBuf> {
    dirs::data_dir()
        .map(|path| path.join("mcp-vault").join("v2"))
        .context("无法确定本机数据目录")
}

#[cfg(windows)]
fn request_square_corners(window: &WebviewWindow) -> Result<()> {
    use windows::Win32::Graphics::Dwm::{
        DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_DONOTROUND, DwmSetWindowAttribute,
    };

    let hwnd = window.hwnd().context("无法获得窗口句柄")?;
    let preference = DWMWCP_DONOTROUND;
    unsafe {
        DwmSetWindowAttribute(
            windows::Win32::Foundation::HWND(hwnd.0),
            DWMWA_WINDOW_CORNER_PREFERENCE,
            &preference as *const _ as *const _,
            size_of_val(&preference) as u32,
        )
        .context("无法请求 Windows 直角窗口")?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn request_square_corners(_window: &WebviewWindow) -> Result<()> {
    Ok(())
}

pub fn run_gui() -> Result<()> {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let vault = Vault::open(app_data_dir()?)?;
            let executable = std::env::current_exe()
                .context("无法确定可执行文件路径")?
                .to_string_lossy()
                .into_owned();
            let browser = BrowserBridge::new(vault.clone());
            let agent_registry = AgentRegistry::new(PathBuf::from(&executable))?;
            app.manage(AppRuntime {
                vault,
                executable,
                browser,
                pending_private_key: Mutex::new(None),
                owner_session: Mutex::new(OwnerSession::default()),
                agent_registry,
            });

            let window = app.get_webview_window("main").context("找不到主窗口")?;
            let fixed_size = LogicalSize::new(WINDOW_LOGICAL_WIDTH, WINDOW_LOGICAL_HEIGHT);
            window.set_min_size(Some(fixed_size))?;
            window.set_max_size(Some(fixed_size))?;
            window.set_size(fixed_size)?;
            window.set_resizable(false)?;
            window.set_maximizable(false)?;
            request_square_corners(&window)?;
            install_tray(app)?;
            spawn_approval_popup_watcher(app.handle().clone());

            {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    handle.state::<AppRuntime>().browser.sync().await;
                    emit_changed(&handle);
                });
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if matches!(event, tauri::WindowEvent::ScaleFactorChanged { .. }) {
                let _ = window.set_size(LogicalSize::new(
                    WINDOW_LOGICAL_WIDTH,
                    WINDOW_LOGICAL_HEIGHT,
                ));
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            owner_status,
            owner_set_pin,
            owner_unlock,
            owner_touch,
            owner_lock,
            owner_secret_view,
            owner_editor_drafts,
            save_editor_draft,
            delete_editor_draft,
            copy_owner_value,
            save_connection,
            set_connection_enabled,
            delete_connection,
            test_connection,
            reset_ssh_fingerprint,
            update_settings,
            clear_activities,
            approval_requests,
            resolve_approval,
            copy_mcp_config,
            agent_mcp_status,
            agent_mcp_register,
            agent_mcp_repair,
            agent_mcp_remove,
            complete_agent_onboarding,
            choose_private_key,
            quick_pair_browser,
            reset_browser_pairing,
            open_browser_extension_folder,
            export_backup,
            import_backup,
            open_data_folder,
            window_action,
        ])
        .run(tauri::generate_context!())
        .context("KRU GUI 启动失败")?;
    Ok(())
}

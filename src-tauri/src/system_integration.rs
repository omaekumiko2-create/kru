use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemIntegrationState {
    pub desktop_shortcut: bool,
    pub launch_at_login: bool,
}

pub fn status(executable: &Path) -> Result<SystemIntegrationState> {
    Ok(SystemIntegrationState {
        desktop_shortcut: desktop_shortcut_status(executable)?,
        launch_at_login: entry_exists(&autostart_entry_path()?),
    })
}

#[cfg(not(target_os = "macos"))]
pub fn set_desktop_shortcut(executable: &Path, enabled: bool) -> Result<SystemIntegrationState> {
    let path = desktop_entry_path(executable)?;
    set_entry(&path, executable, enabled, EntryKind::Desktop)?;
    status(executable)
}

#[cfg(target_os = "macos")]
pub fn set_desktop_shortcut(executable: &Path, enabled: bool) -> Result<SystemIntegrationState> {
    if enabled {
        bail!("macOS 不创建桌面快捷方式；请从应用程序、Dock 或 Spotlight 启动 KRU")
    }
    remove_entry(&desktop_entry_path(executable)?)?;
    status(executable)
}

pub fn set_launch_at_login(executable: &Path, enabled: bool) -> Result<SystemIntegrationState> {
    let path = autostart_entry_path()?;
    set_entry(&path, executable, enabled, EntryKind::Autostart)?;
    status(executable)
}

#[derive(Clone, Copy)]
enum EntryKind {
    #[cfg(not(target_os = "macos"))]
    Desktop,
    Autostart,
}

fn entry_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

#[cfg(not(target_os = "macos"))]
fn desktop_shortcut_status(executable: &Path) -> Result<bool> {
    Ok(entry_exists(&desktop_entry_path(executable)?))
}

#[cfg(target_os = "macos")]
fn desktop_shortcut_status(_executable: &Path) -> Result<bool> {
    Ok(false)
}

fn remove_entry(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            bail!("拒绝删除非快捷方式目录：{}", path.display())
        }
        Ok(_) => {
            fs::remove_file(path).with_context(|| format!("无法删除系统入口：{}", path.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("无法读取系统入口：{}", path.display())),
    }
}

#[cfg(target_os = "windows")]
fn desktop_entry_path(_executable: &Path) -> Result<PathBuf> {
    Ok(dirs::desktop_dir()
        .context("找不到桌面目录")?
        .join("KRU.lnk"))
}

#[cfg(target_os = "windows")]
fn autostart_entry_path() -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .context("找不到 Windows 配置目录")?
        .join("Microsoft/Windows/Start Menu/Programs/Startup/KRU.lnk"))
}

#[cfg(target_os = "windows")]
fn set_entry(path: &Path, executable: &Path, enabled: bool, _kind: EntryKind) -> Result<()> {
    if !enabled {
        return remove_entry(path);
    }
    create_windows_shortcut(path, executable)
}

#[cfg(target_os = "windows")]
fn create_windows_shortcut(path: &Path, executable: &Path) -> Result<()> {
    use windows::{
        Win32::{
            System::Com::{
                CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
                CoUninitialize, IPersistFile,
            },
            UI::Shell::{IShellLinkW, ShellLink},
        },
        core::{HSTRING, IUnknown, Interface},
    };

    let parent = path.parent().context("快捷方式路径缺少父目录")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("无法创建快捷方式目录：{}", parent.display()))?;
    let executable = executable
        .canonicalize()
        .with_context(|| format!("找不到 KRU 程序：{}", executable.display()))?;
    let working_directory = executable.parent().context("KRU 程序路径缺少父目录")?;
    let initialized = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.is_ok();
    let result = (|| -> Result<()> {
        let shell_link: IShellLinkW =
            unsafe { CoCreateInstance(&ShellLink, None::<&IUnknown>, CLSCTX_INPROC_SERVER) }
                .context("无法创建 Windows 快捷方式")?;
        let executable_text = HSTRING::from(windows_shell_path(&executable));
        let working_text = HSTRING::from(windows_shell_path(working_directory));
        let arguments = HSTRING::from("gui");
        let description = HSTRING::from("KRU — local credential relay for AI agents");
        unsafe {
            shell_link.SetPath(&executable_text).context("SetPath")?;
            shell_link
                .SetWorkingDirectory(&working_text)
                .context("SetWorkingDirectory")?;
            shell_link
                .SetArguments(&arguments)
                .context("SetArguments")?;
            shell_link
                .SetDescription(&description)
                .context("SetDescription")?;
            shell_link
                .SetIconLocation(&executable_text, 0)
                .context("SetIconLocation")?;
            let persist: IPersistFile = shell_link.cast().context("IPersistFile")?;
            let path_text = HSTRING::from(windows_shell_path(path));
            persist
                .Save(&path_text, true)
                .context("IPersistFile::Save")?;
        }
        Ok(())
    })();
    if initialized {
        unsafe { CoUninitialize() };
    }
    result.with_context(|| format!("无法写入快捷方式：{}", path.display()))
}

#[cfg(target_os = "windows")]
fn windows_shell_path(path: &Path) -> String {
    let path = path.to_string_lossy();
    if let Some(path) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{path}")
    } else {
        path.strip_prefix(r"\\?\").unwrap_or(&path).to_owned()
    }
}

#[cfg(target_os = "macos")]
fn desktop_entry_path(executable: &Path) -> Result<PathBuf> {
    let name = if macos_app_bundle(executable).is_some() {
        "KRU.app"
    } else {
        "KRU"
    };
    Ok(dirs::desktop_dir().context("找不到桌面目录")?.join(name))
}

#[cfg(target_os = "macos")]
fn autostart_entry_path() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .context("找不到用户目录")?
        .join("Library/LaunchAgents/dev.kru.app.plist"))
}

#[cfg(target_os = "macos")]
fn macos_app_bundle(executable: &Path) -> Option<PathBuf> {
    executable
        .ancestors()
        .find(|path| path.extension().is_some_and(|extension| extension == "app"))
        .map(Path::to_path_buf)
}

#[cfg(target_os = "macos")]
fn set_entry(path: &Path, executable: &Path, enabled: bool, kind: EntryKind) -> Result<()> {
    if !enabled {
        return remove_entry(path);
    }
    let parent = path.parent().context("系统入口路径缺少父目录")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("无法创建系统入口目录：{}", parent.display()))?;
    remove_entry(path)?;
    match kind {
        EntryKind::Autostart => {
            let executable = xml_escape(executable.to_string_lossy().as_ref());
            let content = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key><string>dev.kru.app</string>\n  <key>ProgramArguments</key><array><string>{executable}</string><string>gui</string></array>\n  <key>RunAtLoad</key><true/>\n</dict>\n</plist>\n"
            );
            fs::write(path, content)
                .with_context(|| format!("无法写入登录启动配置：{}", path.display()))
        }
    }
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(target_os = "linux")]
fn desktop_entry_path(_executable: &Path) -> Result<PathBuf> {
    Ok(dirs::desktop_dir()
        .context("找不到桌面目录")?
        .join("KRU.desktop"))
}

#[cfg(target_os = "linux")]
fn autostart_entry_path() -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .context("找不到 Linux 配置目录")?
        .join("autostart/KRU.desktop"))
}

#[cfg(target_os = "linux")]
fn set_entry(path: &Path, executable: &Path, enabled: bool, _kind: EntryKind) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if !enabled {
        return remove_entry(path);
    }
    let parent = path.parent().context("系统入口路径缺少父目录")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("无法创建系统入口目录：{}", parent.display()))?;
    let executable = desktop_exec_quote(executable.to_string_lossy().as_ref());
    let content = format!(
        "[Desktop Entry]\nType=Application\nVersion=1.0\nName=KRU\nComment=Local credential relay for AI agents\nExec={executable} gui\nTryExec={executable}\nIcon=kru\nTerminal=false\nCategories=Utility;Security;\n"
    );
    fs::write(path, content).with_context(|| format!("无法写入系统入口：{}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("无法设置系统入口权限：{}", path.display()))
}

#[cfg(target_os = "linux")]
fn desktop_exec_quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('`', "\\`")
            .replace('$', "\\$")
    )
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
compile_error!("KRU system integration is only supported on Windows, macOS, and Linux");

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::create_windows_shortcut;

    #[test]
    fn creates_a_real_windows_shortcut() {
        let directory = tempfile::tempdir().unwrap();
        let shortcut = directory.path().join("KRU.lnk");
        create_windows_shortcut(&shortcut, &std::env::current_exe().unwrap()).unwrap();
        assert!(shortcut.is_file());
    }
}

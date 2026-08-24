use anyhow::{Context, Result, bail};
use enigo::{Enigo, Keyboard, Settings};

const MAX_FILL_BYTES: usize = 64_000;

pub fn fill_focused(value: &str) -> Result<()> {
    if value.len() > MAX_FILL_BYTES {
        bail!("秘密字段过长，无法通过桌面输入写入");
    }
    if value.contains('\0') {
        bail!("秘密字段包含桌面输入无法写入的空字符");
    }

    #[cfg(target_os = "windows")]
    if fill_standard_windows_control(value)? {
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    if std::env::var_os("WAYLAND_DISPLAY").is_some()
        || std::env::var("XDG_SESSION_TYPE")
            .is_ok_and(|value| value.eq_ignore_ascii_case("wayland"))
    {
        bail!("Wayland 不允许 KRU 可靠地向任意焦点窗口输入；请改用浏览器或托管终端");
    }

    let mut enigo = Enigo::new(&Settings::default()).context("无法初始化桌面输入")?;
    enigo.text(value).context("无法向当前焦点控件输入")
}

#[cfg(target_os = "windows")]
fn fill_standard_windows_control(value: &str) -> Result<bool> {
    use std::mem::size_of;
    use windows::Win32::{
        Foundation::{LPARAM, WPARAM},
        UI::WindowsAndMessaging::{
            GUITHREADINFO, GetClassNameW, GetGUIThreadInfo, SendMessageW, WM_SETTEXT,
        },
    };

    let mut thread = GUITHREADINFO {
        cbSize: size_of::<GUITHREADINFO>() as u32,
        ..Default::default()
    };
    if unsafe { GetGUIThreadInfo(0, &mut thread) }.is_err() || thread.hwndFocus.0.is_null() {
        return Ok(false);
    }

    let mut class_name = [0_u16; 256];
    let class_length = unsafe { GetClassNameW(thread.hwndFocus, &mut class_name) };
    if class_length <= 0 {
        return Ok(false);
    }
    let class_name = String::from_utf16_lossy(&class_name[..class_length as usize]);
    if !class_name.to_ascii_lowercase().contains("edit") {
        return Ok(false);
    }

    let wide = value
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        SendMessageW(
            thread.hwndFocus,
            WM_SETTEXT,
            Some(WPARAM(0)),
            Some(LPARAM(wide.as_ptr() as isize)),
        )
    };
    if result.0 == 0 {
        bail!("前台输入控件拒绝写入");
    }
    Ok(true)
}

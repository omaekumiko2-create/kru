use anyhow::{Context, Result, bail};
use enigo::{Direction, Enigo, Key, Keyboard, Settings};

pub fn fill_focused(value: &str, submit: bool) -> Result<()> {
    validate_fill_value(value)?;

    #[cfg(target_os = "windows")]
    if fill_standard_windows_control(value)? {
        if submit {
            press_enter()?;
        }
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
    enigo.text(value).context("无法向当前焦点控件输入")?;
    if submit {
        enigo
            .key(Key::Return, Direction::Click)
            .context("无法提交当前焦点控件")?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn press_enter() -> Result<()> {
    let mut enigo = Enigo::new(&Settings::default()).context("无法初始化桌面输入")?;
    enigo
        .key(Key::Return, Direction::Click)
        .context("无法提交当前焦点控件")
}

fn validate_fill_value(value: &str) -> Result<()> {
    if value.contains('\0') {
        bail!("秘密字段包含桌面输入无法写入的空字符");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn fill_standard_windows_control(value: &str) -> Result<bool> {
    use std::mem::size_of;
    use windows::Win32::{
        Foundation::{LPARAM, WPARAM},
        UI::WindowsAndMessaging::{
            GUITHREADINFO, GetClassNameW, GetGUIThreadInfo, SEND_MESSAGE_TIMEOUT_FLAGS,
            SMTO_ABORTIFHUNG, SMTO_BLOCK, SendMessageTimeoutW, WM_SETTEXT,
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
    let mut control_result = 0_usize;
    let dispatched = unsafe {
        SendMessageTimeoutW(
            thread.hwndFocus,
            WM_SETTEXT,
            WPARAM(0),
            LPARAM(wide.as_ptr() as isize),
            SEND_MESSAGE_TIMEOUT_FLAGS(SMTO_ABORTIFHUNG.0 | SMTO_BLOCK.0),
            1_000,
            Some(&mut control_result),
        )
    };
    if dispatched.0 == 0 {
        bail!("前台输入控件无响应，已取消写入");
    }
    if control_result == 0 {
        bail!("前台输入控件拒绝写入");
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_fill_has_no_artificial_length_limit() {
        assert!(validate_fill_value(&"x".repeat(2 * 1_048_576)).is_ok());
        assert!(validate_fill_value("contains\0nul").is_err());
    }
}

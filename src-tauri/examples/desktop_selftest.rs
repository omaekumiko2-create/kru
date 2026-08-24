#[cfg(target_os = "windows")]
fn main() -> anyhow::Result<()> {
    use anyhow::Context;
    use mcp_vault::{desktop, vault::Vault};
    use serde_json::json;
    use std::{thread::sleep, time::Duration};
    use windows::{
        Win32::{
            System::Threading::AttachThreadInput,
            UI::{
                Input::KeyboardAndMouse::{GetFocus, SetActiveWindow, SetFocus},
                WindowsAndMessaging::{
                    CW_USEDEFAULT, CreateWindowExW, DestroyWindow, ES_PASSWORD,
                    GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId, SW_SHOW,
                    SetForegroundWindow, SetWindowTextW, ShowWindow, WINDOW_EX_STYLE, WINDOW_STYLE,
                    WS_BORDER, WS_CHILD, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
                },
            },
        },
        core::w,
    };
    use zeroize::Zeroize;

    let data_dir = dirs::data_dir()
        .map(|path| path.join("mcp-vault").join("v2"))
        .context("cannot resolve app data directory")?;
    let vault = Vault::open(data_dir)?;
    let item = vault
        .list_connections()?
        .into_iter()
        .find(|item| item.name == "KRU BROWSER E2E TEST")
        .context("desktop E2E fixture is missing")?;
    let (_, _, mut expected) = vault.get_secret_value(item.id, "password")?;

    let window = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("STATIC"),
            w!("KRU Desktop Self Test"),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            420,
            140,
            None,
            None,
            None,
            None,
        )?
    };
    let edit_style = WINDOW_STYLE(
        WS_CHILD.0 | WS_VISIBLE.0 | WS_BORDER.0 | u32::try_from(ES_PASSWORD).unwrap_or_default(),
    );
    let edit = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("EDIT"),
            w!(""),
            edit_style,
            24,
            32,
            350,
            30,
            Some(window),
            None,
            None,
            None,
        )?
    };
    let foreground = unsafe { GetForegroundWindow() };
    let own_thread = unsafe { GetWindowThreadProcessId(window, None) };
    let foreground_thread = unsafe { GetWindowThreadProcessId(foreground, None) };
    let attached = own_thread != 0 && foreground_thread != 0 && own_thread != foreground_thread;
    unsafe {
        if attached {
            let _ = AttachThreadInput(own_thread, foreground_thread, true);
        }
        let _ = ShowWindow(window, SW_SHOW);
        let _ = SetForegroundWindow(window);
        let _ = SetActiveWindow(window);
        SetFocus(Some(edit))?;
        if attached {
            let _ = AttachThreadInput(own_thread, foreground_thread, false);
        }
    }
    sleep(Duration::from_millis(150));
    let focus_ready = unsafe { GetForegroundWindow() == window && GetFocus() == edit };
    let fill_result = if focus_ready {
        desktop::fill_focused(&expected)
    } else {
        Err(anyhow::anyhow!("self-test control did not receive focus"))
    };

    let mut buffer = vec![0_u16; expected.encode_utf16().count() + 2];
    let length = unsafe { GetWindowTextW(edit, &mut buffer) };
    let mut actual = String::from_utf16_lossy(&buffer[..length.max(0) as usize]);
    let pass = fill_result.is_ok() && actual == expected;
    unsafe {
        SetWindowTextW(edit, w!(""))?;
        DestroyWindow(window)?;
    }
    actual.zeroize();
    expected.zeroize();
    println!(
        "{}",
        serde_json::to_string(&json!({
            "focusReady": focus_ready,
            "fillOk": fill_result.is_ok(),
            "pass": pass
        }))?
    );
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("desktop self-test is Windows-only")
}

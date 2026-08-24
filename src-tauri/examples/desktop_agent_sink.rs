#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[cfg(target_os = "windows")]
fn main() -> anyhow::Result<()> {
    use anyhow::Context;
    use mcp_vault::vault::Vault;
    use serde_json::json;
    use std::{
        env, fs,
        thread::sleep,
        time::{Duration, Instant},
    };
    use windows::{
        Win32::{
            System::Threading::AttachThreadInput,
            UI::{
                Input::KeyboardAndMouse::{SetActiveWindow, SetFocus},
                WindowsAndMessaging::{
                    CreateWindowExW, DestroyWindow, DispatchMessageW, ES_PASSWORD,
                    GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId, MSG, PM_REMOVE,
                    PeekMessageW, SW_SHOW, SetForegroundWindow, SetWindowTextW, ShowWindow,
                    TranslateMessage, WINDOW_EX_STYLE, WINDOW_STYLE, WS_BORDER, WS_CHILD,
                    WS_EX_TOPMOST, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
                },
            },
        },
        core::w,
    };
    use zeroize::Zeroize;

    let result_path = env::args().nth(1).context("result path is required")?;
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
            WS_EX_TOPMOST,
            w!("STATIC"),
            w!("KRU Agent Desktop Test"),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            80,
            80,
            420,
            140,
            None,
            None,
            None,
            None,
        )?
    };
    let edit = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("EDIT"),
            w!(""),
            WINDOW_STYLE(
                WS_CHILD.0
                    | WS_VISIBLE.0
                    | WS_BORDER.0
                    | u32::try_from(ES_PASSWORD).unwrap_or_default(),
            ),
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
    unsafe {
        let _ = ShowWindow(window, SW_SHOW);
    }

    let deadline = Instant::now() + Duration::from_secs(120);
    let mut pass = false;
    while Instant::now() < deadline {
        let foreground = unsafe { GetForegroundWindow() };
        let own_thread = unsafe { GetWindowThreadProcessId(window, None) };
        let foreground_thread = unsafe { GetWindowThreadProcessId(foreground, None) };
        let attached = own_thread != 0 && foreground_thread != 0 && own_thread != foreground_thread;
        unsafe {
            if attached {
                let _ = AttachThreadInput(own_thread, foreground_thread, true);
            }
            let _ = SetForegroundWindow(window);
            let _ = SetActiveWindow(window);
            let _ = SetFocus(Some(edit));
            if attached {
                let _ = AttachThreadInput(own_thread, foreground_thread, false);
            }
            let mut message = MSG::default();
            while PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }

        let mut buffer = vec![0_u16; expected.encode_utf16().count() + 2];
        let length = unsafe { GetWindowTextW(edit, &mut buffer) };
        let mut actual = String::from_utf16_lossy(&buffer[..length.max(0) as usize]);
        pass = actual == expected;
        actual.zeroize();
        if pass {
            break;
        }
        sleep(Duration::from_millis(50));
    }

    unsafe {
        SetWindowTextW(edit, w!(""))?;
        DestroyWindow(window)?;
    }
    expected.zeroize();
    fs::write(result_path, serde_json::to_vec(&json!({"pass": pass}))?)?;
    if !pass {
        anyhow::bail!("desktop Agent test timed out");
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("desktop Agent sink is Windows-only")
}

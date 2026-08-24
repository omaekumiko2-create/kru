#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[cfg(target_os = "windows")]
fn main() -> anyhow::Result<()> {
    use anyhow::Context;
    use mcp_vault::vault::Vault;
    use serde_json::json;
    use std::{
        env, fs,
        sync::Mutex,
        thread::sleep,
        time::{Duration, Instant},
    };
    use windows::{
        Win32::{
            Foundation::{HWND, LPARAM, LRESULT, WPARAM},
            System::Threading::AttachThreadInput,
            UI::{
                Input::KeyboardAndMouse::{SetActiveWindow, SetFocus},
                WindowsAndMessaging::{
                    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
                    GetForegroundWindow, GetWindowThreadProcessId, MSG, PM_REMOVE, PeekMessageW,
                    RegisterClassW, SW_SHOW, SetForegroundWindow, ShowWindow, TranslateMessage,
                    WM_CHAR, WNDCLASSW, WS_EX_TOPMOST, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
                },
            },
        },
        core::w,
    };
    use zeroize::Zeroize;

    static RECEIVED: Mutex<String> = Mutex::new(String::new());

    unsafe extern "system" fn window_proc(
        window: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if message == WM_CHAR {
            if let Some(character) = char::from_u32(wparam.0 as u32) {
                RECEIVED
                    .lock()
                    .expect("receiver mutex poisoned")
                    .push(character);
            }
            return LRESULT(0);
        }
        unsafe { DefWindowProcW(window, message, wparam, lparam) }
    }

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

    let class = WNDCLASSW {
        lpfnWndProc: Some(window_proc),
        lpszClassName: w!("KRUKeyboardAgentSink"),
        ..Default::default()
    };
    if unsafe { RegisterClassW(&class) } == 0 {
        anyhow::bail!(windows::core::Error::from_thread());
    }
    let window = unsafe {
        CreateWindowExW(
            WS_EX_TOPMOST,
            w!("KRUKeyboardAgentSink"),
            w!("KRU Agent Keyboard Event Test"),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            120,
            120,
            440,
            160,
            None,
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
            let _ = SetFocus(Some(window));
            if attached {
                let _ = AttachThreadInput(own_thread, foreground_thread, false);
            }
            let mut message = MSG::default();
            while PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }

        pass = RECEIVED.lock().expect("receiver mutex poisoned").as_str() == expected;
        if pass {
            break;
        }
        sleep(Duration::from_millis(50));
    }

    let received_length = RECEIVED.lock().expect("receiver mutex poisoned").len();
    RECEIVED.lock().expect("receiver mutex poisoned").zeroize();
    unsafe {
        DestroyWindow(window)?;
    }
    expected.zeroize();
    fs::write(
        result_path,
        serde_json::to_vec(&json!({"pass": pass, "receivedLength": received_length}))?,
    )?;
    if !pass {
        anyhow::bail!("keyboard-event Agent test timed out");
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("desktop keyboard Agent sink is Windows-only")
}

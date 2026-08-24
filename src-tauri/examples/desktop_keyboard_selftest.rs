#[cfg(target_os = "windows")]
fn main() -> anyhow::Result<()> {
    use anyhow::Context;
    use mcp_vault::{desktop, vault::Vault};
    use serde_json::json;
    use std::{
        sync::Mutex,
        thread::sleep,
        time::{Duration, Instant},
    };
    use windows::{
        Win32::{
            Foundation::{HWND, LPARAM, LRESULT, WPARAM},
            System::Threading::AttachThreadInput,
            UI::{
                Input::KeyboardAndMouse::{GetFocus, SetActiveWindow, SetFocus},
                WindowsAndMessaging::{
                    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
                    GetForegroundWindow, GetWindowThreadProcessId, MSG, PM_REMOVE, PeekMessageW,
                    RegisterClassW, SW_SHOW, SetForegroundWindow, ShowWindow, TranslateMessage,
                    WINDOW_EX_STYLE, WM_CHAR, WNDCLASSW, WS_OVERLAPPEDWINDOW, WS_VISIBLE,
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
        lpszClassName: w!("KRUKeyboardSink"),
        ..Default::default()
    };
    if unsafe { RegisterClassW(&class) } == 0 {
        anyhow::bail!(windows::core::Error::from_thread());
    }
    let window = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            w!("KRUKeyboardSink"),
            w!("KRU Keyboard Event Test"),
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
        SetFocus(Some(window))?;
        if attached {
            let _ = AttachThreadInput(own_thread, foreground_thread, false);
        }
    }
    sleep(Duration::from_millis(150));
    let focus_ready = unsafe { GetForegroundWindow() == window && GetFocus() == window };
    let fill_result = if focus_ready {
        desktop::fill_focused(&expected)
    } else {
        Err(anyhow::anyhow!("keyboard sink did not receive focus"))
    };

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut pass = false;
    while Instant::now() < deadline {
        unsafe {
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
        sleep(Duration::from_millis(10));
    }

    let received_length = RECEIVED.lock().expect("receiver mutex poisoned").len();
    RECEIVED.lock().expect("receiver mutex poisoned").zeroize();
    unsafe {
        DestroyWindow(window)?;
    }
    expected.zeroize();
    println!(
        "{}",
        serde_json::to_string(&json!({
            "focusReady": focus_ready,
            "fillOk": fill_result.is_ok(),
            "receivedLength": received_length,
            "pass": pass
        }))?
    );
    if !pass {
        anyhow::bail!("keyboard-event desktop input did not reach the focused window");
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("desktop keyboard self-test is Windows-only")
}

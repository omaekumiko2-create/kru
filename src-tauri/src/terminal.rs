use crate::policy::redaction_candidates;
use anyhow::{Context, Result, bail};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};
use uuid::Uuid;

const MAX_SESSIONS: usize = 8;
const MAX_OUTPUT: usize = 200_000;
const MAX_INPUT: usize = 64_000;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalOpenResult {
    pub session_id: Uuid,
    pub executable: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalReadResult {
    pub output: String,
    pub running: bool,
    pub exit_code: Option<u32>,
    pub truncated: bool,
}

#[derive(Default)]
struct OutputBuffer {
    bytes: VecDeque<u8>,
    truncated: bool,
}

impl OutputBuffer {
    fn push(&mut self, bytes: &[u8]) {
        self.bytes.extend(bytes);
        while self.bytes.len() > MAX_OUTPUT {
            self.bytes.pop_front();
            self.truncated = true;
        }
    }

    fn take_redacted(&mut self, candidates: &[String], running: bool) -> (String, bool) {
        let source = self.bytes.drain(..).collect::<Vec<u8>>();
        let candidates = candidates.iter().map(String::as_bytes).collect::<Vec<_>>();
        let mut output = Vec::with_capacity(source.len());
        let mut cursor = 0;
        while cursor < source.len() {
            if let Some(candidate) = candidates
                .iter()
                .find(|candidate| source[cursor..].starts_with(candidate))
            {
                output.extend_from_slice(b"[REDACTED]");
                cursor += candidate.len();
                continue;
            }
            if running
                && candidates
                    .iter()
                    .any(|candidate| candidate.starts_with(&source[cursor..]))
            {
                break;
            }
            output.push(source[cursor]);
            cursor += 1;
        }
        self.bytes.extend(&source[cursor..]);
        let truncated = std::mem::take(&mut self.truncated);
        (String::from_utf8_lossy(&output).into_owned(), truncated)
    }
}

struct TerminalSession {
    _master: Mutex<Box<dyn MasterPty + Send>>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    child: Mutex<Box<dyn Child + Send + Sync>>,
    output: Arc<Mutex<OutputBuffer>>,
    secrets: Mutex<Vec<String>>,
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        if let Ok(child) = self.child.get_mut() {
            let _ = child.kill();
        }
    }
}

#[derive(Clone)]
pub struct TerminalManager {
    sessions: Arc<Mutex<HashMap<Uuid, Arc<TerminalSession>>>>,
}

impl TerminalManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn open(
        &self,
        program: &str,
        args: Vec<String>,
        cwd: Option<String>,
    ) -> Result<TerminalOpenResult> {
        if program.trim().is_empty() || program.chars().count() > 1_024 {
            bail!("程序名称无效");
        }
        if args.len() > 100
            || args
                .iter()
                .any(|arg| arg.chars().count() > 4_096 || arg.contains('\0'))
        {
            bail!("终端参数过多或过长");
        }
        let cwd = normalize_cwd(cwd)?;
        let executable = resolve_executable(program.trim(), cwd.as_deref())?;
        {
            let sessions = self.sessions.lock().map_err(lock_error)?;
            if sessions.len() >= MAX_SESSIONS {
                bail!("同时最多打开 {MAX_SESSIONS} 个终端会话");
            }
        }

        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: 30,
                cols: 120,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("无法创建本地 PTY")?;
        let mut command = CommandBuilder::new(&executable);
        command.args(args);
        command.env_clear();
        for name in safe_environment_names() {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        if let Some(cwd) = &cwd {
            command.cwd(cwd);
        }
        let child = pair
            .slave
            .spawn_command(command)
            .context("无法在 PTY 中启动程序")?;
        drop(pair.slave);
        let mut reader = pair
            .master
            .try_clone_reader()
            .context("无法读取 PTY 输出")?;
        let writer = Arc::new(Mutex::new(
            pair.master.take_writer().context("无法写入 PTY")?,
        ));
        let output = Arc::new(Mutex::new(OutputBuffer::default()));
        let reader_output = output.clone();
        let reader_writer = writer.clone();
        std::thread::Builder::new()
            .name("kru-pty-reader".to_owned())
            .spawn(move || {
                let mut buffer = [0_u8; 8_192];
                loop {
                    match reader.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(count) => {
                            // Windows ConPTY asks the terminal for its cursor position before
                            // presenting the child prompt. We are a headless terminal, so answer
                            // with a stable position instead of leaving the child blocked.
                            if buffer[..count]
                                .windows(4)
                                .any(|window| window == b"\x1b[6n")
                            {
                                if let Ok(mut writer) = reader_writer.lock() {
                                    let _ = writer.write_all(b"\x1b[1;1R");
                                    let _ = writer.flush();
                                }
                            }
                            if let Ok(mut output) = reader_output.lock() {
                                output.push(&buffer[..count]);
                            }
                        }
                    }
                }
            })
            .context("无法启动 PTY 读取线程")?;

        let session_id = Uuid::new_v4();
        self.sessions.lock().map_err(lock_error)?.insert(
            session_id,
            Arc::new(TerminalSession {
                _master: Mutex::new(pair.master),
                writer,
                child: Mutex::new(child),
                output,
                secrets: Mutex::new(Vec::new()),
            }),
        );
        Ok(TerminalOpenResult {
            session_id,
            executable,
        })
    }

    pub fn input(&self, session_id: Uuid, text: &str) -> Result<()> {
        if text.len() > MAX_INPUT || text.contains('\0') {
            bail!("终端输入过长或包含空字符");
        }
        let session = self.session(session_id)?;
        let mut writer = session.writer.lock().map_err(lock_error)?;
        writer
            .write_all(text.as_bytes())
            .context("无法写入终端会话")?;
        writer.flush().context("无法刷新终端输入")
    }

    pub fn fill_value(&self, session_id: Uuid, value: &str) -> Result<()> {
        let session = self.session(session_id)?;
        if value.len() > MAX_INPUT || value.contains('\0') {
            bail!("秘密字段过长或包含空字符，无法写入终端");
        }
        {
            let mut secrets = session.secrets.lock().map_err(lock_error)?;
            if !secrets.iter().any(|secret| secret == value) {
                secrets.push(value.to_owned());
            }
        }
        let mut writer = session.writer.lock().map_err(lock_error)?;
        writer
            .write_all(value.as_bytes())
            .context("无法将凭据写入终端")?;
        writer.flush().context("无法刷新终端凭据")
    }

    pub fn read(&self, session_id: Uuid) -> Result<TerminalReadResult> {
        let session = self.session(session_id)?;
        let status = session
            .child
            .lock()
            .map_err(lock_error)?
            .try_wait()
            .context("无法读取终端进程状态")?;
        let secrets = session.secrets.lock().map_err(lock_error)?.clone();
        let candidates = redaction_candidates(&secrets);
        let (output, truncated) = session
            .output
            .lock()
            .map_err(lock_error)?
            .take_redacted(&candidates, status.is_none());
        Ok(TerminalReadResult {
            output,
            running: status.is_none(),
            exit_code: status.map(|status| status.exit_code()),
            truncated,
        })
    }

    pub fn close(&self, session_id: Uuid) -> Result<()> {
        let session = self
            .sessions
            .lock()
            .map_err(lock_error)?
            .remove(&session_id)
            .context("找不到终端会话")?;
        let mut child = session.child.lock().map_err(lock_error)?;
        if child.try_wait()?.is_none() {
            child.kill().context("无法终止终端进程")?;
        }
        Ok(())
    }

    fn session(&self, id: Uuid) -> Result<Arc<TerminalSession>> {
        self.sessions
            .lock()
            .map_err(lock_error)?
            .get(&id)
            .cloned()
            .context("找不到终端会话；会话只在创建它的 MCP 连接中有效")
    }
}

fn normalize_cwd(cwd: Option<String>) -> Result<Option<PathBuf>> {
    let Some(cwd) = cwd.filter(|value| !value.trim().is_empty()) else {
        return Ok(None);
    };
    let cwd = PathBuf::from(cwd.trim());
    if !cwd.is_absolute() || !cwd.is_dir() {
        bail!("终端工作目录必须是存在的绝对路径");
    }
    Ok(Some(cwd))
}

fn resolve_executable(program: &str, cwd: Option<&Path>) -> Result<String> {
    let path = PathBuf::from(program);
    let has_path = path.is_absolute()
        || path.components().count() > 1
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)));
    let candidate = if has_path {
        if path.is_absolute() {
            path
        } else {
            cwd.unwrap_or_else(|| Path::new(".")).join(path)
        }
    } else {
        find_on_path(program).context("找不到要运行的程序")?
    };
    if !candidate.is_file() {
        bail!("要运行的程序不存在");
    }
    Ok(std::fs::canonicalize(&candidate)
        .unwrap_or(candidate)
        .to_string_lossy()
        .into_owned())
}

fn find_on_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let extensions = executable_extensions(program);
    for directory in std::env::split_paths(&path) {
        for extension in &extensions {
            let candidate = directory.join(format!("{program}{extension}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(windows)]
fn executable_extensions(program: &str) -> Vec<String> {
    if Path::new(program).extension().is_some() {
        return vec![String::new()];
    }
    std::env::var_os("PATHEXT")
        .map(|value| {
            value
                .to_string_lossy()
                .split(';')
                .filter(|value| !value.is_empty())
                .map(|value| value.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_else(|| vec![".exe".into(), ".com".into()])
}

#[cfg(not(windows))]
fn executable_extensions(_program: &str) -> Vec<String> {
    vec![String::new()]
}

#[cfg(windows)]
fn safe_environment_names() -> &'static [&'static str] {
    &[
        "PATH",
        "PATHEXT",
        "COMSPEC",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
    ]
}

#[cfg(not(windows))]
fn safe_environment_names() -> &'static [&'static str] {
    &[
        "PATH",
        "HOME",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "XDG_CONFIG_HOME",
    ]
}

fn lock_error<T>(error: std::sync::PoisonError<T>) -> anyhow::Error {
    anyhow::anyhow!("终端会话锁损坏：{error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_redaction_holds_a_secret_split_across_reads() {
        let candidates = redaction_candidates(&["top-secret".to_owned()]);
        let mut output = OutputBuffer::default();
        output.push(b"prompt top-");
        let (first, _) = output.take_redacted(&candidates, true);
        assert_eq!(first, "prompt ");

        output.push(b"secret accepted\r\n");
        let (second, _) = output.take_redacted(&candidates, true);
        assert_eq!(second, "[REDACTED] accepted\r\n");
    }

    #[test]
    fn terminal_fill_writes_no_newline_and_redacts_echoed_secret() {
        let manager = TerminalManager::new();
        #[cfg(windows)]
        let (program, args) = (
            "cmd.exe".to_owned(),
            vec![
                "/d".into(),
                "/q".into(),
                "/v:on".into(),
                "/c".into(),
                "set /p VAULT_INPUT=PASSWORD READY: & echo received=!VAULT_INPUT!".into(),
            ],
        );
        #[cfg(not(windows))]
        let (program, args) = (
            "sh".to_owned(),
            vec![
                "-c".into(),
                "printf 'PASSWORD READY: '; read VAULT_INPUT; printf 'received=%s\\n' \"$VAULT_INPUT\""
                    .into(),
            ],
        );
        let session = manager.open(&program, args, None).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let initial = manager.read(session.session_id).unwrap();
        assert!(initial.running);
        manager
            .fill_value(session.session_id, "pty-secret-marker-64928")
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(80));
        assert!(
            manager.read(session.session_id).unwrap().running,
            "secret_fill must not submit the prompt"
        );
        manager
            .input(
                session.session_id,
                if cfg!(windows) { "\r\n" } else { "\n" },
            )
            .unwrap();

        let mut combined = initial.output;
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(40));
            let result = manager.read(session.session_id).unwrap();
            combined.push_str(&result.output);
            if !result.running {
                break;
            }
        }
        assert!(
            combined.contains("PASSWORD READY"),
            "PTY output did not contain the prompt: {combined:?}"
        );
        assert!(
            combined.contains("received=[REDACTED]"),
            "PTY output did not contain the redacted echo: {combined:?}"
        );
        assert!(!combined.contains("pty-secret-marker-64928"));
        manager.close(session.session_id).unwrap();
    }
}

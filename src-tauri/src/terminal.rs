use crate::policy::redaction_candidates;
use anyhow::{Context, Result, bail};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use schemars::JsonSchema;
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use uuid::Uuid;

const MAX_SESSIONS: usize = 8;
const MAX_OUTPUT: usize = 200_000;
const MAX_INPUT: usize = 64_000;

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TerminalOpenResult {
    #[schemars(with = "String")]
    pub session_id: Uuid,
    pub executable: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
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
    master: Mutex<Option<Box<dyn MasterPty + Send>>>,
    writer: Arc<Mutex<Option<Box<dyn Write + Send>>>>,
    child: Mutex<Box<dyn Child + Send + Sync>>,
    output: Arc<Mutex<OutputBuffer>>,
    secrets: Mutex<Vec<String>>,
    created_at: Instant,
    reader_done: Arc<AtomicBool>,
}

impl TerminalSession {
    fn close_pty_io(&self) {
        if let Ok(mut writer) = self.writer.lock() {
            writer.take();
        }
        if let Ok(mut master) = self.master.lock() {
            master.take();
        }
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        if let Ok(child) = self.child.get_mut() {
            let _ = child.kill();
        }
        if let Ok(mut writer) = self.writer.lock() {
            writer.take();
        }
        if let Ok(master) = self.master.get_mut() {
            master.take();
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
        let resolved = resolve_executable(program.trim(), cwd.as_deref())?;
        {
            let sessions = self.sessions.lock().map_err(lock_error)?;
            if sessions.len() >= MAX_SESSIONS {
                drop(sessions);
                // Only reclaim at the hard cap. A process exit can race with the
                // PTY reader's final write, so a session is not eligible until
                // that reader has also finished.
                self.reap_finished_session()?;
                if self.sessions.lock().map_err(lock_error)?.len() >= MAX_SESSIONS {
                    bail!("同时最多打开 {MAX_SESSIONS} 个终端会话");
                }
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
        let mut command = CommandBuilder::new(&resolved.executable);
        command.args(resolved.prefix_args);
        command.args(args);
        command.env_clear();
        for name in safe_environment_names() {
            #[cfg(windows)]
            if name.eq_ignore_ascii_case("PSModulePath")
                && is_windows_powershell(&resolved.executable)
            {
                // PowerShell 5.1 builds its own Windows module path when this
                // variable is absent. Forwarding a path inherited from pwsh 7
                // makes it load incompatible type data and breaks even built-in
                // commands such as Get-ExecutionPolicy.
                continue;
            }
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        #[cfg(not(windows))]
        command.env("TERM", "xterm-256color");
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
        let writer = Arc::new(Mutex::new(Some(
            pair.master.take_writer().context("无法写入 PTY")?,
        )));
        let output = Arc::new(Mutex::new(OutputBuffer::default()));
        let reader_output = output.clone();
        let reader_writer = writer.clone();
        let reader_done = Arc::new(AtomicBool::new(false));
        let reader_done_signal = reader_done.clone();
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
                                if let Ok(mut writer) = reader_writer.lock()
                                    && let Some(writer) = writer.as_mut()
                                {
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
                reader_done_signal.store(true, Ordering::Release);
            })
            .context("无法启动 PTY 读取线程")?;

        let session_id = Uuid::new_v4();
        self.sessions.lock().map_err(lock_error)?.insert(
            session_id,
            Arc::new(TerminalSession {
                master: Mutex::new(Some(pair.master)),
                writer,
                child: Mutex::new(child),
                output,
                secrets: Mutex::new(Vec::new()),
                created_at: Instant::now(),
                reader_done,
            }),
        );
        Ok(TerminalOpenResult {
            session_id,
            executable: resolved.executable,
        })
    }

    pub fn input(&self, session_id: Uuid, text: &str) -> Result<()> {
        if text.len() > MAX_INPUT || text.contains('\0') {
            bail!("终端输入过长或包含空字符");
        }
        let session = self.session(session_id)?;
        let mut writer = session.writer.lock().map_err(lock_error)?;
        let writer = writer.as_mut().context("终端会话已经结束")?;
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
        let writer = writer.as_mut().context("终端会话已经结束")?;
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
        if status.is_some() {
            session.close_pty_io();
        }
        let running = status.is_none() || !session.reader_done.load(Ordering::Acquire);
        let secrets = session.secrets.lock().map_err(lock_error)?.clone();
        let candidates = redaction_candidates(&secrets);
        let (output, truncated) = session
            .output
            .lock()
            .map_err(lock_error)?
            .take_redacted(&candidates, running);
        Ok(TerminalReadResult {
            output,
            running,
            exit_code: (!running)
                .then(|| status.as_ref().map(|status| status.exit_code()))
                .flatten(),
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
        drop(child);
        session.close_pty_io();
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

    fn reap_finished_session(&self) -> Result<()> {
        let mut sessions = self.sessions.lock().map_err(lock_error)?;
        let mut exited_sessions = Vec::new();
        for (id, session) in sessions.iter() {
            let exited = session
                .child
                .lock()
                .map_err(lock_error)?
                .try_wait()
                .context("无法回收已结束的终端会话")?
                .is_some();
            if exited {
                session.close_pty_io();
                exited_sessions.push((*id, session.clone()));
            }
        }

        // Closing the final PTY handles releases a blocked reader. Give it a
        // short bounded window to flush the last bytes before choosing a victim.
        let reader_deadline = Instant::now() + std::time::Duration::from_millis(50);
        while !exited_sessions.is_empty()
            && !exited_sessions
                .iter()
                .any(|(_, session)| session.reader_done.load(Ordering::Acquire))
            && Instant::now() < reader_deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        let mut oldest_drained = None;
        let mut oldest_unread = None;
        for (id, session) in exited_sessions {
            if !session.reader_done.load(Ordering::Acquire) {
                continue;
            }
            if session.output.lock().map_err(lock_error)?.bytes.is_empty() {
                if oldest_drained.is_none_or(|(_, created_at)| session.created_at < created_at) {
                    oldest_drained = Some((id, session.created_at));
                }
            } else if oldest_unread.is_none_or(|(_, created_at)| session.created_at < created_at) {
                oldest_unread = Some((id, session.created_at));
            }
        }
        if let Some((id, _)) = oldest_drained.or(oldest_unread) {
            sessions.remove(&id);
        }
        Ok(())
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

struct ResolvedExecutable {
    executable: String,
    prefix_args: Vec<String>,
}

fn resolve_executable(program: &str, cwd: Option<&Path>) -> Result<ResolvedExecutable> {
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
    let candidate = std::fs::canonicalize(&candidate).unwrap_or(candidate);
    #[cfg(windows)]
    if let Some(extension) = candidate.extension().and_then(|value| value.to_str()) {
        if extension.eq_ignore_ascii_case("cmd") {
            return resolve_npm_cmd_shim(&candidate);
        }
        if extension.eq_ignore_ascii_case("bat") {
            bail!(
                "Windows .bat 不能安全地直接用于托管终端；请使用原生可执行文件或标准 npm .cmd 启动器"
            );
        }
    }
    #[cfg(windows)]
    let executable = windows_argument_path(&candidate);
    #[cfg(not(windows))]
    let executable = candidate.to_string_lossy().into_owned();
    Ok(ResolvedExecutable {
        // `canonicalize` is still used above to resolve and validate the actual
        // file. Windows commonly returns its verbatim `\\?\` form, however,
        // and passing that spelling to a child changes PowerShell 5.1's PSHOME
        // and built-in module paths. Use the equivalent ordinary absolute path
        // for CreateProcess while retaining the canonical path for checks.
        executable,
        prefix_args: Vec::new(),
    })
}

#[cfg(windows)]
fn resolve_npm_cmd_shim(shim: &Path) -> Result<ResolvedExecutable> {
    let text = std::fs::read_to_string(shim).context("无法读取 Windows .cmd 启动器")?;
    let pattern = regex::Regex::new(r#"(?i)%dp0%\\([^\"\r\n]+\.(?:c?js|mjs))"#)?;
    let relative = pattern
        .captures(&text)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().replace('\\', "/"))
        .context(
            "该 .cmd 不是受支持的标准 npm 启动器；请改用原生可执行文件，避免通过 Shell 运行任意脚本",
        )?;
    let root = shim.parent().context("npm 启动器目录无效")?;
    let target = std::fs::canonicalize(root.join(relative))
        .context("npm 启动器指向的 JavaScript 文件不存在")?;
    let node_modules = std::fs::canonicalize(root.join("node_modules"))
        .context("npm 启动器缺少 node_modules 目录")?;
    if !target.starts_with(&node_modules) || !target.is_file() {
        bail!("npm 启动器目标不在受信任的 node_modules 中");
    }
    let adjacent_node = root.join("node.exe");
    let node = if adjacent_node.is_file() {
        std::fs::canonicalize(adjacent_node).context("无法解析 npm 启动器旁的 node.exe")?
    } else {
        find_native_windows_executable("node").context("找不到 node.exe，无法安全运行 npm CLI")?
    };
    Ok(ResolvedExecutable {
        executable: windows_argument_path(&node),
        // Node treats Win32's `\\?\` canonical-path prefix as a module name and
        // resolves it incorrectly. Keep the canonical path for the trust check,
        // but pass the equivalent ordinary absolute path as argv.
        prefix_args: vec![windows_argument_path(&target)],
    })
}

#[cfg(windows)]
fn windows_argument_path(path: &Path) -> String {
    let path = path.to_string_lossy();
    if let Some(path) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{path}")
    } else {
        path.strip_prefix(r"\\?\").unwrap_or(&path).to_owned()
    }
}

#[cfg(windows)]
fn is_windows_powershell(executable: &str) -> bool {
    Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("powershell.exe"))
}

#[cfg(windows)]
fn find_native_windows_executable(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .flat_map(|directory| {
            [".exe", ".com"]
                .into_iter()
                .map(move |extension| directory.join(format!("{program}{extension}")))
        })
        .find(|candidate| candidate.is_file())
        .and_then(|candidate| std::fs::canonicalize(&candidate).ok().or(Some(candidate)))
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
        // PowerShell 7 derives its built-in module search path from this value.
        "PSModulePath",
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
    use std::time::{Duration, Instant};

    fn read_until(
        manager: &TerminalManager,
        session_id: Uuid,
        output: &mut String,
        timeout: Duration,
        ready: impl Fn(&str, &TerminalReadResult) -> bool,
    ) -> TerminalReadResult {
        let deadline = Instant::now() + timeout;
        loop {
            let result = manager.read(session_id).unwrap();
            output.push_str(&result.output);
            if ready(output, &result) {
                return result;
            }
            assert!(
                Instant::now() < deadline,
                "PTY readiness timed out: {output:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_exit_with_unread_output(
        manager: &TerminalManager,
        session_id: Uuid,
        timeout: Duration,
    ) {
        let session = manager.session(session_id).unwrap();
        let deadline = Instant::now() + timeout;
        loop {
            let exited = session.child.lock().unwrap().try_wait().unwrap().is_some();
            if exited {
                session.close_pty_io();
            }
            let has_output = !session.output.lock().unwrap().bytes.is_empty();
            if exited && has_output && session.reader_done.load(Ordering::Acquire) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "PTY did not exit with buffered output before timeout"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn output_command(marker: &str) -> (String, Vec<String>) {
        #[cfg(windows)]
        {
            (
                "cmd.exe".to_owned(),
                vec![
                    "/d".into(),
                    "/q".into(),
                    "/c".into(),
                    format!("echo {marker}"),
                ],
            )
        }
        #[cfg(not(windows))]
        {
            (
                "sh".to_owned(),
                vec!["-c".into(), format!("printf '%s' '{marker}'")],
            )
        }
    }

    fn silent_command() -> (String, Vec<String>) {
        #[cfg(windows)]
        {
            (
                "cmd.exe".to_owned(),
                vec!["/d".into(), "/q".into(), "/c".into(), "exit 0".into()],
            )
        }
        #[cfg(not(windows))]
        {
            ("sh".to_owned(), vec!["-c".into(), ":".into()])
        }
    }

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
    fn opening_below_capacity_preserves_a_finished_drained_session() {
        let manager = TerminalManager::new();
        let marker = "KRU-STALE-SESSION";
        let (program, args) = output_command(marker);
        let stale = manager.open(&program, args, None).unwrap();
        let mut output = String::new();
        read_until(
            &manager,
            stale.session_id,
            &mut output,
            Duration::from_secs(2),
            |output, result| !result.running && output.contains(marker),
        );
        // Drain any final bytes that ConPTY publishes just after process exit.
        std::thread::sleep(Duration::from_millis(30));
        let final_read = manager.read(stale.session_id).unwrap();
        assert!(!final_read.running);

        let (program, args) = silent_command();
        let replacement = manager.open(&program, args, None).unwrap();
        assert!(manager.session(stale.session_id).is_ok());
        manager.close(stale.session_id).unwrap();
        manager.close(replacement.session_id).unwrap();
    }

    #[test]
    fn opening_a_terminal_preserves_a_finished_session_with_unread_output() {
        let manager = TerminalManager::new();
        let marker = "KRU-UNREAD-SESSION";
        let (program, args) = output_command(marker);
        let unread = manager.open(&program, args, None).unwrap();
        wait_for_exit_with_unread_output(&manager, unread.session_id, Duration::from_secs(2));

        let (program, args) = silent_command();
        let replacement = manager.open(&program, args, None).unwrap();
        let result = manager.read(unread.session_id).unwrap();
        assert!(!result.running);
        assert!(
            result.output.contains(marker),
            "unexpected output: {result:?}"
        );

        manager.close(unread.session_id).unwrap();
        manager.close(replacement.session_id).unwrap();
    }

    #[test]
    fn terminal_capacity_reclaims_the_oldest_finished_unread_session() {
        let manager = TerminalManager::new();
        let mut sessions = Vec::new();
        for index in 0..MAX_SESSIONS {
            let marker = format!("KRU-FINISHED-{index}");
            let (program, args) = output_command(&marker);
            let session = manager.open(&program, args, None).unwrap();
            wait_for_exit_with_unread_output(&manager, session.session_id, Duration::from_secs(2));
            sessions.push(session.session_id);
        }

        let (program, args) = silent_command();
        let replacement = manager.open(&program, args, None).unwrap();
        assert!(manager.session(sessions[0]).is_err());
        assert!(manager.session(sessions[1]).is_ok());

        for id in sessions.into_iter().skip(1) {
            manager.close(id).unwrap();
        }
        manager.close(replacement.session_id).unwrap();
    }

    #[test]
    fn terminal_capacity_does_not_reclaim_before_the_pty_reader_finishes() {
        let manager = TerminalManager::new();
        let mut sessions = Vec::new();
        for index in 0..MAX_SESSIONS {
            let marker = format!("KRU-READER-{index}");
            let (program, args) = output_command(&marker);
            let session = manager.open(&program, args, None).unwrap();
            wait_for_exit_with_unread_output(&manager, session.session_id, Duration::from_secs(2));
            sessions.push(session.session_id);
        }
        manager
            .session(sessions[0])
            .unwrap()
            .reader_done
            .store(false, Ordering::Release);

        let (program, args) = silent_command();
        let replacement = manager.open(&program, args, None).unwrap();
        assert!(manager.session(sessions[0]).is_ok());
        assert!(manager.session(sessions[1]).is_err());

        manager.close(sessions[0]).unwrap();
        for id in sessions.into_iter().skip(2) {
            manager.close(id).unwrap();
        }
        manager.close(replacement.session_id).unwrap();
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
        let mut combined = String::new();
        let initial = read_until(
            &manager,
            session.session_id,
            &mut combined,
            Duration::from_secs(2),
            |output, _| output.contains("PASSWORD READY"),
        );
        assert!(initial.running);
        manager
            .fill_value(session.session_id, "pty-secret-marker-64928")
            .unwrap();
        let after_fill = manager.read(session.session_id).unwrap();
        combined.push_str(&after_fill.output);
        assert!(
            after_fill.running,
            "credential_fill must not submit the prompt"
        );
        manager
            .input(
                session.session_id,
                if cfg!(windows) { "\r\n" } else { "\n" },
            )
            .unwrap();
        read_until(
            &manager,
            session.session_id,
            &mut combined,
            Duration::from_secs(2),
            |output, result| !result.running && output.contains("received=[REDACTED]"),
        );
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

    #[cfg(not(windows))]
    #[test]
    fn terminal_sets_a_useful_term_after_clearing_environment() {
        let manager = TerminalManager::new();
        let session = manager
            .open(
                "sh",
                vec!["-c".into(), "printf '%s' \"$TERM\"".into()],
                None,
            )
            .unwrap();
        let mut output = String::new();
        read_until(
            &manager,
            session.session_id,
            &mut output,
            Duration::from_secs(2),
            |_, result| !result.running,
        );
        assert_eq!(output, "xterm-256color");
        manager.close(session.session_id).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn standard_npm_cmd_shim_runs_via_node_without_a_shell() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let target = root.join("node_modules").join("demo-cli").join("cli.js");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "console.log(process.argv.slice(2).join('|'))").unwrap();
        let shim = root.join("demo.cmd");
        std::fs::write(
            &shim,
            r#"@ECHO off
"%dp0%\node.exe" "%dp0%\node_modules\demo-cli\cli.js" %*"#,
        )
        .unwrap();

        let manager = TerminalManager::new();
        let session = manager
            .open(
                shim.to_str().unwrap(),
                vec!["literal with spaces".into(), "&no-shell".into()],
                None,
            )
            .unwrap();
        assert!(session.executable.ends_with("node.exe"));
        let mut output = String::new();
        read_until(
            &manager,
            session.session_id,
            &mut output,
            Duration::from_secs(5),
            |output, result| !result.running && output.contains("literal with spaces|&no-shell"),
        );
        manager.close(session.session_id).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn powershell_7_starts_with_the_sanitized_terminal_environment() {
        let manager = TerminalManager::new();
        let session = manager
            .open(
                "pwsh.exe",
                vec![
                    "-NoLogo".into(),
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-Command".into(),
                    "[Console]::Write('KRU-POWERSHELL-OK')".into(),
                ],
                None,
            )
            .unwrap();
        let mut output = String::new();
        read_until(
            &manager,
            session.session_id,
            &mut output,
            Duration::from_secs(5),
            |output, result| !result.running && output.contains("KRU-POWERSHELL-OK"),
        );
        assert!(
            !output.contains("无法启动此 shell"),
            "unexpected output: {output}"
        );
        manager.close(session.session_id).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_powershell_5_starts_with_the_sanitized_terminal_environment() {
        let powershell = PathBuf::from(std::env::var_os("SYSTEMROOT").unwrap())
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        assert!(powershell.is_file(), "Windows PowerShell 5.1 is missing");

        let manager = TerminalManager::new();
        let session = manager
            .open(
                powershell.to_str().unwrap(),
                vec![
                    "-NoLogo".into(),
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-Command".into(),
                    "$ErrorActionPreference='Stop'; try { Import-Module Microsoft.PowerShell.Security -Force; Get-ExecutionPolicy | Out-Null; [void][Net.ServicePointManager]::SecurityProtocol; [Console]::Write('KRU-WINDOWS-POWERSHELL-OK') } catch { [Console]::Write($_.Exception.ToString()) }; exit".into(),
                ],
                None,
            )
            .unwrap();
        assert!(
            !session.executable.starts_with(r"\\?\"),
            "verbatim executable path leaks into PowerShell: {}",
            session.executable
        );
        let mut output = String::new();
        read_until(
            &manager,
            session.session_id,
            &mut output,
            Duration::from_secs(10),
            |_, result| !result.running,
        );
        assert!(
            output.contains("KRU-WINDOWS-POWERSHELL-OK"),
            "Windows PowerShell did not complete its startup checks: {output}"
        );
        assert!(
            !output.contains("ServicePointManager") && !output.contains("Get-ExecutionPolicy"),
            "unexpected Windows PowerShell startup error: {output}"
        );
        manager.close(session.session_id).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn arbitrary_windows_batch_scripts_are_rejected_clearly() {
        let temp = tempfile::tempdir().unwrap();
        let batch = temp.path().join("unsafe.bat");
        std::fs::write(&batch, "@echo off\r\necho unsafe").unwrap();
        let error = resolve_executable(batch.to_str().unwrap(), None)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains(".bat"), "unexpected error: {error}");

        let command = temp.path().join("unsupported.cmd");
        std::fs::write(&command, "@echo off\r\necho unsupported").unwrap();
        let error = resolve_executable(command.to_str().unwrap(), None)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("标准 npm"), "unexpected error: {error}");
    }
}

use crate::{
    model::{SecretBundle, StoredConnection},
    policy::{
        blocked_header_names, normalize_api_request_method, redact, redirect_target_supported,
        validate_ssh_command, visible_response_headers,
    },
    storage::resolve_user_path,
    vault::{DecryptedConnection, Vault},
};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{
    Client, Method,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use russh::{
    ChannelMsg, Disconnect, client,
    keys::{PrivateKeyWithHashAlg, decode_secret_key, ssh_key},
};
use russh_sftp::{client::SftpSession, protocol::OpenFlags};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::io::AsyncWriteExt;
use url::Url;
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

// SSH `exec` carries the complete command in one protocol packet. Keep direct
// requests comfortably below the usual 32 KiB packet limit and stream larger
// commands to the account's configured remote shell instead.
const MAX_DIRECT_SSH_COMMAND_LENGTH: usize = 16_384;

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiRequestInput {
    #[schemars(
        description = "Absolute request URL, saved-service-relative path, or empty to use the saved service URL."
    )]
    pub url: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub query: HashMap<String, Value>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<Value>,
    #[serde(default)]
    pub form: HashMap<String, Value>,
    #[serde(default)]
    pub files: Vec<ApiUploadFile>,
    #[serde(default)]
    pub body_base64: Option<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub max_response_bytes: Option<usize>,
    #[serde(default)]
    pub save_response_to: Option<String>,
    #[serde(default)]
    pub overwrite_response_file: bool,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApiUploadFile {
    pub field: String,
    #[schemars(
        description = "Local file path. Absolute and ~/ paths are accepted; relative paths resolve from the KRU MCP process working directory."
    )]
    pub path: String,
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
}

fn default_method() -> String {
    "GET".to_owned()
}

pub fn describe_api_request(connection: &StoredConnection, input: &ApiRequestInput) -> String {
    let method = input.method.trim().to_ascii_uppercase();
    let method = if method.is_empty()
        || method.len() > 20
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
    {
        "REQUEST".to_owned()
    } else {
        method
    };
    let Ok(target) = build_api_url(connection, &input.url, &input.query) else {
        return format!("API {method}");
    };
    let origin = target.origin().ascii_serialization();
    let mut path = target.path().to_owned();
    if path.len() > 160 {
        let boundary = path
            .char_indices()
            .map(|(index, _)| index)
            .take_while(|index| *index <= 157)
            .last()
            .unwrap_or(0);
        path.truncate(boundary);
        path.push_str("...");
    }
    format!("API {method} {origin}{path}")
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiResponse {
    pub status: u16,
    pub status_text: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_transferred: Option<u64>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshResponse {
    pub exit_code: Option<u32>,
    pub signal: Option<String>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SshTransferResponse {
    pub direction: String,
    pub kind: String,
    pub local_path: String,
    pub remote_path: String,
    pub bytes_transferred: u64,
    pub files_transferred: u64,
    pub directories_transferred: u64,
}

#[derive(Debug, Default)]
struct TransferStats {
    bytes: u64,
    files: u64,
    directories: u64,
}

pub async fn execute_api(
    connection: &DecryptedConnection,
    input: ApiRequestInput,
) -> Result<ApiResponse> {
    if !connection.stored.enabled {
        bail!("该连接已禁用");
    }
    let mut target = build_api_url(&connection.stored, &input.url, &input.query)?;
    let save_response_to = match input.save_response_to {
        Some(path) => {
            Some(prepare_api_response_destination(&path, input.overwrite_response_file).await?)
        }
        None => None,
    };
    let overwrite_response_file = input.overwrite_response_file;
    let method = normalize_api_request_method(&input.method, &target)?;
    let method = Method::from_bytes(method.as_bytes()).context("HTTP 方法无效")?;
    let blocked = blocked_header_names(&connection.stored);
    let mut headers = HeaderMap::new();
    for (name, value) in input.headers {
        if blocked.contains(&name.to_lowercase()) {
            continue;
        }
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).context("请求头名称无效")?,
            HeaderValue::from_str(&value).context("请求头内容无效")?,
        );
    }
    apply_api_auth(
        &connection.stored,
        &connection.secrets,
        &mut headers,
        &mut target,
    )?;

    let response_limit = input.max_response_bytes.filter(|limit| *limit > 0);
    let mut client_builder =
        Client::builder().redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if redirect_target_supported(attempt.url()) {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }));
    if let Some(seconds) = input.timeout_seconds.filter(|seconds| *seconds > 0) {
        client_builder = client_builder.timeout(Duration::from_secs(seconds));
    }
    let client = client_builder.build()?;
    let mut request = client
        .request(method.clone(), target.clone())
        .headers(headers);
    let body_kinds = usize::from(input.body.is_some())
        + usize::from(!input.form.is_empty() || !input.files.is_empty())
        + usize::from(input.body_base64.is_some());
    if body_kinds > 1 {
        bail!("body、form/files 与 bodyBase64 只能选择一种请求正文格式");
    }
    if !input.files.is_empty() {
        let mut multipart = reqwest::multipart::Form::new();
        for (name, value) in input.form {
            for value in form_values(value) {
                multipart = multipart.text(name.clone(), value);
            }
        }
        for file in input.files {
            let field = file.field.trim();
            if field.is_empty() {
                bail!("上传文件的字段名不能为空");
            }
            let path = resolve_user_path(&file.path)?;
            if !tokio::fs::metadata(&path)
                .await
                .context("无法读取上传文件")?
                .is_file()
            {
                bail!("上传路径不是普通文件");
            }
            let mut part = reqwest::multipart::Part::file(&path)
                .await
                .context("无法打开上传文件")?;
            if let Some(file_name) = file.file_name.filter(|value| !value.trim().is_empty()) {
                part = part.file_name(file_name);
            }
            if let Some(content_type) = file.content_type.filter(|value| !value.trim().is_empty()) {
                part = part
                    .mime_str(content_type.trim())
                    .context("上传文件 Content-Type 无效")?;
            }
            multipart = multipart.part(field.to_owned(), part);
        }
        request = request.multipart(multipart);
    } else if !input.form.is_empty() {
        let mut form = Vec::new();
        for (name, value) in input.form {
            for value in form_values(value) {
                form.push((name.clone(), value));
            }
        }
        request = request.form(&form);
    } else if let Some(body_base64) = input.body_base64 {
        let bytes = STANDARD
            .decode(body_base64.trim())
            .context("bodyBase64 不是有效的 Base64")?;
        request = request.body(bytes);
    } else if let Some(body) = input.body {
        if let Some(text) = body.as_str() {
            request = request.body(text.to_owned());
        } else {
            request = request.json(&body);
        }
    }

    let mut response = request
        .send()
        .await
        .map_err(|error| anyhow::anyhow!(api_request_error_message(&error)))?;
    let status = response.status();
    let response_url = response.url().clone();
    let response_headers = visible_response_headers(response.headers())
        .into_iter()
        .map(|(name, value)| (name, redact(value, &connection.stored, &connection.secrets)))
        .collect();
    if let Some(destination) = save_response_to {
        let (saved_to, bytes_transferred) =
            save_api_response_to_file(&mut response, &destination, overwrite_response_file).await?;
        return Ok(ApiResponse {
            status: status.as_u16(),
            status_text: status.canonical_reason().unwrap_or_default().to_owned(),
            url: redact(
                response_url.to_string(),
                &connection.stored,
                &connection.secrets,
            ),
            headers: response_headers,
            body: String::new(),
            truncated: false,
            saved_to: Some(saved_to),
            bytes_transferred: Some(bytes_transferred),
        });
    }
    let mut bytes = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = response.chunk().await.context("无法读取 API 响应")? {
        if let Some(limit) = response_limit {
            let remaining = limit.saturating_sub(bytes.len());
            if remaining == 0 {
                truncated = !chunk.is_empty();
                break;
            }
            bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
            if chunk.len() > remaining {
                truncated = true;
                break;
            }
        } else {
            bytes.extend_from_slice(&chunk);
        }
    }
    let body = sanitize_api_body(
        String::from_utf8_lossy(&bytes).into_owned(),
        truncated,
        &connection.stored,
        &connection.secrets,
    );
    Ok(ApiResponse {
        status: status.as_u16(),
        status_text: status.canonical_reason().unwrap_or_default().to_owned(),
        url: redact(
            response_url.to_string(),
            &connection.stored,
            &connection.secrets,
        ),
        headers: response_headers,
        body,
        truncated,
        saved_to: None,
        bytes_transferred: None,
    })
}

async fn prepare_api_response_destination(
    destination: &str,
    overwrite: bool,
) -> Result<std::path::PathBuf> {
    let destination = destination.trim();
    if destination.is_empty() || destination.contains('\0') {
        bail!("API 响应保存路径无效");
    }
    let destination = resolve_user_path(destination)?;
    if let Some(parent) = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent)
            .await
            .context("无法创建 API 响应目标目录")?;
    }
    if tokio::fs::try_exists(&destination).await? {
        if !tokio::fs::symlink_metadata(&destination)
            .await?
            .file_type()
            .is_file()
        {
            bail!("API 响应目标已存在但不是普通文件，拒绝覆盖");
        }
        if !overwrite {
            bail!("API 响应目标文件已存在；如需替换，请明确设置 overwriteResponseFile=true");
        }
    }
    Ok(destination)
}

async fn save_api_response_to_file(
    response: &mut reqwest::Response,
    destination: &std::path::Path,
    overwrite: bool,
) -> Result<(String, u64)> {
    if !overwrite && tokio::fs::try_exists(&destination).await? {
        bail!("API 响应目标文件已存在；如需替换，请明确设置 overwriteResponseFile=true");
    }
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("response");
    let temporary_path =
        destination.with_file_name(format!(".{file_name}.kru-{}.part", Uuid::new_v4().simple()));
    let write_result: Result<u64> = async {
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .await
            .context("无法创建 API 响应临时文件")?;
        let mut bytes_transferred = 0_u64;
        while let Some(chunk) = response.chunk().await.context("无法读取 API 响应")? {
            file.write_all(&chunk)
                .await
                .context("无法写入 API 响应文件")?;
            bytes_transferred = bytes_transferred
                .checked_add(chunk.len() as u64)
                .context("API 响应文件过大")?;
        }
        file.flush().await.context("无法刷新 API 响应文件")?;
        file.sync_all().await.context("无法同步 API 响应文件")?;
        commit_local_file(&temporary_path, destination, overwrite).await?;
        Ok(bytes_transferred)
    }
    .await;
    let bytes_transferred = match write_result {
        Ok(bytes) => bytes,
        Err(error) => {
            let _ = tokio::fs::remove_file(&temporary_path).await;
            return Err(error);
        }
    };
    let saved_to = tokio::fs::canonicalize(destination)
        .await
        .unwrap_or_else(|_| destination.to_path_buf())
        .to_string_lossy()
        .into_owned();
    Ok((saved_to, bytes_transferred))
}

pub async fn execute_ssh(
    vault: &Vault,
    connection: &DecryptedConnection,
    command: &str,
    cwd: Option<&str>,
    timeout_seconds: Option<u64>,
    secret_env: &HashMap<String, String>,
    stdin: Option<&str>,
) -> Result<SshResponse> {
    if !connection.stored.enabled {
        bail!("该连接已禁用");
    }
    let command = validate_ssh_command(command)?;
    let command = ssh_command_with_secret_environment(&command, secret_env)?;
    let command = match cwd.map(str::trim).filter(|value| !value.is_empty()) {
        Some(cwd) => format!("cd -- {} && {command}", shell_quote(cwd)),
        None => command,
    };
    let command = validate_ssh_command(&command)?;
    let execution = execute_ssh_inner(vault, connection, &command, stdin);
    match timeout_seconds.filter(|seconds| *seconds > 0) {
        Some(seconds) => tokio::time::timeout(Duration::from_secs(seconds), execution)
            .await
            .map_err(|_| anyhow::anyhow!("SSH 命令执行超过调用方设置的 {seconds} 秒超时"))?,
        None => execution.await,
    }
}

pub async fn execute_local(
    connection: Option<&DecryptedConnection>,
    command: &str,
    cwd: Option<&str>,
    timeout_seconds: Option<u64>,
    secret_env: &HashMap<String, String>,
    stdin: Option<&str>,
) -> Result<SshResponse> {
    let command = command.trim();
    if command.is_empty() || command.contains('\0') {
        bail!("本地命令不能为空或包含空字符");
    }
    if connection.is_some_and(|connection| !connection.stored.enabled) {
        bail!("该连接已禁用");
    }

    #[cfg(windows)]
    let mut process = {
        let mut process = tokio::process::Command::new("powershell.exe");
        process.args(["-NoProfile", "-NonInteractive", "-Command", command]);
        process
    };
    #[cfg(not(windows))]
    let mut process = {
        let shell = std::env::var("SHELL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "/bin/sh".to_owned());
        let mut process = tokio::process::Command::new(shell);
        process.args(["-lc", command]);
        process
    };

    if let Some(cwd) = cwd.map(str::trim).filter(|value| !value.is_empty()) {
        let cwd = resolve_user_path(cwd)?;
        if !cwd.is_dir() {
            bail!("本地命令工作目录不存在或不是目录");
        }
        process.current_dir(cwd);
    }
    for (name, value) in secret_env {
        if !valid_environment_name(name) {
            bail!("terminal_run secretEnv 环境变量名称无效：{name}");
        }
        if value.contains('\0') {
            bail!("该秘密模块不能作为本地环境变量使用");
        }
        process.env(name, value);
    }
    process
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let stdin = stdin.map(str::as_bytes).map(<[u8]>::to_vec);
    let execution = async {
        let mut child = process.spawn().context("无法启动本地命令")?;
        let input_task = if let Some(input) = stdin {
            let mut child_stdin = child.stdin.take().context("无法打开本地命令标准输入")?;
            Some(tokio::spawn(async move {
                child_stdin.write_all(&input).await?;
                child_stdin.shutdown().await
            }))
        } else {
            None
        };
        let output = child.wait_with_output().await.context("无法等待本地命令")?;
        if let Some(task) = input_task {
            task.await.context("本地命令标准输入任务异常结束")??;
        }
        Ok::<_, anyhow::Error>(output)
    };
    let output = match timeout_seconds.filter(|seconds| *seconds > 0) {
        Some(seconds) => tokio::time::timeout(Duration::from_secs(seconds), execution)
            .await
            .map_err(|_| anyhow::anyhow!("本地命令超过调用方设置的 {seconds} 秒超时"))??,
        None => execution.await?,
    };
    let mut stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let mut stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if let Some(connection) = connection {
        stdout = redact(stdout, &connection.stored, &connection.secrets);
        stderr = redact(stderr, &connection.stored, &connection.secrets);
    }
    #[cfg(unix)]
    let signal = output.status.signal().map(|signal| signal.to_string());
    #[cfg(not(unix))]
    let signal = None;
    Ok(SshResponse {
        exit_code: output.status.code().map(|code| code as u32),
        signal,
        stdout,
        stderr,
        stdout_truncated: false,
        stderr_truncated: false,
    })
}

fn ssh_command_with_secret_environment(
    command: &str,
    secret_env: &HashMap<String, String>,
) -> Result<String> {
    if secret_env.is_empty() {
        return Ok(command.to_owned());
    }
    let mut variables = secret_env.iter().collect::<Vec<_>>();
    variables.sort_by(|left, right| left.0.cmp(right.0));
    let mut assignments = Vec::with_capacity(variables.len());
    for (name, value) in variables {
        if !valid_environment_name(name) {
            bail!("SSH secretEnv 环境变量名称无效：{name}");
        }
        if value.contains('\0') {
            bail!("该秘密模块不能作为 SSH 环境变量使用");
        }
        assignments.push(format!("{name}={}", shell_quote(value)));
    }
    Ok(format!(
        "{} sh -c {}",
        assignments.join(" "),
        shell_quote(command)
    ))
}

fn valid_environment_name(name: &str) -> bool {
    let mut characters = name.chars();
    matches!(characters.next(), Some('_' | 'a'..='z' | 'A'..='Z'))
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

async fn execute_ssh_inner(
    vault: &Vault,
    connection: &DecryptedConnection,
    command: &str,
    stdin: Option<&str>,
) -> Result<SshResponse> {
    let session = connect_ssh(vault, connection).await?;
    let channel = session.channel_open_session().await?;
    let send_task;
    let mut reader;
    if command.len() <= MAX_DIRECT_SSH_COMMAND_LENGTH || stdin.is_some() {
        channel.exec(true, command).await?;
        let (read_half, write_half) = channel.split();
        reader = read_half;
        send_task = stdin.map(|stdin| {
            let input = stdin.as_bytes().to_vec();
            tokio::spawn(async move {
                write_half.data_bytes(input).await?;
                write_half.eof().await
            })
        });
    } else {
        // A shell channel invokes the account's configured shell, so the same
        // path works for POSIX shells and Windows OpenSSH targets.
        channel.request_shell(true).await?;
        let mut script = Vec::with_capacity(command.len() + 1);
        script.extend_from_slice(command.as_bytes());
        script.push(b'\n');
        let (read_half, write_half) = channel.split();
        reader = read_half;
        send_task = Some(tokio::spawn(async move {
            write_half.data_bytes(script).await?;
            write_half.eof().await
        }));
    }
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code = None;
    let mut signal = None;
    while let Some(message) = reader.wait().await {
        match message {
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status),
            ChannelMsg::ExitSignal { signal_name, .. } => signal = Some(format!("{signal_name:?}")),
            _ => {}
        }
    }
    if let Some(task) = send_task {
        task.await.context("SSH 长命令发送任务异常结束")??;
    }
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "en")
        .await;
    let stdout = redact(
        String::from_utf8_lossy(&stdout).into_owned(),
        &connection.stored,
        &connection.secrets,
    );
    let stderr = redact(
        String::from_utf8_lossy(&stderr).into_owned(),
        &connection.stored,
        &connection.secrets,
    );
    Ok(SshResponse {
        exit_code,
        signal,
        stdout,
        stderr,
        stdout_truncated: false,
        stderr_truncated: false,
    })
}

async fn connect_ssh(
    _vault: &Vault,
    connection: &DecryptedConnection,
) -> Result<client::Handle<SshClient>> {
    let handler = SshClient;
    let mut session = client::connect(
        Arc::new(client::Config::default()),
        (connection.stored.host.as_str(), connection.stored.port),
        handler,
    )
    .await
    .map_err(|error| anyhow::anyhow!(ssh_connect_error_message(&error)))?;

    let ssh_auth_type = if connection.stored.ssh_auth_type.is_empty() {
        connection.stored.auth_type.as_str()
    } else {
        connection.stored.ssh_auth_type.as_str()
    };
    let auth = if ssh_auth_type == "privateKey" {
        let username = connection
            .secrets
            .get("username")
            .context("保险库中没有 SSH 用户名")?;
        let private_key = connection
            .secrets
            .private_key
            .as_deref()
            .context("保险库中没有 SSH 私钥")?;
        let key = decode_secret_key(private_key, connection.secrets.passphrase.as_deref())
            .context("无法解析 SSH 私钥或口令不正确")?;
        let hash = session.best_supported_rsa_hash().await?.flatten();
        session
            .authenticate_publickey(username, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
            .await?
    } else {
        let username = connection
            .secrets
            .get("username")
            .context("保险库中没有 SSH 用户名")?;
        session
            .authenticate_password(
                username,
                connection
                    .secrets
                    .password
                    .clone()
                    .context("保险库中没有 SSH 密码")?,
            )
            .await?
    };
    if !auth.success() {
        bail!("SSH 认证失败");
    }

    Ok(session)
}

async fn open_sftp(
    vault: &Vault,
    connection: &DecryptedConnection,
) -> Result<(client::Handle<SshClient>, SftpSession)> {
    let session = connect_ssh(vault, connection).await?;
    let channel = session.channel_open_session().await?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .context("远端没有启用 SFTP 子系统")?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .context("无法初始化 SFTP 会话")?;
    Ok((session, sftp))
}

pub async fn ssh_upload(
    vault: &Vault,
    connection: &DecryptedConnection,
    local_path: &str,
    remote_path: &str,
    overwrite: bool,
    timeout_seconds: Option<u64>,
) -> Result<SshTransferResponse> {
    if !connection.stored.enabled {
        bail!("该连接已禁用");
    }
    let local_path = local_path.trim();
    let remote_path = validate_transfer_path(remote_path, "远端路径")?;
    if local_path.is_empty() || local_path.contains('\0') {
        bail!("本地上传路径无效");
    }
    let execution = async {
        let local_path = resolve_user_path(local_path)?;
        let canonical_local = tokio::fs::canonicalize(local_path)
            .await
            .context("找不到本地上传路径")?;
        let metadata = tokio::fs::metadata(&canonical_local).await?;
        if !metadata.is_file() && !metadata.is_dir() {
            bail!("本地上传路径不是文件或目录");
        }
        let (session, sftp) = open_sftp(vault, connection).await?;
        let remote_path = resolve_remote_path(&sftp, &remote_path).await?;
        let (kind, stats) = if metadata.is_dir() {
            (
                "directory",
                upload_local_directory(&sftp, &canonical_local, &remote_path, overwrite).await?,
            )
        } else {
            (
                "file",
                upload_local_file(&sftp, &canonical_local, &remote_path, overwrite).await?,
            )
        };
        let _ = sftp.close().await;
        let _ = session
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
        Ok(SshTransferResponse {
            direction: "upload".to_owned(),
            kind: kind.to_owned(),
            local_path: canonical_local.to_string_lossy().into_owned(),
            remote_path,
            bytes_transferred: stats.bytes,
            files_transferred: stats.files,
            directories_transferred: stats.directories,
        })
    };
    run_optional_ssh_timeout(execution, timeout_seconds, "SSH 上传").await
}

pub async fn ssh_download(
    vault: &Vault,
    connection: &DecryptedConnection,
    remote_path: &str,
    local_path: &str,
    overwrite: bool,
    timeout_seconds: Option<u64>,
) -> Result<SshTransferResponse> {
    if !connection.stored.enabled {
        bail!("该连接已禁用");
    }
    let remote_path = validate_transfer_path(remote_path, "远端路径")?;
    let local_path = local_path.trim();
    if local_path.is_empty() || local_path.contains('\0') {
        bail!("本地保存路径无效");
    }
    let local_path = resolve_user_path(local_path)?;
    let execution = async {
        let (session, sftp) = open_sftp(vault, connection).await?;
        let remote_path = resolve_remote_path(&sftp, &remote_path).await?;
        let remote_metadata = sftp
            .metadata(remote_path.clone())
            .await
            .context("找不到远端下载路径")?;
        let (kind, stats) = if remote_metadata.file_type().is_dir() {
            (
                "directory",
                download_remote_directory(&sftp, &remote_path, &local_path, overwrite).await?,
            )
        } else if remote_metadata.file_type().is_file() {
            (
                "file",
                download_remote_file(&sftp, &remote_path, &local_path, overwrite).await?,
            )
        } else {
            bail!("远端下载路径不是文件或目录");
        };
        let _ = sftp.close().await;
        let _ = session
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;
        Ok(SshTransferResponse {
            direction: "download".to_owned(),
            kind: kind.to_owned(),
            local_path: tokio::fs::canonicalize(&local_path)
                .await
                .unwrap_or(local_path)
                .to_string_lossy()
                .into_owned(),
            remote_path,
            bytes_transferred: stats.bytes,
            files_transferred: stats.files,
            directories_transferred: stats.directories,
        })
    };
    run_optional_ssh_timeout(execution, timeout_seconds, "SSH 下载").await
}

async fn upload_local_file(
    sftp: &SftpSession,
    local_path: &Path,
    remote_path: &str,
    overwrite: bool,
) -> Result<TransferStats> {
    ensure_remote_parent_directories(sftp, remote_path).await?;
    if !overwrite && sftp.try_exists(remote_path.to_owned()).await? {
        bail!("远端目标已存在；如需替换，请设置 overwrite=true");
    }
    let temporary_path = format!("{remote_path}.kru-{}.part", Uuid::new_v4().simple());
    let result: Result<u64> = async {
        let mut local = tokio::fs::File::open(local_path)
            .await
            .context("无法打开本地上传文件")?;
        let mut remote = sftp
            .open_with_flags(
                temporary_path.clone(),
                OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
            )
            .await
            .context("无法创建远端临时文件")?;
        let bytes = tokio::io::copy(&mut local, &mut remote)
            .await
            .context("SFTP 上传中断")?;
        remote.flush().await.context("无法刷新远端文件")?;
        remote.shutdown().await.context("无法关闭远端文件")?;
        commit_remote_file(sftp, &temporary_path, remote_path, overwrite).await?;
        Ok(bytes)
    }
    .await;
    match result {
        Ok(bytes) => Ok(TransferStats {
            bytes,
            files: 1,
            directories: 0,
        }),
        Err(error) => {
            let _ = sftp.remove_file(temporary_path).await;
            Err(error)
        }
    }
}

async fn upload_local_directory(
    sftp: &SftpSession,
    local_root: &Path,
    remote_path: &str,
    overwrite: bool,
) -> Result<TransferStats> {
    ensure_remote_parent_directories(sftp, remote_path).await?;
    if !overwrite && sftp.try_exists(remote_path.to_owned()).await? {
        bail!("远端目标已存在；如需替换，请设置 overwrite=true");
    }
    let temporary_path = format!("{remote_path}.kru-{}.part", Uuid::new_v4().simple());
    sftp.create_dir(temporary_path.clone())
        .await
        .context("无法创建远端临时目录")?;

    let result: Result<TransferStats> = async {
        let mut stats = TransferStats {
            directories: 1,
            ..Default::default()
        };
        let mut visited = HashSet::from([tokio::fs::canonicalize(local_root).await?]);
        let mut stack = vec![(local_root.to_path_buf(), String::new())];
        while let Some((local_directory, relative_directory)) = stack.pop() {
            let mut entries = tokio::fs::read_dir(&local_directory)
                .await
                .with_context(|| format!("无法读取本地目录 {}", local_directory.display()))?;
            while let Some(entry) = entries.next_entry().await? {
                let name = entry.file_name();
                let relative_path = if relative_directory.is_empty() {
                    PathBuf::from(&name)
                } else {
                    PathBuf::from(&relative_directory).join(&name)
                };
                let relative_remote = relative_path.to_string_lossy().replace('\\', "/");
                let remote_entry = format!(
                    "{}/{}",
                    temporary_path.trim_end_matches('/'),
                    relative_remote
                );
                let entry_path = entry.path();
                let metadata = tokio::fs::metadata(&entry_path).await?;
                if metadata.is_dir() {
                    let canonical = tokio::fs::canonicalize(&entry_path).await?;
                    if !visited.insert(canonical) {
                        bail!("本地目录包含循环链接：{}", entry_path.display());
                    }
                    sftp.create_dir(remote_entry)
                        .await
                        .with_context(|| format!("无法创建远端目录 {relative_remote}"))?;
                    stats.directories += 1;
                    stack.push((entry_path, relative_remote));
                } else if metadata.is_file() {
                    let mut local = tokio::fs::File::open(&entry_path).await?;
                    let mut remote = sftp
                        .open_with_flags(
                            remote_entry,
                            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE,
                        )
                        .await?;
                    stats.bytes += tokio::io::copy(&mut local, &mut remote)
                        .await
                        .context("SFTP 目录上传中断")?;
                    remote.flush().await?;
                    remote.shutdown().await?;
                    stats.files += 1;
                } else {
                    bail!("本地目录包含无法传输的特殊文件：{}", entry_path.display());
                }
            }
        }
        commit_remote_directory(sftp, &temporary_path, remote_path, overwrite).await?;
        Ok(stats)
    }
    .await;
    if result.is_err() {
        let _ = remove_remote_tree(sftp, &temporary_path).await;
    }
    result
}

async fn download_remote_file(
    sftp: &SftpSession,
    remote_path: &str,
    local_path: &Path,
    overwrite: bool,
) -> Result<TransferStats> {
    if let Some(parent) = local_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent)
            .await
            .context("无法创建本地目标目录")?;
    }
    if !overwrite && tokio::fs::try_exists(local_path).await? {
        bail!("本地目标已存在；如需替换，请设置 overwrite=true");
    }
    let file_name = local_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    let temporary_path =
        local_path.with_file_name(format!(".{file_name}.kru-{}.part", Uuid::new_v4().simple()));
    let result: Result<u64> = async {
        let mut remote = sftp
            .open(remote_path.to_owned())
            .await
            .context("无法打开远端下载文件")?;
        let mut local = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
            .await
            .context("无法创建本地临时文件")?;
        let bytes = tokio::io::copy(&mut remote, &mut local)
            .await
            .context("SFTP 下载中断")?;
        local.flush().await.context("无法刷新本地文件")?;
        local.sync_all().await.context("无法同步本地文件")?;
        remote.shutdown().await.context("无法关闭远端文件")?;
        commit_local_file(&temporary_path, local_path, overwrite).await?;
        Ok(bytes)
    }
    .await;
    match result {
        Ok(bytes) => Ok(TransferStats {
            bytes,
            files: 1,
            directories: 0,
        }),
        Err(error) => {
            let _ = tokio::fs::remove_file(&temporary_path).await;
            Err(error)
        }
    }
}

async fn download_remote_directory(
    sftp: &SftpSession,
    remote_root: &str,
    local_path: &Path,
    overwrite: bool,
) -> Result<TransferStats> {
    if let Some(parent) = local_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent)
            .await
            .context("无法创建本地目标目录")?;
    }
    if !overwrite && tokio::fs::try_exists(local_path).await? {
        bail!("本地目标已存在；如需替换，请设置 overwrite=true");
    }
    let directory_name = local_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    let temporary_path = local_path.with_file_name(format!(
        ".{directory_name}.kru-{}.part",
        Uuid::new_v4().simple()
    ));
    tokio::fs::create_dir(&temporary_path)
        .await
        .context("无法创建本地临时目录")?;

    let result: Result<TransferStats> = async {
        let canonical_root = sftp
            .canonicalize(remote_root.to_owned())
            .await
            .unwrap_or_else(|_| remote_root.to_owned());
        let mut visited = HashSet::from([canonical_root]);
        let mut stats = TransferStats {
            directories: 1,
            ..Default::default()
        };
        let mut stack = vec![(remote_root.to_owned(), PathBuf::new())];
        while let Some((remote_directory, relative_directory)) = stack.pop() {
            let entries = sftp
                .read_dir(remote_directory.clone())
                .await
                .with_context(|| format!("无法读取远端目录 {remote_directory}"))?;
            for entry in entries {
                let name = entry.file_name();
                let relative_path = relative_directory.join(&name);
                let local_entry = temporary_path.join(&relative_path);
                let remote_entry = entry.path();
                let metadata = if entry.file_type().is_symlink() {
                    sftp.metadata(remote_entry.clone()).await?
                } else {
                    entry.metadata()
                };
                if metadata.file_type().is_dir() {
                    let canonical = sftp
                        .canonicalize(remote_entry.clone())
                        .await
                        .unwrap_or_else(|_| remote_entry.clone());
                    if !visited.insert(canonical) {
                        bail!("远端目录包含循环链接：{remote_entry}");
                    }
                    tokio::fs::create_dir(&local_entry)
                        .await
                        .with_context(|| format!("无法创建本地目录 {}", local_entry.display()))?;
                    stats.directories += 1;
                    stack.push((remote_entry, relative_path));
                } else if metadata.file_type().is_file() {
                    let mut remote = sftp.open(remote_entry.clone()).await?;
                    let mut local = tokio::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&local_entry)
                        .await?;
                    stats.bytes += tokio::io::copy(&mut remote, &mut local)
                        .await
                        .context("SFTP 目录下载中断")?;
                    local.flush().await?;
                    local.sync_all().await?;
                    remote.shutdown().await?;
                    stats.files += 1;
                } else {
                    bail!("远端目录包含无法传输的特殊文件：{remote_entry}");
                }
            }
        }
        commit_local_directory(&temporary_path, local_path, overwrite).await?;
        Ok(stats)
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_dir_all(&temporary_path).await;
    }
    result
}

async fn resolve_remote_path(sftp: &SftpSession, path: &str) -> Result<String> {
    if path.starts_with('~') {
        let (home, remainder) = path.split_once('/').unwrap_or((path, ""));
        let Some(expanded_home) = sftp
            .expand_path(home.to_owned())
            .await
            .context("无法展开远端主目录")?
        else {
            bail!("远端 SFTP 服务不支持展开 ~ 路径；请改用绝对路径");
        };
        return Ok(if remainder.is_empty() {
            expanded_home
        } else {
            format!("{}/{remainder}", expanded_home.trim_end_matches('/'))
        });
    }
    if remote_path_is_absolute(path) {
        return Ok(path.replace('\\', "/"));
    }
    let base = sftp
        .canonicalize(".")
        .await
        .context("无法解析远端当前目录")?;
    Ok(format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.replace('\\', "/").trim_start_matches('/')
    ))
}

fn remote_path_is_absolute(path: &str) -> bool {
    path.starts_with('/')
        || path.starts_with('\\')
        || path
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
}

async fn ensure_remote_parent_directories(sftp: &SftpSession, path: &str) -> Result<()> {
    for directory in remote_parent_directories(path) {
        if !sftp.try_exists(directory.clone()).await? {
            sftp.create_dir(directory.clone())
                .await
                .with_context(|| format!("无法创建远端目录 {directory}"))?;
        }
    }
    Ok(())
}

fn remote_parent_directories(path: &str) -> Vec<String> {
    let normalized = path.replace('\\', "/");
    let mut parts = normalized.split('/').collect::<Vec<_>>();
    if parts.len() < 2 {
        return Vec::new();
    }
    parts.pop();

    let absolute = normalized.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    let mut root_depth = 0;
    for part in parts {
        match part {
            "" | "." => continue,
            ".." => {
                if stack.len() > root_depth {
                    stack.pop();
                }
            }
            _ => {
                stack.push(part);
                if stack.len() == 1 && part.ends_with(':') {
                    root_depth = 1;
                }
            }
        }
    }
    (1..=stack.len())
        .map(|length| {
            let joined = stack[..length].join("/");
            if absolute {
                format!("/{joined}")
            } else {
                joined
            }
        })
        .collect()
}

async fn commit_remote_file(
    sftp: &SftpSession,
    temporary_path: &str,
    destination_path: &str,
    overwrite: bool,
) -> Result<()> {
    let destination_exists = sftp.try_exists(destination_path.to_owned()).await?;
    if !destination_exists {
        return sftp
            .rename(temporary_path.to_owned(), destination_path.to_owned())
            .await
            .context("无法完成远端文件写入");
    }
    if !overwrite {
        bail!("远端文件已存在；如需替换，请明确设置 overwrite=true");
    }
    let backup_path = format!("{destination_path}.kru-{}.backup", Uuid::new_v4().simple());
    sftp.rename(destination_path.to_owned(), backup_path.clone())
        .await
        .context("无法暂存已有远端文件，原文件未改变")?;

    if let Err(install_error) = sftp
        .rename(temporary_path.to_owned(), destination_path.to_owned())
        .await
    {
        if let Err(restore_error) = sftp
            .rename(backup_path.clone(), destination_path.to_owned())
            .await
        {
            bail!(
                "无法安装新远端文件（{install_error}），也无法自动恢复原文件（{restore_error}）；原文件保留在 {backup_path}"
            );
        }
        return Err(anyhow::anyhow!(install_error)).context("无法安装新远端文件，原文件已恢复");
    }

    if let Err(cleanup_error) = remove_remote_tree(sftp, &backup_path).await {
        let remove_new = sftp.remove_file(destination_path.to_owned()).await;
        let restore_old = sftp
            .rename(backup_path.clone(), destination_path.to_owned())
            .await;
        if remove_new.is_ok() && restore_old.is_ok() {
            return Err(anyhow::anyhow!(cleanup_error))
                .context("无法清理远端备份，新文件已撤销且原文件已恢复");
        }
        bail!(
            "新文件已写入，但无法清理远端备份 {backup_path}（{cleanup_error}）；自动回滚也未完整完成"
        );
    }
    Ok(())
}

async fn commit_remote_directory(
    sftp: &SftpSession,
    temporary_path: &str,
    destination_path: &str,
    overwrite: bool,
) -> Result<()> {
    let destination_exists = sftp.try_exists(destination_path.to_owned()).await?;
    if !destination_exists {
        return sftp
            .rename(temporary_path.to_owned(), destination_path.to_owned())
            .await
            .context("无法完成远端目录写入");
    }
    if !overwrite {
        bail!("远端目标已存在；如需替换，请设置 overwrite=true");
    }
    let backup_path = format!("{destination_path}.kru-{}.backup", Uuid::new_v4().simple());
    sftp.rename(destination_path.to_owned(), backup_path.clone())
        .await
        .context("无法暂存已有远端目录，原目录未改变")?;
    if let Err(install_error) = sftp
        .rename(temporary_path.to_owned(), destination_path.to_owned())
        .await
    {
        if let Err(restore_error) = sftp
            .rename(backup_path.clone(), destination_path.to_owned())
            .await
        {
            bail!(
                "无法安装新远端目录（{install_error}），也无法自动恢复原目录（{restore_error}）；原目录保留在 {backup_path}"
            );
        }
        return Err(anyhow::anyhow!(install_error)).context("无法安装新远端目录，原目录已恢复");
    }

    if let Err(cleanup_error) = remove_remote_tree(sftp, &backup_path).await {
        let remove_new = remove_remote_tree(sftp, destination_path).await;
        let restore_old = sftp
            .rename(backup_path.clone(), destination_path.to_owned())
            .await;
        if remove_new.is_ok() && restore_old.is_ok() {
            return Err(cleanup_error).context("无法清理远端目录备份，新目录已撤销且原目录已恢复");
        }
        bail!(
            "新目录已写入，但无法清理远端备份 {backup_path}（{cleanup_error}）；自动回滚也未完整完成"
        );
    }
    Ok(())
}

async fn remove_remote_tree(sftp: &SftpSession, root: &str) -> Result<()> {
    if !sftp.try_exists(root.to_owned()).await? {
        return Ok(());
    }
    let metadata = sftp.symlink_metadata(root.to_owned()).await?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return sftp
            .remove_file(root.to_owned())
            .await
            .with_context(|| format!("无法删除远端文件 {root}"));
    }

    let mut stack = vec![(root.to_owned(), false)];
    while let Some((path, visited)) = stack.pop() {
        if visited {
            sftp.remove_dir(path.clone())
                .await
                .with_context(|| format!("无法删除远端目录 {path}"))?;
            continue;
        }
        stack.push((path.clone(), true));
        for entry in sftp
            .read_dir(path.clone())
            .await
            .with_context(|| format!("无法读取待删除的远端目录 {path}"))?
        {
            if entry.file_type().is_dir() && !entry.file_type().is_symlink() {
                stack.push((entry.path(), false));
            } else {
                let entry_path = entry.path();
                sftp.remove_file(entry_path.clone())
                    .await
                    .with_context(|| format!("无法删除远端文件 {entry_path}"))?;
            }
        }
    }
    Ok(())
}

async fn commit_local_file(
    temporary_path: &std::path::Path,
    destination_path: &std::path::Path,
    overwrite: bool,
) -> Result<()> {
    let destination_exists = tokio::fs::try_exists(destination_path).await?;
    if !destination_exists {
        return tokio::fs::rename(temporary_path, destination_path)
            .await
            .context("无法完成本地文件写入");
    }
    if !overwrite {
        bail!("本地文件已存在；如需替换，请明确设置 overwrite=true");
    }
    let file_name = destination_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    let backup_path = destination_path.with_file_name(format!(
        ".{file_name}.kru-{}.backup",
        Uuid::new_v4().simple()
    ));
    tokio::fs::rename(destination_path, &backup_path)
        .await
        .context("无法暂存已有本地文件，原文件未改变")?;

    if let Err(install_error) = tokio::fs::rename(temporary_path, destination_path).await {
        if let Err(restore_error) = tokio::fs::rename(&backup_path, destination_path).await {
            bail!(
                "无法安装新本地文件（{install_error}），也无法自动恢复原文件（{restore_error}）；原文件保留在 {}",
                backup_path.display()
            );
        }
        return Err(install_error).context("无法安装新本地文件，原文件已恢复");
    }

    if let Err(cleanup_error) = remove_local_path(&backup_path).await {
        let remove_new = tokio::fs::remove_file(destination_path).await;
        let restore_old = tokio::fs::rename(&backup_path, destination_path).await;
        if remove_new.is_ok() && restore_old.is_ok() {
            return Err(cleanup_error).context("无法清理本地备份，新文件已撤销且原文件已恢复");
        }
        bail!(
            "新文件已写入，但无法清理本地备份 {}（{cleanup_error}）；自动回滚也未完整完成",
            backup_path.display()
        );
    }
    Ok(())
}

async fn commit_local_directory(
    temporary_path: &Path,
    destination_path: &Path,
    overwrite: bool,
) -> Result<()> {
    let destination_exists = tokio::fs::try_exists(destination_path).await?;
    if !destination_exists {
        return tokio::fs::rename(temporary_path, destination_path)
            .await
            .context("无法完成本地目录写入");
    }
    if !overwrite {
        bail!("本地目标已存在；如需替换，请设置 overwrite=true");
    }
    let directory_name = destination_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    let backup_path = destination_path.with_file_name(format!(
        ".{directory_name}.kru-{}.backup",
        Uuid::new_v4().simple()
    ));
    tokio::fs::rename(destination_path, &backup_path)
        .await
        .context("无法暂存已有本地目录，原目录未改变")?;
    if let Err(install_error) = tokio::fs::rename(temporary_path, destination_path).await {
        if let Err(restore_error) = tokio::fs::rename(&backup_path, destination_path).await {
            bail!(
                "无法安装新本地目录（{install_error}），也无法自动恢复原目录（{restore_error}）；原目录保留在 {}",
                backup_path.display()
            );
        }
        return Err(install_error).context("无法安装新本地目录，原目录已恢复");
    }

    if let Err(cleanup_error) = remove_local_path(&backup_path).await {
        let remove_new = tokio::fs::remove_dir_all(destination_path).await;
        let restore_old = tokio::fs::rename(&backup_path, destination_path).await;
        if remove_new.is_ok() && restore_old.is_ok() {
            return Err(cleanup_error).context("无法清理本地目录备份，新目录已撤销且原目录已恢复");
        }
        bail!(
            "新目录已写入，但无法清理本地备份 {}（{cleanup_error}）；自动回滚也未完整完成",
            backup_path.display()
        );
    }
    Ok(())
}

async fn remove_local_path(path: &Path) -> Result<()> {
    let file_type = tokio::fs::symlink_metadata(path).await?.file_type();
    if file_type.is_dir() && !file_type.is_symlink() {
        tokio::fs::remove_dir_all(path).await?;
    } else {
        tokio::fs::remove_file(path).await?;
    }
    Ok(())
}

async fn run_optional_ssh_timeout<T>(
    execution: impl std::future::Future<Output = Result<T>>,
    timeout_seconds: Option<u64>,
    action: &str,
) -> Result<T> {
    match timeout_seconds.filter(|seconds| *seconds > 0) {
        Some(seconds) => tokio::time::timeout(Duration::from_secs(seconds), execution)
            .await
            .map_err(|_| anyhow::anyhow!("{action}超过调用方设置的 {seconds} 秒超时"))?,
        None => execution.await,
    }
}

fn validate_transfer_path(value: &str, label: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.contains('\0') {
        bail!("{label}无效");
    }
    Ok(value.to_owned())
}

pub async fn test_connection(vault: &Vault, connection: &DecryptedConnection) -> Result<String> {
    if connection.stored.has_capability("ssh") {
        let testable = DecryptedConnection {
            stored: connection.stored.clone(),
            secrets: connection.secrets.clone(),
        };
        let result = execute_ssh(
            vault,
            &testable,
            "printf 'mcp-vault-ok'",
            None,
            Some(30),
            &HashMap::new(),
            None,
        )
        .await?;
        if result.stdout != "mcp-vault-ok" {
            bail!("VPS 返回了意外结果：{}", result.stderr);
        }
        Ok("SSH 连接成功".to_owned())
    } else if connection.stored.has_capability("http")
        && !connection.stored.base_url.trim().is_empty()
    {
        let mut base = Url::parse(&connection.stored.base_url).context("API URL 无效")?;
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        let url = if connection.stored.test_path.trim().is_empty() {
            base.to_string()
        } else {
            base.join(connection.stored.test_path.trim().trim_start_matches('/'))
                .context("API 测试路径无效")?
                .to_string()
        };
        let result = execute_api(
            connection,
            ApiRequestInput {
                url,
                method: "GET".to_owned(),
                query: HashMap::new(),
                headers: HashMap::new(),
                body: None,
                timeout_seconds: Some(30),
                ..ApiRequestInput::default()
            },
        )
        .await?;
        Ok(format!("API 已响应：HTTP {}", result.status))
    } else {
        bail!("该项目没有可自动测试的连接目标")
    }
}

fn build_api_url(
    connection: &StoredConnection,
    request_url: &str,
    query: &HashMap<String, Value>,
) -> Result<Url> {
    let request_url = request_url.trim();
    let mut target = if request_url.is_empty() {
        let saved = connection.base_url.trim();
        if saved.is_empty() {
            bail!("该项目没有服务 URL；请为本次请求提供绝对 URL");
        }
        Url::parse(saved).context("已保存的服务 URL 无效")?
    } else if let Ok(absolute) = Url::parse(request_url) {
        absolute
    } else {
        let saved = connection.base_url.trim();
        if saved.is_empty() {
            bail!("没有保存服务 URL 时，本次请求必须提供绝对 URL");
        }
        let mut base = Url::parse(saved).context("已保存的服务 URL 无效")?;
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }
        base.join(request_url).context("API 请求相对路径无效")?
    };
    if !query.is_empty() {
        let mut pairs = target.query_pairs_mut();
        for (name, value) in query {
            match value {
                Value::Array(values) => {
                    for value in values {
                        pairs.append_pair(name, &query_value(value));
                    }
                }
                Value::Null => {}
                value => {
                    pairs.append_pair(name, &query_value(value));
                }
            }
        }
    }
    Ok(target)
}

fn query_value(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn form_values(value: Value) -> Vec<String> {
    match value {
        Value::Array(values) => values
            .into_iter()
            .map(|value| query_value(&value))
            .collect(),
        Value::Null => Vec::new(),
        value => vec![query_value(&value)],
    }
}

fn api_request_error_message(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "API 请求超时"
    } else if error.is_connect() {
        "无法连接 API 服务；请检查地址、网络、VPN/代理和端口"
    } else if error.is_body() {
        "API 请求或响应正文传输失败"
    } else if error.is_request() {
        "API 请求无法发送"
    } else {
        "API 请求失败"
    }
}

fn apply_api_auth(
    connection: &StoredConnection,
    secrets: &SecretBundle,
    headers: &mut HeaderMap,
    target: &mut Url,
) -> Result<()> {
    let auth_type = if connection.http_auth_type.is_empty() {
        connection.auth_type.as_str()
    } else {
        connection.http_auth_type.as_str()
    };
    match auth_type {
        "bearer" => {
            let prefix = if connection.auth_prefix.trim().is_empty() {
                "Bearer"
            } else {
                connection.auth_prefix.trim()
            };
            let value = format!(
                "{prefix} {}",
                secrets
                    .get("apiCredential")
                    .context("保险库中没有 API 凭据")?
            );
            headers.insert(
                reqwest::header::AUTHORIZATION,
                HeaderValue::from_str(&value)?,
            );
        }
        "apiKey" => {
            let secret = secrets
                .get("apiCredential")
                .context("保险库中没有 API 凭据")?;
            let value = if connection.auth_prefix.trim().is_empty() {
                secret.to_owned()
            } else {
                format!("{} {secret}", connection.auth_prefix.trim())
            };
            if connection.auth_location == "query" {
                replace_query_pair(target, &connection.auth_header, &value);
            } else {
                let name = HeaderName::from_bytes(connection.auth_header.as_bytes())
                    .context("API Key 请求头无效")?;
                headers.insert(name, HeaderValue::from_str(&value)?);
            }
        }
        "basic" => {
            let username = secrets
                .get("username")
                .context("保险库中没有 Basic Auth 用户名")?;
            let password = secrets
                .password
                .as_deref()
                .context("保险库中没有 Basic Auth 密码")?;
            let encoded = STANDARD.encode(format!("{username}:{password}"));
            headers.insert(
                reqwest::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Basic {encoded}"))?,
            );
        }
        "custom" => {
            for header in &connection.api_auth_headers {
                let name = HeaderName::from_bytes(header.name.as_bytes())
                    .context("自定义认证请求头名称无效")?;
                let value = secrets
                    .get(&header.secret_name)
                    .context("保险库中缺少自定义认证请求头")?;
                headers.insert(name, HeaderValue::from_str(value)?);
            }
        }
        _ => {}
    }
    Ok(())
}

fn replace_query_pair(target: &mut Url, name: &str, value: &str) {
    let retained = target
        .query_pairs()
        .filter(|(key, _)| key != name)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    target.set_query(None);
    let mut pairs = target.query_pairs_mut();
    for (key, value) in retained {
        pairs.append_pair(&key, &value);
    }
    pairs.append_pair(name, value);
}

struct SshClient;

impl client::Handler for SshClient {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

fn sanitize_api_body(
    mut body: String,
    truncated: bool,
    connection: &StoredConnection,
    secrets: &SecretBundle,
) -> String {
    if truncated {
        body.push_str("\n…[结果已截断]");
    }
    redact(body, connection, secrets)
}

fn ssh_connect_error_message(error: &impl Display) -> String {
    let raw = error.to_string();
    let normalized = raw.to_ascii_lowercase();
    if normalized.contains("disconnected") || normalized.contains("connection closed") {
        return "SSH 握手被远端提前关闭（凭据尚未发送）；请检查远端 sshd、VPN/代理链路或 SSH 并发限制".to_owned();
    }
    if normalized.contains("timed out")
        || normalized.contains("timeout")
        || normalized.contains("os error 10060")
    {
        return "SSH TCP 连接超时；请检查目标地址、VPN/代理路由和 22 端口".to_owned();
    }
    if normalized.contains("connection refused") || normalized.contains("os error 10061") {
        return "SSH 端口拒绝连接；目标可达，但 sshd 未监听该端口".to_owned();
    }
    if normalized.contains("no common") || normalized.contains("key exchange") {
        return format!("SSH 握手算法不兼容：{raw}");
    }
    format!("SSH 连接或握手失败：{raw}")
}

pub(crate) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ApiAuthHeader, SecretEnvelope};
    use axum::{
        Router,
        body::Bytes,
        extract::Query,
        http::HeaderMap as AxumHeaders,
        response::Redirect,
        routing::{get, post},
    };
    use chrono::Utc;
    use tempfile::tempdir;
    use uuid::Uuid;

    fn stored(base_url: String) -> StoredConnection {
        StoredConnection {
            id: Uuid::new_v4(),
            kind: "api".into(),
            capabilities: vec!["fill".into(), "http".into()],
            modules: vec![],
            name: "local-api".into(),
            enabled: true,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            description: String::new(),
            host: String::new(),
            port: 0,
            username: String::new(),
            auth_type: "bearer".into(),
            ssh_auth_type: String::new(),
            http_auth_type: String::new(),
            private_key_name: String::new(),
            host_fingerprint: String::new(),
            host_fingerprint_host: String::new(),
            host_fingerprint_port: 0,
            base_url,
            auth_header: "X-API-Key".into(),
            auth_location: "header".into(),
            auth_prefix: String::new(),
            api_auth_headers: vec![],
            allowed_methods: vec!["GET".into()],
            allowed_path_prefixes: vec!["/v1/".into()],
            test_path: String::new(),
            cli: None,
            browser: None,
            credential: None,
            secret: None,
            encrypted_secrets: SecretEnvelope {
                version: 1,
                nonce: String::new(),
                ciphertext: String::new(),
            },
        }
    }

    #[tokio::test]
    async fn fill_only_item_does_not_offer_a_fake_connection_test() {
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let mut stored = stored(String::new());
        stored.capabilities = vec!["fill".to_owned()];
        let connection = DecryptedConnection {
            stored,
            secrets: SecretBundle::default(),
        };
        assert_eq!(
            test_connection(&vault, &connection)
                .await
                .unwrap_err()
                .to_string(),
            "该项目没有可自动测试的连接目标"
        );
    }

    #[test]
    fn remote_parent_paths_are_normalized_and_incremental() {
        assert_eq!(
            remote_parent_directories("/home/user/project/file.txt"),
            vec!["/home", "/home/user", "/home/user/project"]
        );
        assert_eq!(
            remote_parent_directories("/home/user/../shared/file.txt"),
            vec!["/home", "/home/shared"]
        );
        assert_eq!(
            remote_parent_directories("C:\\Users\\me\\file.txt"),
            vec!["C:", "C:/Users", "C:/Users/me"]
        );
        assert_eq!(
            remote_parent_directories("C:/../shared/file.txt"),
            vec!["C:", "C:/shared"]
        );
        assert!(remote_parent_directories("file.txt").is_empty());
    }

    #[tokio::test]
    async fn local_transfer_commit_preserves_existing_files_until_replacement_is_ready() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("download.txt");
        let refused_temporary = directory.path().join("refused.part");
        std::fs::write(&destination, "old").unwrap();
        std::fs::write(&refused_temporary, "new").unwrap();

        assert!(
            commit_local_file(&refused_temporary, &destination, false)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "old");
        assert_eq!(std::fs::read_to_string(&refused_temporary).unwrap(), "new");

        commit_local_file(&refused_temporary, &destination, true)
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&destination).unwrap(), "new");
        assert!(!refused_temporary.exists());
        assert!(std::fs::read_dir(directory.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".backup")
        }));

        let fresh_temporary = directory.path().join("fresh.part");
        let fresh_destination = directory.path().join("fresh.txt");
        std::fs::write(&fresh_temporary, "fresh").unwrap();
        commit_local_file(&fresh_temporary, &fresh_destination, false)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&fresh_destination).unwrap(),
            "fresh"
        );

        let directory_destination = directory.path().join("existing-directory");
        let directory_temporary = directory.path().join("directory.part");
        std::fs::create_dir(&directory_destination).unwrap();
        std::fs::write(&directory_temporary, "must-not-replace-directory").unwrap();
        commit_local_file(&directory_temporary, &directory_destination, true)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&directory_destination).unwrap(),
            "must-not-replace-directory"
        );
        assert!(!directory_temporary.exists());

        let mixed_directory_temporary = directory.path().join("mixed-directory.part");
        std::fs::create_dir(&mixed_directory_temporary).unwrap();
        std::fs::write(mixed_directory_temporary.join("new.txt"), "directory-wins").unwrap();
        commit_local_directory(&mixed_directory_temporary, &directory_destination, true)
            .await
            .unwrap();
        assert!(directory_destination.is_dir());
        assert_eq!(
            std::fs::read_to_string(directory_destination.join("new.txt")).unwrap(),
            "directory-wins"
        );

        let existing_tree = directory.path().join("existing-tree");
        let replacement_tree = directory.path().join("replacement-tree.part");
        std::fs::create_dir(&existing_tree).unwrap();
        std::fs::write(existing_tree.join("old.txt"), "old-tree").unwrap();
        std::fs::create_dir(&replacement_tree).unwrap();
        std::fs::create_dir(replacement_tree.join("nested")).unwrap();
        std::fs::write(replacement_tree.join("nested/new.txt"), "new-tree").unwrap();

        assert!(
            commit_local_directory(&replacement_tree, &existing_tree, false)
                .await
                .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(existing_tree.join("old.txt")).unwrap(),
            "old-tree"
        );
        commit_local_directory(&replacement_tree, &existing_tree, true)
            .await
            .unwrap();
        assert!(!existing_tree.join("old.txt").exists());
        assert_eq!(
            std::fs::read_to_string(existing_tree.join("nested/new.txt")).unwrap(),
            "new-tree"
        );
        assert!(!replacement_tree.exists());
    }

    #[tokio::test]
    async fn api_injects_vault_auth_overwrites_auth_and_keeps_ordinary_headers() {
        async fn response(headers: AxumHeaders) -> String {
            let auth = headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            let cookie = headers
                .get("cookie")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            format!("auth={auth}\ncookie={cookie}\n{}", "x".repeat(1_048_676))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/v1/echo", get(response)))
                .await
                .unwrap();
        });

        let mut secrets = SecretBundle::default();
        secrets.token = Some("vault-secret-token-9384".into());
        let connection = DecryptedConnection {
            stored: stored(format!("http://{address}/v1/")),
            secrets,
        };
        let mut headers = HashMap::new();
        headers.insert("Authorization".into(), "Bearer attacker-value".into());
        headers.insert("Cookie".into(), "session=attacker".into());
        let result = execute_api(
            &connection,
            ApiRequestInput {
                url: format!("http://{address}/v1/echo"),
                method: "GET".into(),
                query: HashMap::new(),
                headers,
                body: None,
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(result.status, 200);
        assert!(!result.body.contains("vault-secret-token-9384"));
        assert!(!result.body.contains("attacker-value"));
        assert!(result.body.contains("[REDACTED]"));
        assert!(result.body.contains("cookie=session=attacker"));
        assert!(!result.body.contains("[结果已截断]"));
        assert!(!result.truncated);
        assert!(result.body.len() > 1_048_576);

        let limited = execute_api(
            &connection,
            ApiRequestInput {
                url: format!("http://{address}/v1/echo"),
                method: "GET".into(),
                max_response_bytes: Some(1_024),
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();
        assert!(limited.body.contains("[结果已截断]"));
        assert!(limited.truncated);
        server.abort();
    }

    #[tokio::test]
    async fn api_streams_large_responses_to_a_safe_local_file() {
        async fn artifact() -> Vec<u8> {
            vec![b'Z'; 1_148_576]
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/v1/artifact", get(artifact)))
                .await
                .unwrap();
        });
        let mut secrets = SecretBundle::default();
        secrets.token = Some("artifact-test-token".into());
        let connection = DecryptedConnection {
            stored: stored(format!("http://{address}/v1/")),
            secrets,
        };
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("nested/artifact.bin");
        let request = || ApiRequestInput {
            url: format!("http://{address}/v1/artifact"),
            method: "GET".into(),
            save_response_to: Some(destination.to_string_lossy().into_owned()),
            ..ApiRequestInput::default()
        };

        let result = execute_api(&connection, request()).await.unwrap();
        assert_eq!(result.body, "");
        assert!(!result.truncated);
        assert_eq!(result.bytes_transferred, Some(1_148_576));
        assert_eq!(std::fs::metadata(&destination).unwrap().len(), 1_148_576);
        assert!(
            result
                .saved_to
                .as_deref()
                .is_some_and(|path| path.ends_with("artifact.bin"))
        );

        assert!(execute_api(&connection, request()).await.is_err());
        std::fs::write(&destination, "old").unwrap();
        let overwritten = execute_api(
            &connection,
            ApiRequestInput {
                overwrite_response_file: true,
                ..request()
            },
        )
        .await
        .unwrap();
        assert_eq!(overwritten.bytes_transferred, Some(1_148_576));
        assert_eq!(std::fs::read(&destination).unwrap()[0], b'Z');
        server.abort();
    }

    #[tokio::test]
    async fn api_follows_redirects_and_reports_the_final_url() {
        let final_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let final_address = final_listener.local_addr().unwrap();
        let final_server = tokio::spawn(async move {
            axum::serve(
                final_listener,
                Router::new().route("/v1/final", get(|| async { "redirect-complete" })),
            )
            .await
            .unwrap();
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let redirect_url = format!("http://{final_address}/v1/final");
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/v1/start",
                    get(move || {
                        let redirect_url = redirect_url.clone();
                        async move { Redirect::temporary(&redirect_url) }
                    }),
                ),
            )
            .await
            .unwrap();
        });
        let mut secrets = SecretBundle::default();
        secrets.token = Some("redirect-token-9384".into());
        let connection = DecryptedConnection {
            stored: stored(format!("http://{address}/v1/")),
            secrets,
        };

        let result = execute_api(
            &connection,
            ApiRequestInput {
                url: format!("http://{address}/v1/start"),
                method: "GET".into(),
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(result.status, 200);
        assert_eq!(result.body, "redirect-complete");
        assert_eq!(result.url, format!("http://{final_address}/v1/final"));
        server.abort();
        final_server.abort();
    }

    #[tokio::test]
    async fn api_key_query_replaces_agent_value_without_exposing_secret() {
        async fn response(Query(query): Query<HashMap<String, String>>) -> &'static str {
            if query.get("key").map(String::as_str) == Some("vault-query-key-9384") {
                "correct"
            } else {
                "wrong"
            }
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/v1/echo", get(response)))
                .await
                .unwrap();
        });
        let mut item = stored(format!("http://{address}/v1/"));
        item.auth_type = "apiKey".into();
        item.auth_location = "query".into();
        item.auth_header = "key".into();
        let mut secrets = SecretBundle::default();
        secrets.api_key = Some("vault-query-key-9384".into());
        let connection = DecryptedConnection {
            stored: item,
            secrets,
        };
        let mut query = HashMap::new();
        query.insert("key".into(), Value::String("agent-value".into()));

        let result = execute_api(
            &connection,
            ApiRequestInput {
                url: format!("http://{address}/v1/echo"),
                method: "GET".into(),
                query,
                headers: HashMap::new(),
                body: None,
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(result.body, "correct");
        assert!(!result.url.contains("vault-query-key-9384"));
        assert!(result.url.contains("[REDACTED]"));
        server.abort();
    }

    #[tokio::test]
    async fn api_supports_forms_raw_bytes_and_streamed_file_uploads() {
        async fn echo(headers: AxumHeaders, body: Bytes) -> String {
            format!(
                "{}\n{}",
                headers
                    .get("content-type")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default(),
                String::from_utf8_lossy(&body)
            )
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/v1/echo", post(echo)))
                .await
                .unwrap();
        });
        let mut stored = stored(format!("http://{address}/v1/"));
        stored.allowed_methods = vec!["POST".into()];
        let mut secrets = SecretBundle::default();
        secrets.token = Some("vault-form-token-9384".into());
        let connection = DecryptedConnection { stored, secrets };
        let url = format!("http://{address}/v1/echo");

        let mut form = HashMap::new();
        form.insert(
            "tag".into(),
            Value::Array(vec![
                Value::String("one".into()),
                Value::String("two".into()),
            ]),
        );
        let form_result = execute_api(
            &connection,
            ApiRequestInput {
                url: url.clone(),
                method: "POST".into(),
                form,
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();
        assert!(
            form_result
                .body
                .contains("application/x-www-form-urlencoded")
        );
        assert!(form_result.body.contains("tag=one"));
        assert!(form_result.body.contains("tag=two"));

        let raw_result = execute_api(
            &connection,
            ApiRequestInput {
                url: url.clone(),
                method: "POST".into(),
                body_base64: Some(STANDARD.encode(b"raw-binary-marker-9384\0tail")),
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();
        assert!(raw_result.body.contains("raw-binary-marker-9384"));

        let mut text_headers = HashMap::new();
        text_headers.insert("Content-Type".into(), "text/plain; charset=utf-8".into());
        let text_result = execute_api(
            &connection,
            ApiRequestInput {
                url: url.clone(),
                method: "POST".into(),
                headers: text_headers,
                body: Some(Value::String("plain-text-marker-9384".into())),
                max_response_bytes: Some(32 * 1024 * 1024),
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();
        assert!(text_result.body.contains("text/plain"));
        assert!(text_result.body.contains("plain-text-marker-9384"));

        let directory = tempfile::tempdir().unwrap();
        let file_path = directory.path().join("upload.txt");
        std::fs::write(&file_path, "multipart-file-marker-9384").unwrap();
        let mut multipart_fields = HashMap::new();
        multipart_fields.insert("note".into(), Value::String("multipart-note-9384".into()));
        let multipart_result = execute_api(
            &connection,
            ApiRequestInput {
                url,
                method: "POST".into(),
                form: multipart_fields,
                files: vec![ApiUploadFile {
                    field: "attachment".into(),
                    path: file_path.to_string_lossy().into_owned(),
                    file_name: None,
                    content_type: None,
                }],
                ..ApiRequestInput::default()
            },
        )
        .await
        .unwrap();
        assert!(multipart_result.body.contains("multipart/form-data"));
        assert!(multipart_result.body.contains("multipart-note-9384"));
        assert!(multipart_result.body.contains("multipart-file-marker-9384"));
        server.abort();
    }

    #[test]
    fn custom_auth_headers_are_injected_from_named_secrets() {
        let mut item = stored("https://api.example.test/v1/".to_owned());
        item.auth_type = "custom".into();
        item.api_auth_headers = vec![ApiAuthHeader {
            name: "X-Client-Secret".into(),
            secret_name: "apiHeader_client".into(),
        }];
        let mut secrets = SecretBundle::default();
        secrets
            .named_secrets
            .insert("apiHeader_client".into(), "custom-secret-9384".into());
        let mut headers = HeaderMap::new();
        let mut target = Url::parse("https://api.example.test/v1/").unwrap();

        apply_api_auth(&item, &secrets, &mut headers, &mut target).unwrap();

        assert_eq!(
            headers.get("x-client-secret").unwrap(),
            "custom-secret-9384"
        );
        assert!(blocked_header_names(&item).contains("x-client-secret"));
    }

    #[test]
    fn api_activity_description_omits_query_and_records_origin_and_path() {
        let mut query = HashMap::new();
        query.insert("token".into(), Value::String("must-not-be-logged".into()));
        let connection = stored("https://api.example.test/v1/".to_owned());
        let description = describe_api_request(
            &connection,
            &ApiRequestInput {
                url: "https://api.example.test/v1/items".into(),
                method: "post".into(),
                query,
                headers: HashMap::new(),
                body: None,
                ..ApiRequestInput::default()
            },
        );
        assert_eq!(description, "API POST https://api.example.test/v1/items");
        assert!(!description.contains("token"));
        assert!(!description.contains("must-not-be-logged"));
    }

    #[test]
    fn api_response_only_redacts_secrets_known_to_kru() {
        let connection = stored("https://api.example.test/v1/".to_owned());
        let mut secrets = SecretBundle::default();
        secrets.token = Some("stored-token-9384".to_owned());
        let body = sanitize_api_body(
            r#"{
                "name": "visible",
                "access_token": "new-access-token",
                "nested": [{"client-secret": "new-client-secret"}],
                "credential": {"value": "new-credential"},
                "echo": "stored-token-9384"
            }"#
            .to_owned(),
            false,
            &connection,
            &secrets,
        );
        assert!(body.contains("visible"));
        for server_value in ["new-access-token", "new-client-secret", "new-credential"] {
            assert!(body.contains(server_value));
        }
        assert!(!body.contains("stored-token-9384"));

        let malformed = sanitize_api_body(
            r#"{"token":"new-token""#.to_owned(),
            false,
            &connection,
            &secrets,
        );
        assert_eq!(malformed, r#"{"token":"new-token""#);

        let truncated = sanitize_api_body(
            r#"{"name":"partial""#.to_owned(),
            true,
            &connection,
            &secrets,
        );
        assert_eq!(truncated, "{\"name\":\"partial\"\n…[结果已截断]");
    }

    #[test]
    fn saved_api_url_accepts_omitted_and_relative_request_urls() {
        let connection = stored("https://api.example.test/v1".to_owned());
        let query = HashMap::new();

        assert_eq!(
            build_api_url(&connection, "", &query).unwrap().as_str(),
            "https://api.example.test/v1"
        );
        assert_eq!(
            build_api_url(&connection, "items/42", &query)
                .unwrap()
                .as_str(),
            "https://api.example.test/v1/items/42"
        );
        assert_eq!(
            build_api_url(&connection, "/health", &query)
                .unwrap()
                .as_str(),
            "https://api.example.test/health"
        );

        let addressless = stored(String::new());
        assert!(build_api_url(&addressless, "", &query).is_err());
        assert!(build_api_url(&addressless, "items", &query).is_err());
        assert_eq!(
            build_api_url(&addressless, "https://other.example/items", &query)
                .unwrap()
                .as_str(),
            "https://other.example/items"
        );
    }

    #[test]
    fn ssh_connect_errors_name_the_failed_stage() {
        assert!(ssh_connect_error_message(&"Disconnected").contains("握手"));
        assert!(ssh_connect_error_message(&"os error 10060").contains("TCP"));
        assert!(ssh_connect_error_message(&"connection refused").contains("端口"));
    }

    #[test]
    fn ssh_secret_environment_quotes_values_and_rejects_invalid_names() {
        let command = ssh_command_with_secret_environment(
            "printf '%s' \"$KRU_PASSWORD\"",
            &HashMap::from([(
                "KRU_PASSWORD".to_owned(),
                "value with ' quotes and $shell".to_owned(),
            )]),
        )
        .unwrap();
        assert!(command.starts_with("KRU_PASSWORD='value with '\\'' quotes and $shell' sh -c "));
        assert!(command.contains("$KRU_PASSWORD"));
        assert!(
            ssh_command_with_secret_environment(
                "true",
                &HashMap::from([("NOT-VALID".to_owned(), "secret".to_owned())]),
            )
            .is_err()
        );
    }
}

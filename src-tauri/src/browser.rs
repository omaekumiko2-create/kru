use crate::{model::BrowserBridgeState, vault::Vault};
use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, Method, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, mpsc, oneshot},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

const JOB_TIMEOUT: Duration = Duration::from_secs(35);
const EXTENSION_QUEUE_TIMEOUT: Duration = Duration::from_millis(500);
const EXTENSION_RECONNECT_GRACE: Duration = Duration::from_secs(2);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(40);
const HEALTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrowserJob {
    id: Uuid,
    value: String,
    #[serde(default)]
    submit: bool,
    #[serde(default)]
    expires_at: u64,
}

impl BrowserJob {
    fn with_deadline(id: Uuid, value: String, submit: bool) -> Self {
        Self {
            id,
            value,
            submit,
            expires_at: unix_millis().saturating_add(JOB_TIMEOUT.as_millis() as u64),
        }
    }

    fn normalize_deadline(&mut self) {
        let now = unix_millis();
        let latest = now.saturating_add(JOB_TIMEOUT.as_millis() as u64);
        if self.expires_at == 0 || self.expires_at > latest {
            self.expires_at = latest;
        }
    }

    fn remaining(&self) -> Duration {
        Duration::from_millis(self.expires_at.saturating_sub(unix_millis()))
    }

    fn is_expired(&self) -> bool {
        self.remaining().is_zero()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFillResult {
    pub status: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PairRequest {
    code: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PairResponse {
    token: String,
    port: u16,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExtensionMessage {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    job_id: Option<Uuid>,
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    message: String,
}

struct PairingCode {
    value: String,
    expires_at: std::time::Instant,
    attempts: u8,
    allow_claim: bool,
}

#[derive(Clone)]
struct ActiveExtension {
    id: Uuid,
    jobs: mpsc::Sender<BrowserJob>,
}

#[derive(Default)]
struct ExtensionPool {
    clients: HashMap<Uuid, mpsc::Sender<BrowserJob>>,
    active: Option<Uuid>,
}

impl ExtensionPool {
    fn add(&mut self, id: Uuid, jobs: mpsc::Sender<BrowserJob>) {
        self.clients.insert(id, jobs);
        if self.active.is_none() {
            self.active = Some(id);
        }
    }

    fn activate(&mut self, id: Uuid) -> bool {
        if self.clients.contains_key(&id) {
            self.active = Some(id);
            true
        } else {
            false
        }
    }

    fn remove(&mut self, id: Uuid) {
        self.clients.remove(&id);
        if self.active == Some(id) {
            self.active = self.clients.keys().next().copied();
        }
    }

    fn active(&self) -> Option<ActiveExtension> {
        let id = self.active?;
        Some(ActiveExtension {
            id,
            jobs: self.clients.get(&id)?.clone(),
        })
    }
}

#[derive(Clone)]
struct BridgeServerState {
    vault: Vault,
    port: u16,
    internal_token: String,
    extension_token: String,
    pairing: Arc<Mutex<Option<PairingCode>>>,
    extensions: Arc<Mutex<ExtensionPool>>,
    pending: Arc<Mutex<HashMap<Uuid, oneshot::Sender<BrowserFillResult>>>>,
    cancellation: CancellationToken,
}

struct Runtime {
    port: u16,
    status: String,
    error: String,
    cancellation: Option<CancellationToken>,
    task: Option<JoinHandle<()>>,
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            port: 0,
            status: "off".to_owned(),
            error: String::new(),
            cancellation: None,
            task: None,
        }
    }
}

#[derive(Clone)]
pub struct BrowserBridge {
    vault: Vault,
    runtime: Arc<Mutex<Runtime>>,
    client: reqwest::Client,
}

impl BrowserBridge {
    pub fn new(vault: Vault) -> Self {
        Self {
            vault,
            runtime: Arc::new(Mutex::new(Runtime::default())),
            client: reqwest::Client::builder()
                .timeout(HTTP_REQUEST_TIMEOUT)
                .connect_timeout(Duration::from_secs(2))
                .build()
                .expect("reqwest client configuration must be valid"),
        }
    }

    pub async fn sync(&self) {
        let settings = match self.vault.settings() {
            Ok(settings) => settings,
            Err(error) => {
                self.set_error(error.to_string()).await;
                return;
            }
        };
        if !settings.browser_enabled {
            self.stop().await;
            return;
        }
        if let Err(error) = self.ensure_started(settings.browser_port).await {
            self.set_error(error.to_string()).await;
        }
    }

    pub async fn stop(&self) {
        let (cancellation, task) = {
            let mut runtime = self.runtime.lock().await;
            runtime.status = "off".to_owned();
            runtime.error.clear();
            (runtime.cancellation.take(), runtime.task.take())
        };
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
        if let Some(task) = task {
            let _ = task.await;
        }
    }

    pub async fn status(&self) -> BrowserBridgeState {
        let settings = self.vault.settings().unwrap_or_default();
        let (status, error) = {
            let runtime = self.runtime.lock().await;
            (runtime.status.clone(), runtime.error.clone())
        };
        let connected = settings.browser_enabled
            && settings.browser_paired
            && matches!(status.as_str(), "listening" | "delegated")
            && self.probe_fill_ready(settings.browser_port).await;
        BrowserBridgeState {
            enabled: settings.browser_enabled,
            paired: settings.browser_paired,
            connected,
            status,
            error,
            endpoint: format!("ws://127.0.0.1:{}/extension", settings.browser_port),
        }
    }

    pub async fn fill_ready(&self) -> bool {
        let Ok(settings) = self.vault.settings() else {
            return false;
        };
        if !settings.browser_enabled || !settings.browser_paired {
            return false;
        }
        self.ensure_started(settings.browser_port).await.is_ok()
            && self.probe_fill_ready(settings.browser_port).await
    }

    pub fn fill_configured(&self) -> bool {
        self.vault
            .settings()
            .is_ok_and(|settings| settings.browser_enabled && settings.browser_paired)
    }

    async fn probe_fill_ready(&self, port: u16) -> bool {
        self.client
            .get(format!("http://127.0.0.1:{port}/internal/ready"))
            .bearer_auth(self.internal_token().unwrap_or_default())
            .timeout(HEALTH_REQUEST_TIMEOUT)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
    }

    pub async fn create_pairing_code(&self) -> Result<String> {
        let settings = self.vault.settings()?;
        if !settings.browser_enabled {
            bail!("请先启用 Browser Bridge");
        }
        self.ensure_started(settings.browser_port).await?;
        let response = self
            .client
            .post(format!(
                "http://127.0.0.1:{}/internal/pair-code",
                settings.browser_port
            ))
            .bearer_auth(self.internal_token()?)
            .send()
            .await
            .context("无法连接 Browser Bridge")?;
        if !response.status().is_success() {
            bail!(
                "无法生成浏览器配对码：{}",
                response.text().await.unwrap_or_default()
            );
        }
        Ok(response.text().await?)
    }

    pub async fn start_quick_pairing(&self) -> Result<()> {
        let settings = self.vault.settings()?;
        if !settings.browser_enabled {
            bail!("请先启用 Browser Bridge");
        }
        self.ensure_started(settings.browser_port).await?;
        let response = self
            .client
            .post(format!(
                "http://127.0.0.1:{}/internal/quick-pair",
                settings.browser_port
            ))
            .bearer_auth(self.internal_token()?)
            .send()
            .await
            .context("无法连接 Browser Bridge")?;
        if !response.status().is_success() {
            bail!(
                "无法开启浏览器自动配对：{}",
                response.text().await.unwrap_or_default()
            );
        }
        Ok(())
    }

    pub async fn reset_pairing(&self) -> Result<()> {
        let settings = self.vault.settings()?;
        if !settings.browser_enabled {
            self.vault.rotate_browser_bridge_secret()?;
            return Ok(());
        }
        self.ensure_started(settings.browser_port).await?;
        let response = self
            .client
            .post(format!(
                "http://127.0.0.1:{}/internal/reset",
                settings.browser_port
            ))
            .bearer_auth(self.internal_token()?)
            .send()
            .await
            .context("无法连接 Browser Bridge")?;
        if !response.status().is_success() {
            bail!("无法重置浏览器配对");
        }
        self.stop().await;
        sleep(Duration::from_millis(120)).await;
        self.sync().await;
        Ok(())
    }

    pub async fn fill_value(&self, value: String, submit: bool) -> Result<BrowserFillResult> {
        let settings = self.vault.settings()?;
        if !settings.browser_enabled {
            bail!("Browser Bridge 未启用");
        }
        if !settings.browser_paired {
            bail!("尚未配对 Chromium 扩展");
        }
        self.ensure_started(settings.browser_port).await?;
        let job = BrowserJob::with_deadline(Uuid::new_v4(), value, submit);
        let response = self
            .client
            .post(format!(
                "http://127.0.0.1:{}/internal/jobs",
                settings.browser_port
            ))
            .bearer_auth(self.internal_token()?)
            .json(&job)
            .send()
            .await
            .context("无法提交浏览器填写任务")?;
        if !response.status().is_success() {
            bail!(
                "浏览器填写失败：{}",
                response.text().await.unwrap_or_default()
            );
        }
        response.json().await.context("浏览器结果格式无效")
    }

    async fn ensure_started(&self, port: u16) -> Result<()> {
        self.clear_finished_runtime().await;
        let current_status = {
            let runtime = self.runtime.lock().await;
            (runtime.port, runtime.status.clone())
        };
        if current_status.0 == port && current_status.1 == "listening" {
            return Ok(());
        }
        if current_status.0 == port && current_status.1 == "delegated" {
            let alive = self
                .client
                .get(format!("http://127.0.0.1:{port}/internal/health"))
                .bearer_auth(self.internal_token()?)
                .timeout(HEALTH_REQUEST_TIMEOUT)
                .send()
                .await
                .is_ok_and(|response| response.status().is_success());
            if alive {
                return Ok(());
            }
        }
        self.stop().await;
        let internal_token = self.internal_token()?;
        let extension_token = self.extension_token()?;
        match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => {
                let cancellation = CancellationToken::new();
                let state = BridgeServerState {
                    vault: self.vault.clone(),
                    port,
                    internal_token,
                    extension_token,
                    pairing: Arc::new(Mutex::new(None)),
                    extensions: Arc::new(Mutex::new(ExtensionPool::default())),
                    pending: Arc::new(Mutex::new(HashMap::new())),
                    cancellation: cancellation.clone(),
                };
                let router = Router::new()
                    .route("/health", get(health))
                    .route("/pair", post(pair))
                    .route("/claim", post(claim))
                    .route("/extension", get(extension_upgrade))
                    .route("/internal/health", get(internal_health))
                    .route("/internal/ready", get(internal_ready))
                    .route("/internal/pair-code", post(create_pair_code))
                    .route("/internal/quick-pair", post(create_quick_pair))
                    .route("/internal/jobs", post(submit_job))
                    .route("/internal/reset", post(reset_pairing))
                    .layer(
                        CorsLayer::new()
                            .allow_origin(Any)
                            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
                            .allow_methods([Method::GET, Method::POST]),
                    )
                    .with_state(state);
                let child_cancellation = cancellation.clone();
                let task = tokio::spawn(async move {
                    let _ = axum::serve(listener, router)
                        .with_graceful_shutdown(child_cancellation.cancelled_owned())
                        .await;
                });
                let mut runtime = self.runtime.lock().await;
                runtime.port = port;
                runtime.status = "listening".to_owned();
                runtime.error.clear();
                runtime.cancellation = Some(cancellation);
                runtime.task = Some(task);
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                let response = self
                    .client
                    .get(format!("http://127.0.0.1:{port}/internal/health"))
                    .bearer_auth(internal_token)
                    .timeout(HEALTH_REQUEST_TIMEOUT)
                    .send()
                    .await
                    .context("Browser Bridge 端口已被其他程序占用")?;
                if !response.status().is_success() {
                    bail!("Browser Bridge 端口已被其他程序占用");
                }
                let mut runtime = self.runtime.lock().await;
                runtime.port = port;
                runtime.status = "delegated".to_owned();
                runtime.error.clear();
                Ok(())
            }
            Err(error) => Err(error).context("无法启动 Browser Bridge"),
        }
    }

    async fn clear_finished_runtime(&self) {
        let mut runtime = self.runtime.lock().await;
        if runtime.task.as_ref().is_some_and(JoinHandle::is_finished) {
            runtime.task = None;
            runtime.cancellation = None;
            runtime.status = "off".to_owned();
        }
    }

    async fn set_error(&self, message: String) {
        let mut runtime = self.runtime.lock().await;
        runtime.status = "error".to_owned();
        runtime.error = message;
    }

    fn internal_token(&self) -> Result<String> {
        derive_token(&self.vault.browser_bridge_secret()?, "internal")
    }

    fn extension_token(&self) -> Result<String> {
        derive_token(&self.vault.browser_bridge_secret()?, "extension")
    }
}

async fn health() -> &'static str {
    "KRU Browser Bridge"
}

async fn internal_health(
    State(state): State<BridgeServerState>,
    headers: HeaderMap,
) -> Result<&'static str, (StatusCode, String)> {
    require_bearer(&headers, &state.internal_token)?;
    Ok("ok")
}

async fn internal_ready(
    State(state): State<BridgeServerState>,
    headers: HeaderMap,
) -> Result<&'static str, (StatusCode, String)> {
    require_bearer(&headers, &state.internal_token)?;
    if state.extensions.lock().await.active().is_some() {
        Ok("ready")
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "浏览器扩展未连接".to_owned(),
        ))
    }
}

async fn create_pair_code(
    State(state): State<BridgeServerState>,
    headers: HeaderMap,
) -> Result<String, (StatusCode, String)> {
    require_bearer(&headers, &state.internal_token)?;
    let mut bytes = [0_u8; 4];
    getrandom::fill(&mut bytes).map_err(internal_error)?;
    let code = format!("{:06}", u32::from_le_bytes(bytes) % 1_000_000);
    *state.pairing.lock().await = Some(PairingCode {
        value: code.clone(),
        expires_at: std::time::Instant::now() + Duration::from_secs(120),
        attempts: 0,
        allow_claim: false,
    });
    Ok(code)
}

async fn create_quick_pair(
    State(state): State<BridgeServerState>,
    headers: HeaderMap,
) -> Result<&'static str, (StatusCode, String)> {
    require_bearer(&headers, &state.internal_token)?;
    *state.pairing.lock().await = Some(PairingCode {
        value: String::new(),
        expires_at: std::time::Instant::now() + Duration::from_secs(120),
        attempts: 0,
        allow_claim: true,
    });
    Ok("ready")
}

async fn pair(
    State(state): State<BridgeServerState>,
    Json(request): Json<PairRequest>,
) -> Result<Json<PairResponse>, (StatusCode, String)> {
    let mut pairing = state.pairing.lock().await;
    let current = pairing
        .as_mut()
        .ok_or((StatusCode::UNAUTHORIZED, "没有待处理的配对".to_owned()))?;
    if current.allow_claim {
        return Err((StatusCode::UNAUTHORIZED, "当前已开启自动配对".to_owned()));
    }
    if std::time::Instant::now() > current.expires_at || current.attempts >= 5 {
        *pairing = None;
        return Err((StatusCode::UNAUTHORIZED, "配对码已过期".to_owned()));
    }
    current.attempts += 1;
    if request.code.trim() != current.value {
        return Err((StatusCode::UNAUTHORIZED, "配对码不正确".to_owned()));
    }
    *pairing = None;
    state
        .vault
        .set_browser_paired(true)
        .map_err(internal_error)?;
    Ok(Json(PairResponse {
        token: state.extension_token.clone(),
        port: state.port,
    }))
}

async fn claim(
    State(state): State<BridgeServerState>,
    headers: HeaderMap,
) -> Result<Json<PairResponse>, (StatusCode, String)> {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !origin.starts_with("chrome-extension://") {
        return Err((
            StatusCode::FORBIDDEN,
            "只允许 Chromium 扩展认领配对".to_owned(),
        ));
    }
    let mut pairing = state.pairing.lock().await;
    let current = pairing
        .as_ref()
        .ok_or((StatusCode::UNAUTHORIZED, "没有待处理的配对".to_owned()))?;
    if !current.allow_claim || std::time::Instant::now() > current.expires_at {
        *pairing = None;
        return Err((StatusCode::UNAUTHORIZED, "自动配对窗口已关闭".to_owned()));
    }
    *pairing = None;
    state
        .vault
        .set_browser_paired(true)
        .map_err(internal_error)?;
    Ok(Json(PairResponse {
        token: state.extension_token.clone(),
        port: state.port,
    }))
}

async fn submit_job(
    State(state): State<BridgeServerState>,
    headers: HeaderMap,
    Json(mut job): Json<BrowserJob>,
) -> Result<Json<BrowserFillResult>, (StatusCode, String)> {
    require_bearer(&headers, &state.internal_token)?;
    job.normalize_deadline();
    let (sender, receiver) = oneshot::channel();
    state.pending.lock().await.insert(job.id, sender);
    let delivered = deliver_to_extension_with_grace(&state, &job).await;
    if !delivered {
        state.pending.lock().await.remove(&job.id);
        if job.is_expired() {
            return Err((StatusCode::GATEWAY_TIMEOUT, "浏览器填写超时".to_owned()));
        }
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "浏览器扩展未连接".to_owned(),
        ));
    }
    match timeout(job.remaining(), receiver).await {
        Ok(Ok(result)) => {
            if result.status == "ok" {
                Ok(Json(result))
            } else {
                Err((StatusCode::BAD_REQUEST, result.message))
            }
        }
        _ => {
            state.pending.lock().await.remove(&job.id);
            Err((StatusCode::GATEWAY_TIMEOUT, "浏览器填写超时".to_owned()))
        }
    }
}

async fn deliver_to_extension_with_grace(state: &BridgeServerState, job: &BrowserJob) -> bool {
    let grace = EXTENSION_RECONNECT_GRACE.min(job.remaining());
    let deadline = tokio::time::Instant::now() + grace;
    loop {
        if deliver_to_extension(state, job).await {
            return true;
        }
        if job.is_expired() || tokio::time::Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(50)).await;
    }
}

async fn deliver_to_extension(state: &BridgeServerState, job: &BrowserJob) -> bool {
    let candidates = state.extensions.lock().await.clients.len();
    for _ in 0..candidates {
        if !job_is_deliverable(state, job).await {
            return false;
        }
        let Some(active) = state.extensions.lock().await.active() else {
            break;
        };
        let send_timeout = EXTENSION_QUEUE_TIMEOUT.min(job.remaining());
        match timeout(send_timeout, active.jobs.send(job.clone())).await {
            Ok(Ok(())) => return true,
            Ok(Err(_)) | Err(_) => state.extensions.lock().await.remove(active.id),
        }
    }
    false
}

async fn job_is_deliverable(state: &BridgeServerState, job: &BrowserJob) -> bool {
    !job.is_expired() && state.pending.lock().await.contains_key(&job.id)
}

async fn reset_pairing(
    State(state): State<BridgeServerState>,
    headers: HeaderMap,
) -> Result<&'static str, (StatusCode, String)> {
    require_bearer(&headers, &state.internal_token)?;
    state
        .vault
        .rotate_browser_bridge_secret()
        .map_err(internal_error)?;
    let cancellation = state.cancellation.clone();
    tokio::spawn(async move {
        sleep(Duration::from_millis(80)).await;
        cancellation.cancel();
    });
    Ok("reset")
}

async fn extension_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<BridgeServerState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| extension_socket(socket, state))
}

async fn extension_socket(socket: WebSocket, state: BridgeServerState) {
    let (mut sender, mut receiver) = socket.split();
    let authenticated = timeout(Duration::from_secs(5), receiver.next()).await;
    let Ok(Some(Ok(Message::Text(message)))) = authenticated else {
        let _ = sender.send(Message::Close(None)).await;
        return;
    };
    let Ok(message) = serde_json::from_str::<ExtensionMessage>(&message) else {
        let _ = sender.send(Message::Close(None)).await;
        return;
    };
    if message.kind != "auth" || message.token != state.extension_token {
        let _ = sender
            .send(Message::Text(
                serde_json::json!({"type":"auth-error"}).to_string().into(),
            ))
            .await;
        let _ = sender.send(Message::Close(None)).await;
        return;
    }
    let _ = sender
        .send(Message::Text(
            serde_json::json!({"type":"ready"}).to_string().into(),
        ))
        .await;
    let connection_id = Uuid::new_v4();
    let (job_sender, mut jobs) = mpsc::channel(8);
    state.extensions.lock().await.add(connection_id, job_sender);
    loop {
        tokio::select! {
            job = jobs.recv() => {
                let Some(job) = job else { break; };
                if !job_is_deliverable(&state, &job).await { continue; }
                let Ok(json) = serde_json::to_string(&serde_json::json!({"type":"job", "job":job})) else { continue; };
                match timeout(job.remaining(), sender.send(Message::Text(json.into()))).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) | Err(_) => break,
                }
            }
            message = receiver.next() => {
                match message {
                    Some(Ok(Message::Text(message))) => {
                        let Ok(message) = serde_json::from_str::<ExtensionMessage>(&message) else { continue; };
                        if message.kind == "ping" {
                            let pong = serde_json::json!({"type":"pong"}).to_string();
                            if sender.send(Message::Text(pong.into())).await.is_err() { break; }
                            continue;
                        }
                        if message.kind == "activate" {
                            state.extensions.lock().await.activate(connection_id);
                            continue;
                        }
                        if message.kind != "complete" { continue; }
                        let Some(job_id) = message.job_id else { continue; };
                        if let Some(pending) = state.pending.lock().await.remove(&job_id) {
                            let _ = pending.send(BrowserFillResult {
                                status: if message.ok { "ok" } else { "error" }.to_owned(),
                                message: message.message,
                            });
                        }
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        if sender.send(Message::Pong(payload)).await.is_err() { break; }
                    }
                    Some(Ok(Message::Pong(_))) | Some(Ok(Message::Binary(_))) => {}
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                }
            }
        }
    }
    state.extensions.lock().await.remove(connection_id);
}

fn require_bearer(headers: &HeaderMap, expected: &str) -> Result<(), (StatusCode, String)> {
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");
    if supplied.len() == expected.len()
        && subtle::ConstantTimeEq::ct_eq(supplied.as_bytes(), expected.as_bytes()).into()
    {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "未授权".to_owned()))
    }
}

fn internal_error(error: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

fn derive_token(secret: &str, role: &str) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"mcp-vault/browser/v1/");
    hasher.update(role.as_bytes());
    hasher.update(secret.as_bytes());
    Ok(STANDARD_NO_PAD.encode(hasher.finalize()))
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn current_totp(secret: &str) -> Result<String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("系统时间无效")?
        .as_secs();
    totp_at(secret, timestamp)
}

fn totp_at(secret: &str, timestamp: u64) -> Result<String> {
    let key = decode_base32(secret)?;
    let counter = timestamp / 30;
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).context("TOTP 密钥无效")?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let value = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Ok(format!("{:06}", value % 1_000_000))
}

fn decode_base32(value: &str) -> Result<Vec<u8>> {
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    let mut output = Vec::new();
    for character in value
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '-')
    {
        if character == '=' {
            break;
        }
        let character = character.to_ascii_uppercase();
        let number = match character {
            'A'..='Z' => character as u8 - b'A',
            '2'..='7' => character as u8 - b'2' + 26,
            _ => bail!("TOTP Secret 必须是 Base32"),
        };
        buffer = (buffer << 5) | u32::from(number);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1_u32 << bits).saturating_sub(1);
        }
    }
    if output.is_empty() {
        bail!("TOTP Secret 不能为空");
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_server_state(vault: Vault) -> BridgeServerState {
        BridgeServerState {
            vault,
            port: 0,
            internal_token: "internal".to_owned(),
            extension_token: "extension".to_owned(),
            pairing: Arc::new(Mutex::new(None)),
            extensions: Arc::new(Mutex::new(ExtensionPool::default())),
            pending: Arc::new(Mutex::new(HashMap::new())),
            cancellation: CancellationToken::new(),
        }
    }

    #[test]
    fn totp_matches_rfc_vector_truncated_to_six_digits() {
        assert_eq!(
            totp_at("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59).unwrap(),
            "287082"
        );
    }

    #[test]
    fn bridge_roles_use_distinct_tokens() {
        let internal = derive_token("same-local-secret", "internal").unwrap();
        let extension = derive_token("same-local-secret", "extension").unwrap();
        assert_ne!(internal, extension);
    }

    #[tokio::test]
    async fn stalled_extension_queue_is_bounded_and_client_is_removed() {
        let directory = tempdir().unwrap();
        let state = test_server_state(Vault::open(directory.path().join("vault")).unwrap());
        let (jobs, mut receiver) = mpsc::channel(1);
        jobs.send(BrowserJob::with_deadline(
            Uuid::new_v4(),
            "already queued".to_owned(),
            false,
        ))
        .await
        .unwrap();
        state.extensions.lock().await.add(Uuid::new_v4(), jobs);

        let mut job = BrowserJob::with_deadline(Uuid::new_v4(), "secret".to_owned(), false);
        job.expires_at = unix_millis().saturating_add(100);
        let (result, _receiver) = oneshot::channel();
        state.pending.lock().await.insert(job.id, result);

        let started = std::time::Instant::now();
        assert!(!deliver_to_extension(&state, &job).await);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(state.extensions.lock().await.active().is_none());
        assert_eq!(receiver.recv().await.unwrap().value, "already queued");
    }

    #[tokio::test]
    async fn expired_or_cancelled_jobs_cannot_be_delivered_later() {
        let directory = tempdir().unwrap();
        let state = test_server_state(Vault::open(directory.path().join("vault")).unwrap());

        let mut expired = BrowserJob::with_deadline(Uuid::new_v4(), "expired".to_owned(), false);
        expired.expires_at = unix_millis().saturating_sub(1);
        expired.normalize_deadline();
        let (result, _receiver) = oneshot::channel();
        state.pending.lock().await.insert(expired.id, result);
        assert!(expired.is_expired());
        assert!(!job_is_deliverable(&state, &expired).await);

        let active = BrowserJob::with_deadline(Uuid::new_v4(), "active".to_owned(), false);
        let (result, _receiver) = oneshot::channel();
        state.pending.lock().await.insert(active.id, result);
        assert!(job_is_deliverable(&state, &active).await);
        state.pending.lock().await.remove(&active.id);
        assert!(!job_is_deliverable(&state, &active).await);
    }

    #[tokio::test]
    async fn first_job_waits_briefly_for_extension_reconnect() {
        let directory = tempdir().unwrap();
        let state = test_server_state(Vault::open(directory.path().join("vault")).unwrap());
        let job = BrowserJob::with_deadline(Uuid::new_v4(), "secret".to_owned(), false);
        let (result, _receiver) = oneshot::channel();
        state.pending.lock().await.insert(job.id, result);

        let extensions = state.extensions.clone();
        let (jobs, mut receiver) = mpsc::channel(1);
        tokio::spawn(async move {
            sleep(Duration::from_millis(100)).await;
            extensions.lock().await.add(Uuid::new_v4(), jobs);
        });

        assert!(deliver_to_extension_with_grace(&state, &job).await);
        assert_eq!(receiver.recv().await.unwrap().id, job.id);
    }

    #[tokio::test]
    async fn pairing_rejects_wrong_code_and_returns_only_extension_token() {
        let port = {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            listener.local_addr().unwrap().port()
        };
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let mut settings = vault.settings().unwrap();
        settings.browser_enabled = true;
        settings.browser_port = port;
        vault.update_settings(settings).unwrap();
        let bridge = BrowserBridge::new(vault.clone());
        bridge.sync().await;
        let code = bridge.create_pairing_code().await.unwrap();
        let client = reqwest::Client::new();
        let bad = client
            .post(format!("http://127.0.0.1:{port}/pair"))
            .json(&serde_json::json!({"code":"999999"}))
            .send()
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
        let paired = client
            .post(format!("http://127.0.0.1:{port}/pair"))
            .json(&serde_json::json!({"code":code}))
            .send()
            .await
            .unwrap();
        assert_eq!(paired.status(), StatusCode::OK);
        let payload: serde_json::Value = paired.json().await.unwrap();
        assert!(
            payload["token"]
                .as_str()
                .is_some_and(|token| token.len() > 20)
        );
        assert!(payload.get("internalToken").is_none());
        assert!(vault.settings().unwrap().browser_paired);
        bridge.stop().await;
    }

    #[tokio::test]
    async fn quick_pairing_requires_a_chromium_extension_origin() {
        let port = {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            listener.local_addr().unwrap().port()
        };
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let mut settings = vault.settings().unwrap();
        settings.browser_enabled = true;
        settings.browser_port = port;
        vault.update_settings(settings).unwrap();
        let bridge = BrowserBridge::new(vault.clone());
        bridge.sync().await;
        bridge.start_quick_pairing().await.unwrap();

        let client = reqwest::Client::new();
        let web_page = client
            .post(format!("http://127.0.0.1:{port}/claim"))
            .header(header::ORIGIN, "https://example.com")
            .send()
            .await
            .unwrap();
        assert_eq!(web_page.status(), StatusCode::FORBIDDEN);

        let extension = client
            .post(format!("http://127.0.0.1:{port}/claim"))
            .header(header::ORIGIN, "chrome-extension://abcdefghijklmnop")
            .send()
            .await
            .unwrap();
        assert_eq!(extension.status(), StatusCode::OK);
        let payload: serde_json::Value = extension.json().await.unwrap();
        assert!(
            payload["token"]
                .as_str()
                .is_some_and(|token| token.len() > 20)
        );
        assert!(vault.settings().unwrap().browser_paired);
        bridge.stop().await;
    }

    #[tokio::test]
    async fn activated_extension_receives_the_job_and_a_standby_takes_over() {
        use tokio_tungstenite::tungstenite::Message as ClientMessage;

        let port = {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            listener.local_addr().unwrap().port()
        };
        let directory = tempdir().unwrap();
        let vault = Vault::open(directory.path().join("vault")).unwrap();
        let mut settings = vault.settings().unwrap();
        settings.browser_enabled = true;
        settings.browser_port = port;
        vault.update_settings(settings).unwrap();
        vault.set_browser_paired(true).unwrap();
        let bridge = BrowserBridge::new(vault);
        bridge.sync().await;
        assert!(bridge.fill_configured());
        assert!(!bridge.fill_ready().await);

        let url = format!("ws://127.0.0.1:{port}/extension");
        let auth = serde_json::json!({
            "type": "auth",
            "token": bridge.extension_token().unwrap()
        })
        .to_string();
        let (mut first, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        first
            .send(ClientMessage::Text(auth.clone().into()))
            .await
            .unwrap();
        assert!(
            first
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap()
                .contains("ready")
        );
        sleep(Duration::from_millis(20)).await;
        assert!(bridge.fill_ready().await);
        assert!(bridge.status().await.connected);

        let (mut second, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        second.send(ClientMessage::Text(auth.into())).await.unwrap();
        assert!(
            second
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap()
                .contains("ready")
        );
        second
            .send(ClientMessage::Text(r#"{"type":"activate"}"#.into()))
            .await
            .unwrap();
        second
            .send(ClientMessage::Text(r#"{"type":"ping"}"#.into()))
            .await
            .unwrap();
        assert!(
            second
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap()
                .contains("pong")
        );

        let job_id = Uuid::new_v4();
        let client = reqwest::Client::new();
        let job_request = tokio::spawn({
            let url = format!("http://127.0.0.1:{port}/internal/jobs");
            let token = bridge.internal_token().unwrap();
            async move {
                client
                    .post(url)
                    .bearer_auth(token)
                    .json(&serde_json::json!({"id": job_id, "value": "test-value"}))
                    .send()
                    .await
                    .unwrap()
            }
        });

        let delivered = timeout(Duration::from_secs(2), second.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        let delivered: serde_json::Value = serde_json::from_str(&delivered).unwrap();
        assert_eq!(delivered["type"], "job");
        assert_eq!(delivered["job"]["id"], job_id.to_string());

        if let Ok(Some(Ok(ClientMessage::Text(message)))) =
            timeout(Duration::from_millis(250), first.next()).await
        {
            let message: serde_json::Value = serde_json::from_str(&message).unwrap();
            assert_ne!(message["type"], "job");
        }

        second
            .send(ClientMessage::Text(
                serde_json::json!({
                    "type": "complete",
                    "jobId": job_id,
                    "ok": true,
                    "message": "done"
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        assert_eq!(job_request.await.unwrap().status(), StatusCode::OK);

        second.close(None).await.unwrap();
        sleep(Duration::from_millis(50)).await;
        let takeover_job_id = Uuid::new_v4();
        let takeover_request = tokio::spawn({
            let url = format!("http://127.0.0.1:{port}/internal/jobs");
            let token = bridge.internal_token().unwrap();
            async move {
                reqwest::Client::new()
                    .post(url)
                    .bearer_auth(token)
                    .json(&serde_json::json!({"id": takeover_job_id, "value": "next"}))
                    .send()
                    .await
                    .unwrap()
            }
        });
        let delivered = timeout(Duration::from_secs(2), first.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap();
        let delivered: serde_json::Value = serde_json::from_str(&delivered).unwrap();
        assert_eq!(delivered["job"]["id"], takeover_job_id.to_string());
        first
            .send(ClientMessage::Text(
                serde_json::json!({
                    "type": "complete",
                    "jobId": takeover_job_id,
                    "ok": true,
                    "message": "done"
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        assert_eq!(takeover_request.await.unwrap().status(), StatusCode::OK);
        bridge.stop().await;
    }
}

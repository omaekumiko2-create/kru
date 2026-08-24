use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use mcp_vault::{browser::BrowserBridge, vault::Vault};
use serde_json::{Value, json};
use std::{env, fs, path::PathBuf};
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[tokio::main]
async fn main() -> Result<()> {
    let result_path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .context("missing result path")?;
    let ready_path = env::args()
        .nth(2)
        .map(PathBuf::from)
        .context("missing ready path")?;
    let data_dir = dirs::data_dir()
        .map(|path| path.join("mcp-vault").join("v2"))
        .context("cannot resolve app data directory")?;
    let vault = Vault::open(data_dir)?;
    let original_paired = vault.settings()?.browser_paired;
    let bridge = BrowserBridge::new(vault.clone());
    bridge.sync().await;

    let code = bridge.create_pairing_code().await?;
    let settings = vault.settings()?;
    let pair: Value = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{}/pair", settings.browser_port))
        .json(&json!({"code": code}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let token = pair["token"].as_str().context("pair token missing")?;
    let (mut socket, _) = connect_async(format!(
        "ws://127.0.0.1:{}/extension",
        settings.browser_port
    ))
    .await?;
    socket
        .send(Message::Text(
            json!({"type":"auth", "token":token}).to_string().into(),
        ))
        .await?;
    let ready = socket
        .next()
        .await
        .context("bridge closed before ready")??;
    let ready: Value = serde_json::from_str(ready.to_text()?)?;
    if ready["type"] != "ready" {
        bail!("bridge did not authenticate the extension simulator");
    }
    fs::write(&ready_path, b"ready")?;

    let mut jobs = 0_u8;
    let mut minimal_shape = true;
    let mut non_empty_values = true;
    while jobs < 2 {
        let message = socket.next().await.context("bridge closed before job")??;
        if !message.is_text() {
            continue;
        }
        let message: Value = serde_json::from_str(message.to_text()?)?;
        if message["type"] != "job" {
            continue;
        }
        let job = message["job"].as_object().context("job is not an object")?;
        minimal_shape &= job.len() == 2 && job.contains_key("id") && job.contains_key("value");
        non_empty_values &= job["value"].as_str().is_some_and(|value| !value.is_empty());
        let job_id = job["id"].clone();
        socket
            .send(Message::Text(
                json!({
                    "type":"complete",
                    "jobId":job_id,
                    "ok":true,
                    "message":"accepted by local E2E sink"
                })
                .to_string()
                .into(),
            ))
            .await?;
        jobs += 1;
    }

    vault.set_browser_paired(original_paired)?;
    bridge.stop().await;
    fs::write(
        result_path,
        serde_json::to_vec(&json!({
            "jobs": jobs,
            "minimalShape": minimal_shape,
            "nonEmptyValues": non_empty_values
        }))?,
    )?;
    Ok(())
}

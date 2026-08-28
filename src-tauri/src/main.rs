#![cfg_attr(
    all(windows, not(debug_assertions), feature = "gui"),
    windows_subsystem = "windows"
)]

use anyhow::{Context, Result};
#[cfg(target_os = "macos")]
use mcp_vault::crypto::MasterKey;
#[cfg(feature = "gui")]
use mcp_vault::run_gui;
use mcp_vault::{
    backup, browser::BrowserBridge, mcp, model::SettingsPatch, storage::app_data_dir, vault::Vault,
};
use std::env;
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    if let Err(error) = dispatch().await {
        eprintln!("KRU: {error:#}");
        std::process::exit(1);
    }
}

async fn dispatch() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.first().is_some_and(|arg| arg == "gui") {
        #[cfg(feature = "gui")]
        {
            run_gui()?;
            return Ok(());
        }
        #[cfg(not(feature = "gui"))]
        anyhow::bail!("这是 KRU 无头版本；请使用 mcp stdio、config、browser 或 backup 子命令");
    }

    #[cfg(target_os = "macos")]
    if matches!(args.as_slice(), [command, action] if command == "key" && action == "migrate") {
        let data_dir = app_data_dir()?;
        if MasterKey::migrate_legacy_macos_key(&data_dir)? {
            Vault::open(data_dir)?;
            println!("旧钥匙串主密钥已迁移；KRU 后续启动不会再请求钥匙串权限");
        } else {
            println!("应用私有主密钥文件已存在，无需迁移");
        }
        return Ok(());
    }

    let vault = Vault::open(app_data_dir()?)?;
    match args.as_slice() {
        [command, transport] if command == "mcp" && transport == "stdio" => {
            mcp::serve_stdio(vault).await
        }
        [command, format] if command == "config" => {
            println!("{}", mcp::render_config(format)?);
            Ok(())
        }
        [command, action] if command == "browser" && action == "status" => {
            print_browser_status(&vault)
        }
        [command, action] if command == "browser" && action == "enable" => {
            set_browser_enabled(&vault, true, None)
        }
        [command, action, port] if command == "browser" && action == "enable" => {
            set_browser_enabled(&vault, true, Some(parse_port(port)?))
        }
        [command, action] if command == "browser" && action == "disable" => {
            set_browser_enabled(&vault, false, None)
        }
        [command, action] if command == "browser" && action == "pair" => {
            pair_browser(&vault, None).await
        }
        [command, action, port] if command == "browser" && action == "pair" => {
            pair_browser(&vault, Some(parse_port(port)?)).await
        }
        [command, action] if command == "browser" && action == "reset" => {
            reset_browser(&vault).await
        }
        [command, action, file] if command == "backup" && action == "export" => {
            backup::export_to_file(&vault, file)?;
            println!("备份已写入 {file}");
            Ok(())
        }
        [command, action, file] if command == "backup" && action == "import" => {
            let summary = backup::import_from_file(&vault, file)?;
            println!(
                "已导入：新增 {}，合并重复 {}",
                summary.added, summary.merged
            );
            Ok(())
        }
        _ => anyhow::bail!(
            "用法：kru [gui] | mcp stdio | config <stdio-json|stdio-toml> | browser <status|enable [port]|disable|pair [port]|reset> | backup <export|import> <file> | key migrate (macOS)"
        ),
    }
}

fn parse_port(value: &str) -> Result<u16> {
    let port = value.parse::<u16>().context("浏览器桥接端口无效")?;
    if port == 0 {
        anyhow::bail!("浏览器桥接端口必须在 1 到 65535 之间");
    }
    Ok(port)
}

fn set_browser_enabled(vault: &Vault, enabled: bool, port: Option<u16>) -> Result<()> {
    vault.update_settings_patch(SettingsPatch {
        browser_enabled: Some(enabled),
        browser_port: port,
        ..SettingsPatch::default()
    })?;
    print_browser_status(vault)
}

fn print_browser_status(vault: &Vault) -> Result<()> {
    let settings = vault.settings()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "enabled": settings.browser_enabled,
            "paired": settings.browser_paired,
            "port": settings.browser_port,
            "endpoint": format!("ws://127.0.0.1:{}/extension", settings.browser_port),
        }))?
    );
    Ok(())
}

async fn pair_browser(vault: &Vault, port: Option<u16>) -> Result<()> {
    let settings = vault.update_settings_patch(SettingsPatch {
        browser_enabled: Some(true),
        browser_port: port,
        ..SettingsPatch::default()
    })?;

    let bridge = BrowserBridge::new(vault.clone());
    bridge.sync().await;
    bridge.start_quick_pairing().await?;
    eprintln!(
        "已开启 120 秒自动配对窗口；请加载或唤醒 KRU Chromium 扩展（端口 {}）…",
        settings.browser_port
    );
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(120) {
        if vault.settings()?.browser_paired {
            bridge.stop().await;
            println!("浏览器扩展配对成功");
            return Ok(());
        }
        sleep(Duration::from_millis(250)).await;
    }
    bridge.stop().await;
    anyhow::bail!("浏览器扩展配对超时；请确认扩展端口与 KRU 一致后重试")
}

async fn reset_browser(vault: &Vault) -> Result<()> {
    let bridge = BrowserBridge::new(vault.clone());
    bridge.reset_pairing().await?;
    bridge.stop().await;
    print_browser_status(vault)
}

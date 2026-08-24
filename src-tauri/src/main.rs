#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::{Context, Result};
#[cfg(feature = "gui")]
use mcp_vault::run_gui;
use mcp_vault::{backup, mcp, vault::Vault};
use std::{env, io::IsTerminal, path::PathBuf};

fn app_data_dir() -> Result<PathBuf> {
    dirs::data_dir()
        .map(|path| path.join("mcp-vault").join("v2"))
        .context("无法确定本机数据目录")
}

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
        anyhow::bail!("这是 KRU 无头版本；请使用 mcp stdio、config 或 backup 子命令");
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
        [command, action, file] if command == "backup" && action == "export" => {
            require_tty()?;
            let password = rpassword::prompt_password("备份密码：")?;
            let confirm = rpassword::prompt_password("再次输入：")?;
            if password != confirm {
                anyhow::bail!("两次输入的密码不一致");
            }
            backup::export_to_file(&vault, file, &password)?;
            println!("备份已写入 {file}");
            Ok(())
        }
        [command, action, file] if command == "backup" && action == "import" => {
            require_tty()?;
            let password = rpassword::prompt_password("备份密码：")?;
            let summary = backup::import_from_file(&vault, file, &password)?;
            println!("已导入：新增 {}，更新 {}", summary.added, summary.updated);
            Ok(())
        }
        _ => anyhow::bail!(
            "用法：kru [gui] | mcp stdio | config <stdio-json|stdio-toml> | backup <export|import> <file>"
        ),
    }
}

fn require_tty() -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        anyhow::bail!("备份密码只能从真实终端交互读取；不接受管道、参数或环境变量")
    }
    Ok(())
}

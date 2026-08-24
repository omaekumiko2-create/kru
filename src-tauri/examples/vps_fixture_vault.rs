use anyhow::{Context, Result, bail};
use mcp_vault::{
    model::{ConnectionInput, SecretBundle},
    vault::Vault,
};
use serde::Deserialize;
use std::{env, fs, path::PathBuf};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureState {
    run_id: String,
    local_ssh_port: u16,
    local_api_port: u16,
    fixture_user: String,
    fixture_password: String,
    api_token: String,
    test_home: String,
}

fn app_data_dir() -> Result<PathBuf> {
    dirs::data_dir()
        .map(|path| path.join("mcp-vault").join("v2"))
        .context("cannot determine KRU data directory")
}

fn empty_input(kind: &str, name: String) -> ConnectionInput {
    ConnectionInput {
        id: None,
        kind: kind.to_owned(),
        capabilities: match kind {
            "ssh" => vec!["fill".to_owned(), "ssh".to_owned()],
            "api" => vec!["fill".to_owned(), "http".to_owned()],
            _ => vec!["fill".to_owned()],
        },
        modules: Vec::new(),
        name,
        enabled: true,
        description: "Disposable remote integration fixture".to_owned(),
        host: String::new(),
        port: 22,
        username: String::new(),
        auth_type: String::new(),
        ssh_auth_type: String::new(),
        http_auth_type: String::new(),
        private_key_import_path: String::new(),
        host_fingerprint: String::new(),
        security_mode: String::new(),
        allowed_commands: Vec::new(),
        base_url: String::new(),
        auth_header: String::new(),
        auth_location: String::new(),
        auth_prefix: String::new(),
        api_auth_headers: vec![],
        allowed_methods: Vec::new(),
        allowed_path_prefixes: Vec::new(),
        test_path: String::new(),
        cli: None,
        browser: None,
        credential: None,
        secret: None,
        remove_secret_names: Vec::new(),
        secrets: SecretBundle::default(),
    }
}

fn load_state(path: &str) -> Result<FixtureState> {
    let raw = fs::read_to_string(path).with_context(|| format!("cannot read {path}"))?;
    serde_json::from_str(raw.trim_start_matches('\u{feff}')).context("invalid fixture state")
}

fn names(state: &FixtureState) -> (String, String) {
    (
        format!("KRU VPS FIXTURE {}", state.run_id),
        format!("KRU API FIXTURE {}", state.run_id),
    )
}

fn setup(vault: &Vault, state: &FixtureState) -> Result<()> {
    let (ssh_name, api_name) = names(state);
    if vault
        .list_connections()?
        .iter()
        .any(|item| item.name == ssh_name || item.name == api_name)
    {
        bail!("fixture items already exist")
    }

    let mut ssh = empty_input("ssh", ssh_name);
    ssh.host = "127.0.0.1".to_owned();
    ssh.port = state.local_ssh_port;
    ssh.username = state.fixture_user.clone();
    ssh.auth_type = "password".to_owned();
    ssh.security_mode = "readonly".to_owned();
    ssh.secrets.password = Some(state.fixture_password.clone());
    vault.save_connection(ssh)?;

    let mut api = empty_input("api", api_name);
    api.base_url = format!("http://127.0.0.1:{}/test/", state.local_api_port);
    api.auth_type = "bearer".to_owned();
    api.allowed_methods = vec!["GET".to_owned(), "POST".to_owned()];
    api.allowed_path_prefixes = vec!["/test/".to_owned()];
    api.test_path = "health".to_owned();
    api.secrets.token = Some(state.api_token.clone());
    vault.save_connection(api)?;

    println!(
        r#"{{"ok":true,"action":"setup","runId":"{}"}}"#,
        state.run_id
    );
    Ok(())
}

fn set_mode(vault: &Vault, state: &FixtureState, mode: &str) -> Result<()> {
    if !matches!(
        mode,
        "readonly" | "diagnostic" | "restricted" | "unrestricted"
    ) {
        bail!("unsupported SSH mode")
    }
    let (ssh_name, _) = names(state);
    let public = vault
        .list_connections()?
        .into_iter()
        .find(|item| item.name == ssh_name)
        .context("fixture SSH item missing")?;
    let mut input = empty_input("ssh", public.name);
    input.id = Some(public.id);
    input.enabled = public.enabled;
    input.description = public.description;
    input.host = public.host;
    input.port = public.port;
    input.auth_type = public.auth_type;
    input.host_fingerprint = public.host_fingerprint;
    input.security_mode = mode.to_owned();
    if mode == "restricted" {
        input.allowed_commands = vec![format!("touch {}/allowed", state.test_home)];
    }
    vault.save_connection(input)?;
    println!(r#"{{"ok":true,"action":"mode","mode":"{mode}"}}"#);
    Ok(())
}

fn reset_fingerprint(vault: &Vault, state: &FixtureState) -> Result<()> {
    let (ssh_name, _) = names(state);
    let item = vault
        .list_connections()?
        .into_iter()
        .find(|item| item.name == ssh_name)
        .context("fixture SSH item missing")?;
    vault.reset_ssh_fingerprint(item.id)?;
    println!(r#"{{"ok":true,"action":"reset-fingerprint"}}"#);
    Ok(())
}

fn cleanup(vault: &Vault, state: &FixtureState) -> Result<()> {
    let (ssh_name, api_name) = names(state);
    let items = vault.list_connections()?;
    let mut removed = 0;
    for item in items {
        if item.name == ssh_name || item.name == api_name {
            vault.delete_connection(item.id)?;
            removed += 1;
        }
    }
    println!(r#"{{"ok":true,"action":"cleanup","removed":{removed}}}"#);
    Ok(())
}

fn audit(vault: &Vault, state: &FixtureState) -> Result<()> {
    let activities = vault
        .activities()?
        .into_iter()
        .filter(|activity| activity.connection_name.contains(&state.run_id))
        .collect::<Vec<_>>();
    let serialized = serde_json::to_string(&activities)?;
    for canary in [
        &state.fixture_user,
        &state.fixture_password,
        &state.api_token,
    ] {
        if serialized.contains(canary) {
            bail!("fixture canary found in activity log")
        }
    }
    let vault_bytes = fs::read(app_data_dir()?.join("vault.json"))?;
    for canary in [
        &state.fixture_user,
        &state.fixture_password,
        &state.api_token,
    ] {
        if vault_bytes
            .windows(canary.len())
            .any(|window| window == canary.as_bytes())
        {
            bail!("fixture canary found as plaintext in vault.json")
        }
    }
    let mut sources = activities
        .iter()
        .map(|activity| activity.source.clone())
        .collect::<Vec<_>>();
    sources.sort();
    sources.dedup();
    println!(
        r#"{{"ok":true,"action":"audit","activityCount":{},"sources":{}}}"#,
        activities.len(),
        serde_json::to_string(&sources)?
    );
    Ok(())
}

fn main() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let [action, state_path, rest @ ..] = args.as_slice() else {
        bail!(
            "usage: vps_fixture_vault <setup|mode|reset-fingerprint|audit|cleanup> <state.json> [mode]"
        )
    };
    let state = load_state(state_path)?;
    let vault = Vault::open(app_data_dir()?)?;
    match action.as_str() {
        "setup" if rest.is_empty() => setup(&vault, &state),
        "mode" if rest.len() == 1 => set_mode(&vault, &state, &rest[0]),
        "reset-fingerprint" if rest.is_empty() => reset_fingerprint(&vault, &state),
        "audit" if rest.is_empty() => audit(&vault, &state),
        "cleanup" if rest.is_empty() => cleanup(&vault, &state),
        _ => bail!("invalid fixture vault command"),
    }
}

use anyhow::{Context, Result, bail};
use std::{env, ffi::OsString, path::PathBuf};

pub const DATA_DIR_OVERRIDE_ENV: &str = "KRU_DATA_DIR";

pub fn app_data_dir() -> Result<PathBuf> {
    resolve_data_dir(
        env::var_os(DATA_DIR_OVERRIDE_ENV),
        dirs::data_dir().map(|path| path.join("mcp-vault").join("v2")),
    )
}

pub fn resolve_user_path(value: &str) -> Result<PathBuf> {
    let current_dir = env::current_dir().context("无法确定当前工作目录")?;
    let home_dir = dirs::home_dir();
    resolve_user_path_from(value, &current_dir, home_dir.as_deref())
}

fn resolve_user_path_from(
    value: &str,
    current_dir: &std::path::Path,
    home_dir: Option<&std::path::Path>,
) -> Result<PathBuf> {
    let value = value.trim();
    if value.is_empty() || value.contains('\0') {
        bail!("本地路径无效");
    }
    let path = if value == "~" {
        home_dir.context("无法确定用户主目录")?.to_path_buf()
    } else if let Some(relative) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    {
        home_dir.context("无法确定用户主目录")?.join(relative)
    } else {
        PathBuf::from(value)
    };
    Ok(if path.is_absolute() {
        path
    } else {
        current_dir.join(path)
    })
}

fn resolve_data_dir(
    override_path: Option<OsString>,
    default_path: Option<PathBuf>,
) -> Result<PathBuf> {
    if let Some(path) = override_path {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            bail!("{DATA_DIR_OVERRIDE_ENV} 必须是绝对路径");
        }
        return Ok(path);
    }
    default_path.context("无法确定本机数据目录")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_data_directory_must_be_absolute_and_wins_over_the_default() {
        let absolute = if cfg!(windows) {
            PathBuf::from(r"C:\kru-isolated-vault")
        } else {
            PathBuf::from("/tmp/kru-isolated-vault")
        };
        let overridden = resolve_data_dir(
            Some(absolute.clone().into_os_string()),
            Some(PathBuf::from("/default")),
        )
        .unwrap();
        assert_eq!(overridden, absolute);
        assert!(
            resolve_data_dir(
                Some(OsString::from("relative/vault")),
                Some(PathBuf::from("/default"))
            )
            .is_err()
        );
        assert_eq!(
            resolve_data_dir(None, Some(PathBuf::from("/default"))).unwrap(),
            PathBuf::from("/default")
        );
    }

    #[test]
    fn user_paths_accept_workspace_relative_and_home_relative_forms() {
        let (current, home) = if cfg!(windows) {
            (
                PathBuf::from(r"C:\workspace"),
                PathBuf::from(r"C:\Users\tester"),
            )
        } else {
            (PathBuf::from("/workspace"), PathBuf::from("/home/tester"))
        };
        assert_eq!(
            resolve_user_path_from("artifacts/output.bin", &current, Some(&home)).unwrap(),
            current.join("artifacts/output.bin")
        );
        assert_eq!(
            resolve_user_path_from("~/downloads/output.bin", &current, Some(&home)).unwrap(),
            home.join("downloads/output.bin")
        );
        assert!(resolve_user_path_from("", &current, Some(&home)).is_err());
    }
}

use anyhow::{Context, Result, bail};
use std::{env, ffi::OsString, path::PathBuf};

pub const DATA_DIR_OVERRIDE_ENV: &str = "KRU_DATA_DIR";

pub fn app_data_dir() -> Result<PathBuf> {
    resolve_data_dir(
        env::var_os(DATA_DIR_OVERRIDE_ENV),
        dirs::data_dir().map(|path| path.join("mcp-vault").join("v2")),
    )
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
}

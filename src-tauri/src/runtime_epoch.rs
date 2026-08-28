use anyhow::{Context, Result};
use atomic_write_file::AtomicWriteFile;
use fs2::FileExt;
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

const BUILD_EPOCH_FILE: &str = "mcp-build-epoch";
const EPOCH_LOCK_FILE: &str = "mcp-build-epoch.lock";

pub fn monitor_until_invalidated(data_dir: PathBuf) -> Result<()> {
    let expected = current_or_initialize(&data_dir)?;
    exit_process_when_changed(data_dir, expected)
}

pub fn invalidate(data_dir: &Path) -> Result<()> {
    with_epoch_lock(data_dir, || {
        write_epoch_unlocked(data_dir, &format!("stopped:{}", uuid::Uuid::new_v4()))
    })
}

pub fn exit_process_when_changed(data_dir: PathBuf, expected: String) -> Result<()> {
    thread::Builder::new()
        .name("kru-mcp-lifecycle".to_owned())
        .spawn(move || {
            let path = data_dir.join(BUILD_EPOCH_FILE);
            loop {
                thread::sleep(Duration::from_millis(500));
                if std::fs::read_to_string(&path)
                    .ok()
                    .is_some_and(|value| value.trim() != expected)
                {
                    std::process::exit(0);
                }
            }
        })
        .context("无法启动 KRU MCP 生命周期监控")?;
    Ok(())
}

fn current_or_initialize(data_dir: &Path) -> Result<String> {
    with_epoch_lock(data_dir, || {
        let path = data_dir.join(BUILD_EPOCH_FILE);
        if let Ok(current) = std::fs::read_to_string(&path) {
            let current = current.trim();
            if !current.is_empty() {
                return Ok(current.to_owned());
            }
        }
        let initial = format!("running:{}", uuid::Uuid::new_v4());
        write_epoch_unlocked(data_dir, &initial)?;
        Ok(initial)
    })
}

fn with_epoch_lock<T>(data_dir: &Path, action: impl FnOnce() -> Result<T>) -> Result<T> {
    std::fs::create_dir_all(data_dir).context("无法创建 KRU 数据目录")?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(data_dir.join(EPOCH_LOCK_FILE))
        .context("无法打开 KRU MCP 生命周期锁")?;
    lock.lock_exclusive().context("无法锁定 KRU MCP 生命周期")?;
    let result = action();
    let _ = FileExt::unlock(&lock);
    result
}

fn write_epoch_unlocked(data_dir: &Path, value: &str) -> Result<()> {
    let path = data_dir.join(BUILD_EPOCH_FILE);
    let mut file = AtomicWriteFile::open(&path).context("无法创建 KRU MCP 生命周期文件")?;
    file.write_all(value.as_bytes())
        .context("无法写入 KRU MCP 生命周期文件")?;
    file.commit().context("无法保存 KRU MCP 生命周期文件")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starting_another_mcp_session_keeps_existing_sessions_alive() {
        let directory = tempfile::tempdir().unwrap();
        let first = current_or_initialize(directory.path()).unwrap();
        let second = current_or_initialize(directory.path()).unwrap();
        assert_eq!(first, second);

        invalidate(directory.path()).unwrap();
        let after_explicit_stop = current_or_initialize(directory.path()).unwrap();
        assert_ne!(after_explicit_stop, first);
    }

    #[test]
    fn simultaneous_first_sessions_share_one_lifecycle() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().to_path_buf();
        let sessions = (0..8)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || current_or_initialize(&path).unwrap())
            })
            .collect::<Vec<_>>();
        let values = sessions
            .into_iter()
            .map(|session| session.join().unwrap())
            .collect::<Vec<_>>();
        assert!(values.iter().all(|value| value == &values[0]));
    }
}

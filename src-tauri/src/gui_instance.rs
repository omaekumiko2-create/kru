use anyhow::{Context, Result, bail};
use atomic_write_file::AtomicWriteFile;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

const TAKEOVER_TIMEOUT: Duration = Duration::from_secs(6);
const TAKEOVER_RETRY: Duration = Duration::from_millis(100);

#[derive(Serialize, Deserialize)]
struct InstanceDescriptor {
    port: u16,
    token: String,
}

pub struct GuiInstance {
    _lock: File,
    listener: Option<TcpListener>,
    token: String,
    descriptor_path: PathBuf,
}

impl GuiInstance {
    pub fn acquire(data_dir: &Path) -> Result<Self> {
        fs::create_dir_all(data_dir).context("无法创建 KRU 数据目录")?;
        let lock_path = data_dir.join("gui-instance.lock");
        let descriptor_path = data_dir.join("gui-instance.json");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .context("无法打开 KRU GUI 实例锁")?;
        let started = Instant::now();

        loop {
            match lock.try_lock_exclusive() {
                Ok(()) => return Self::become_primary(lock, descriptor_path),
                Err(error) if lock_is_contended(&error) => {
                    request_takeover(&descriptor_path);
                    if started.elapsed() >= TAKEOVER_TIMEOUT {
                        bail!("旧 KRU 实例未能在 6 秒内退出");
                    }
                    thread::sleep(TAKEOVER_RETRY);
                }
                Err(error) => return Err(error).context("无法锁定 KRU GUI 实例"),
            }
        }
    }

    fn become_primary(lock: File, descriptor_path: PathBuf) -> Result<Self> {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).context("无法创建 KRU GUI 接管通道")?;
        let port = listener.local_addr()?.port();
        let token = uuid::Uuid::new_v4().to_string();
        let descriptor = serde_json::to_vec(&InstanceDescriptor {
            port,
            token: token.clone(),
        })?;
        write_descriptor(&descriptor_path, &descriptor)?;
        Ok(Self {
            _lock: lock,
            listener: Some(listener),
            token,
            descriptor_path,
        })
    }

    pub fn listen_for_takeover(&mut self, exit: impl FnOnce() + Send + 'static) -> Result<()> {
        let listener = self.listener.take().context("KRU GUI 接管通道已启动")?;
        let token = self.token.clone();
        thread::Builder::new()
            .name("kru-gui-instance".to_owned())
            .spawn(move || {
                let mut exit = Some(exit);
                for incoming in listener.incoming() {
                    let Ok(mut stream) = incoming else {
                        continue;
                    };
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                    let mut message = String::new();
                    if Read::by_ref(&mut stream)
                        .take(128)
                        .read_to_string(&mut message)
                        .is_ok()
                        && message.trim() == token
                    {
                        if let Some(exit) = exit.take() {
                            exit();
                        }
                        break;
                    }
                }
            })
            .context("无法启动 KRU GUI 接管监听器")?;
        Ok(())
    }
}

impl Drop for GuiInstance {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.descriptor_path);
    }
}

fn lock_is_contended(error: &std::io::Error) -> bool {
    error.kind() == ErrorKind::WouldBlock
        || cfg!(windows) && matches!(error.raw_os_error(), Some(32) | Some(33))
}

fn request_takeover(descriptor_path: &Path) {
    let Ok(bytes) = fs::read(descriptor_path) else {
        return;
    };
    let Ok(descriptor) = serde_json::from_slice::<InstanceDescriptor>(&bytes) else {
        return;
    };
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, descriptor.port));
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(250)) else {
        return;
    };
    let _ = stream.write_all(descriptor.token.as_bytes());
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

fn write_descriptor(path: &Path, value: &[u8]) -> Result<()> {
    let mut file = AtomicWriteFile::open(path).context("无法创建 KRU GUI 实例描述文件")?;
    file.write_all(value)
        .context("无法写入 KRU GUI 实例描述文件")?;
    file.commit().context("无法保存 KRU GUI 实例描述文件")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn takeover_releases_the_old_gui_lock_for_the_new_instance() {
        let temp = tempdir().unwrap();
        let mut first = GuiInstance::acquire(temp.path()).unwrap();
        let takeover = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback = takeover.clone();
        first
            .listen_for_takeover(move || callback.store(true, std::sync::atomic::Ordering::Release))
            .unwrap();
        let releaser = thread::spawn(move || {
            while !takeover.load(std::sync::atomic::Ordering::Acquire) {
                thread::sleep(Duration::from_millis(10));
            }
            drop(first);
        });

        let second = GuiInstance::acquire(temp.path()).unwrap();
        releaser.join().unwrap();
        assert!(second.descriptor_path.is_file());
    }
}

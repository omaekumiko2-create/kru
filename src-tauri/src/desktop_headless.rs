use anyhow::{Result, bail};

pub fn fill_focused(_value: &str) -> Result<()> {
    bail!("此 KRU 无头版本不包含桌面焦点输入；请使用浏览器、托管终端、SSH 或 API")
}

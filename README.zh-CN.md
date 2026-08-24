<p align="center">
  <img src=".github/assets/kru-hero.svg" alt="KRU — Key Relay Unit" width="100%" />
</p>

<p align="center">
  <strong>一个超小型、完全免费、无需账号、跨平台的 Agent 密码输入器。</strong>
</p>

<p align="center">
  完全本地&nbsp;&nbsp;·&nbsp;&nbsp;免费开源&nbsp;&nbsp;·&nbsp;&nbsp;无需账号&nbsp;&nbsp;·&nbsp;&nbsp;Windows / macOS / Linux
</p>

<p align="center">
  <a href="../../releases/latest"><strong>下载 KRU</strong></a>
  &nbsp;&nbsp;·&nbsp;&nbsp;
  <a href="README.md">English</a>
  &nbsp;&nbsp;·&nbsp;&nbsp;
  <a href="SECURITY.md">安全说明</a>
</p>

---

## KRU 是什么

KRU 是一个为 AI Agent 输入密码及其他凭据的本地小工具。连接一次、保存需要的值，之后 Agent 就能把最后一步认证操作交给 KRU，而不必取得隐藏的明文。

KRU 没有账号、订阅或云端密码库。它完全免费且开源，支持 Windows、macOS 和 Linux，所有密码库数据都在本地加密保存。

<table>
  <tr>
    <td width="33%"><strong>01 / 保存</strong><br><br>凭据加密保存在本机，不需要 KRU 账号或云端密码库。</td>
    <td width="33%"><strong>02 / 转交</strong><br><br>Agent 看到可用字段名和动作，但看不到默认隐藏的值。</td>
    <td width="33%"><strong>03 / 执行</strong><br><br>KRU 在本地完成填写、SSH 认证或 API 认证。</td>
  </tr>
</table>

<p align="center">
  <img src=".github/assets/kru-flow.svg" alt="Agent 将最后一步认证操作交给 KRU" width="100%" />
</p>

## 三步开始使用

1. **下载并打开 KRU**
   选择对应平台的便携包，无需注册账号。

2. **连接 Agent**
   打开 **设置 → Agent 接入**，注册已支持的客户端。

3. **保存项目并新建会话**
   只添加需要的模块，然后新建一个已经接入 KRU 的 Agent 会话。

KRU 注册的是本地 `stdio` MCP。Agent 需要时才启动，不会对外暴露远程 MCP 地址。

## 一个保险库，多种最后一步操作

| 动作 | Agent 决定 | KRU 在本地完成 |
| --- | --- | --- |
| **填写** | 字段、时机和已聚焦目标 | 把选定值输入浏览器、桌面控件或托管终端 |
| **SSH** | 任务和命令 | 使用已保存密码或私钥认证，并执行已保存的命令策略 |
| **HTTP** | 方法、路径、查询和正文 | 注入已保存 API 凭据并发送受约束的请求 |
| **终端** | 程序流程和输入时机 | 托管交互式程序，写入秘密但不把秘密返回给 Agent |

项目由独立模块组合而成，不再被固定为“登录 / SSH / API”类型。同一项目的模块组合满足条件时，可以同时开放多种动作。

## 明文是否可见，由你决定

每个模块都有独立的 Agent 明文开关：

- **关闭** — 秘密模块的默认状态。Agent 可以命令 KRU 使用该值，但不会收到明文。
- **打开** — 只有用户明确打开后，KRU 才会把该模块值返回给 Agent。
- **TOTP** — KRU 只生成当前六位验证码，永久种子不会返回。

可选的 **审核模式** 会在每次使用秘密前暂停，等待一次本地批准。审核请求只显示调用方、项目、动作和目标，不显示凭据。

## 为本地使用而设计

<table>
  <tr>
    <td width="33%"><strong>加密保险库</strong><br><br>字段使用 XChaCha20-Poly1305 加密，机器主密钥留在本机。</td>
    <td width="33%"><strong>便携备份</strong><br><br>导出加密的 <code>.mvault</code> 包，在其他设备上导入使用。</td>
    <td width="33%"><strong>本地记录</strong><br><br>记录哪个客户端请求了什么动作，但不记录秘密值。</td>
  </tr>
</table>

### 浏览器填写

可靠的无人值守浏览器填写使用随包提供的 Chromium 扩展。KRU 只把一个选定字段写入当前聚焦控件；不分析页面、不替 Agent 选择字段、不点击提交，也不导出 Cookie。Chrome、Edge 和 Brave 首次使用时需要手动加载一次扩展。

### 本地 PIN

六位 PIN 用于锁定 GUI 中的明文查看和本地审核。它是用户查看锁，不是保险库加密密钥。当前版本不提供 PIN 找回或重置流程。

## 下载

所有发布版本均为免安装便携包。

| 目标平台 | 格式 | 说明 |
| --- | --- | --- |
| Windows x64 | `.zip` | GUI、托盘、桌面输入、浏览器扩展 |
| macOS arm64 | `.zip` | 原生 `.app`；桌面输入需要辅助功能权限 |
| Linux x64 | `.tar.gz` | AppImage GUI；桌面输入支持 X11 |
| Linux x64 无头版 | `.tar.gz` | 无 WebView 依赖；保留 MCP、SSH、HTTP、终端、备份与浏览器桥接 |

<p align="center">
  <a href="../../releases/latest"><strong>打开最新发布版本 →</strong></a>
</p>

## MCP 接口

KRU 刻意保持很小的工具面：

```text
vault_items_list
secret_fill
ssh_execute
api_request
terminal_open · terminal_input · terminal_read · terminal_close
```

KRU 不提供不受限制的 `get_secret`。`vault_items_list` 只返回项目 ID、模块元数据、非秘密目标信息和自动推导的动作。只有用户明确打开 Agent 明文开关的模块才会包含值。

手动配置 `stdio`：

```json
{
  "mcpServers": {
    "kru": {
      "command": "C:\\absolute\\path\\to\\kru.exe",
      "args": ["mcp", "stdio"]
    }
  }
}
```

也可以让 KRU 输出对应配置：

```text
kru config stdio-json
kru config stdio-toml
```

## 安全边界

KRU 的目标是避免正常流程中的秘密进入 MCP 参数、返回值、应用日志和 LLM API 流量。执行动作时，KRU 进程和最终目标仍会短暂接触明文。

KRU 不抵抗恶意 Agent、已被攻陷的系统、浏览器调试器或本机同用户进程；也无法判断 Agent 是否聚焦了正确输入框、选择了可信目标。将 KRU 用于敏感基础设施前，请阅读完整的[安全策略与威胁边界](SECURITY.md)。

## 从源码构建

需要 Rust 1.88+、Node.js 22+ 以及 [Tauri 2 平台依赖](https://v2.tauri.app/start/prerequisites/)。

```bash
npm install
npm run check
npm test
npm run build
npm run portable
```

其他平台发布命令：

```bash
npm run release:mac
npm run release:linux
npm run release:headless
```

## 许可证

[MIT](LICENSE) — 可以使用、检查和改进它。

<p align="center">
  <img src=".github/assets/kru-hero.svg" alt="KRU — Key Relay Unit" width="100%" />
</p>

<p align="center">
  <strong>一个本地 MCP 凭据中继工具：不中断 Agent 工作流，也不必让 Agent 接触隐藏的明文。</strong>
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

## 你可以这样用

连接 KRU 后，像平常一样描述任务即可。写出唯一的 KRU 项目名可以获得最准确的匹配；不知道项目名时，也可以直接让 Agent 在需要认证时检查 KRU。

| 目的 | 可以直接这样说 |
| --- | --- |
| **服务器任务** | `使用 KRU MCP 中的「生产服务器」部署当前版本，并验证服务状态。` |
| **认证 API** | `使用 KRU MCP 中的「域名服务」，列出当前账号下的域名。` |
| **网页登录** | `打开管理后台；需要凭据时，使用 KRU MCP 中的「管理账号」。` |
| **自动查找** | `继续完成任务；如果中途需要认证，先检查 KRU。` |

引号中的文字就是保存在 KRU 内的项目名。省略名称时，Agent 可以先读取 KRU 项目列表并选择匹配项。

## KRU 是什么

KRU 是一个用于保存和使用凭据的小型本地 MCP 工具。Agent 负责完整任务流程，KRU 只在需要凭据的最后一步于本地完成填写、SSH 认证或发送已认证的 API 请求，因此工作流无需中断，默认隐藏的明文也不会返回给 Agent。

KRU 不再把项目固定分成“登录 / SSH / API”类型。账号、密码、API 凭据、私钥、私钥口令、TOTP、主机、端口、URL 和自定义字段都是独立模块，可以自由组合在同一项目中；KRU 根据模块组合自动推导可用动作。

KRU 没有账号、订阅、云端密码库或远程 MCP 服务。它免费开源，支持 Windows、macOS 和 Linux，保险库数据始终在当前设备本地加密保存。本地 `stdio` MCP 只在 Agent 调用时启动。

<table>
  <tr>
    <td width="33%"><strong>01 / 保存</strong><br><br>只添加项目真正需要的模块，所有凭据在本机加密。</td>
    <td width="33%"><strong>02 / 发现</strong><br><br>Agent 看到项目名、字段名、非秘密目标和可用动作。</td>
    <td width="33%"><strong>03 / 使用</strong><br><br>KRU 在本地执行凭据操作，不返回默认隐藏的明文。</td>
  </tr>
</table>

<p align="center">
  <img src=".github/assets/kru-flow.svg" alt="Agent 将凭据步骤交给 KRU" width="100%" />
</p>

## 三步开始使用

1. **下载并打开 KRU**
   选择对应平台的便携包，无需注册账号。

2. **连接 Agent**
   打开 **设置 → Agent 接入**，连接检测到的客户端，然后新建一个 Agent 会话。

3. **保存一个项目**
   设置不可重复的项目名称，只添加真正需要的模块；既可以选择预设，也可以从空白开始组合。

KRU 注册的是本地 `stdio` MCP。Agent 调用时才会启动对应 MCP 进程。

## 一个项目，多种动作

| 动作 | 自动开放条件 | KRU 在本地完成 |
| --- | --- | --- |
| **填写** | 项目包含任意凭据模块 | 把选定值写入已聚焦的浏览器、桌面控件或托管终端 |
| **SSH** | 主机 + 端口 + 账号 + 密码/私钥 | 在本地认证，并执行 Agent 为当前任务提交的命令 |
| **HTTP** | 项目包含 API 凭据 | 注入认证信息并发送受约束的请求 |
| **终端** | Agent 打开 KRU 托管终端 | 写入选定秘密，但不把秘密返回给 Agent |

同一项目可以开放多个动作。KRU 没有观察、诊断、受限或执行模式：项目开放 `ssh_execute` 后，Agent 直接提交任务真正需要的命令。

## 每个模块独立控制明文

- **隐藏** — 凭据模块的默认状态。KRU 可以使用该值，但 MCP 返回中不会包含它。
- **可见** — 只有用户明确打开开关后，该值才允许返回给 Agent。
- **TOTP** — KRU 只生成当前六位验证码，永久种子不会返回。

编辑器中的查看与复制按钮供本机用户使用。可选的六位 PIN 只锁定 GUI 中的明文查看；它不代替保险库加密，也不会关闭 MCP 动作。

## 为本地使用而设计

<table>
  <tr>
    <td width="33%"><strong>加密保险库</strong><br><br>字段使用 XChaCha20-Poly1305 加密，机器主密钥留在本机。</td>
    <td width="33%"><strong>便携备份</strong><br><br>导出加密的 <code>.mvault</code> 包，在其他设备上导入使用。</td>
    <td width="33%"><strong>本地记录</strong><br><br>记录哪个客户端请求了什么动作，但不记录秘密值。</td>
  </tr>
</table>

## 浏览器、SSH 与 API

### 浏览器填写

可靠的无人值守浏览器填写使用随包提供的 Chromium 扩展。KRU 只把一个选定字段写入当前聚焦控件；不分析页面、不选择字段、不点击提交，也不导出 Cookie。Chrome、Edge 和 Brave 首次使用时需要手动加载一次扩展。

### SSH

KRU 支持密码与私钥认证。首次连接会记录服务器指纹；服务器身份变化后必须由用户明确重置。认证明文不会返回给 Agent。

### HTTP API

KRU 会识别常见 API 服务，无法识别时使用 Bearer Token。保存服务 URL 后，请求会被限制在同一 Origin；没有保存 URL 时，Agent 必须提供绝对 HTTPS URL，HTTP 只允许本机回环地址。

## 本地程序设置

设置页包含：

- 创建桌面快捷方式（受支持的平台）与开机自启动；
- 关闭到托盘或真正退出；
- 可选六位本地 PIN；
- Agent 接入、扫描与修复；
- Browser Bridge 配对；
- 加密备份导入、导出与打开本地数据目录。

替换或升级可执行文件不会删除保险库。KRU 会继续读取当前系统用户的数据目录：

| 平台 | 保险库位置 |
| --- | --- |
| Windows | `%APPDATA%\mcp-vault\v2` |
| macOS | `~/Library/Application Support/mcp-vault/v2` |
| Linux | `${XDG_DATA_HOME:-~/.local/share}/mcp-vault/v2` |

导出的 `.mvault` 包经过加密并可跨设备导入，但为了免密码导入，包内同时携带自动解锁材料。请像保护原始凭据一样保护备份文件。

## 下载

| 目标平台 | 格式 | 说明 |
| --- | --- | --- |
| Windows x64 | `.zip` | 便携 GUI、托盘、桌面输入与浏览器扩展 |
| macOS arm64 | `.zip` | 原生 `.app`；桌面输入需要辅助功能权限 |
| Linux x64 GUI | `.tar.gz` | AppImage GUI；桌面输入支持 X11 |
| Linux x64 无头版 | `.tar.gz` | 无 WebView 依赖；保留 MCP、SSH、HTTP、终端、备份与浏览器桥接 |

<p align="center">
  <a href="../../releases/latest"><strong>打开最新发布版本 →</strong></a>
</p>

<details>
  <summary>观看简短产品演示</summary>
  <p><a href="https://www.youtube.com/watch?v=GKQLEgAdbTU">在 YouTube 观看 KRU 演示 →</a></p>
</details>

## MCP 接口

```text
vault_items_list
secret_fill
ssh_execute
api_request
terminal_open · terminal_input · terminal_read · terminal_close
```

KRU 不提供不受限制的 `get_secret`。`vault_items_list` 只返回项目与模块元数据、非秘密目标信息和自动推导的动作。只有用户明确打开 Agent 可见开关的凭据值才会出现在返回中。

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

KRU 的目标是避免默认隐藏的值进入正常 MCP 参数、返回值、操作记录、应用日志或 LLM API 流量。执行动作时，KRU 进程和最终目标仍会短暂接触明文。

KRU 不是沙箱，也不抵抗恶意 Agent、已被攻陷的系统或浏览器，以及本机同用户进程；它也无法判断 Agent 是否聚焦了正确输入框或选择了可信目标。将 KRU 用于敏感基础设施前，请阅读完整的[安全策略与威胁边界](SECURITY.md)。

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
